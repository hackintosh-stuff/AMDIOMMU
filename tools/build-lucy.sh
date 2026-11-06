#!/bin/sh
# build-lucy.sh — 从源码构建 RTL812xLucy，不依赖 Xcode.app（只需 Command Line Tools）。
#
# 用法： sh tools/build-lucy.sh [source-dir]
# 相对源码目录基于项目根目录；兼容既有显式绝对路径；省略时自动选择。
# 输出： build-lucy/RTL812xLucy.kext
#
# 为什么不用 xcodebuild：
#   本机只装了 Command Line Tools，/usr/bin/xcodebuild 是个空壳，
#   任何 -project 调用都会报 "requires Xcode"。但 kext 构建本身只需要
#   clang + SDK 头 + libkmod，这些 CLT 都有。
#
# 为什么用仓库自带的 MacKernelSDK 头而不是系统 SDK 头：
#   驱动依赖 IONetworkingFamily 的 polled-mode SPI，Apple 已从公开 SDK 移除，
#   仓库用 KernelSPI/ 覆盖头补回。MacKernelSDK 提供与之匹配的整套内核头，
#   混用系统头容易版本不一致。

set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

LUCY_VERSION=1.1.239
PROBE_DEP=0.61.0
if [ "$#" -gt 0 ] && [ "$1" = "--r64" ]; then
    shift
    LUCY_VERSION=1.1.241
    PROBE_DEP=0.70.0
elif [ "$#" -gt 0 ] && [ "$1" = "--r59" ]; then
    shift
    LUCY_VERSION=1.1.240
    PROBE_DEP=0.66.0
fi
[ "$#" -le 1 ] || { echo "usage: sh tools/build-lucy.sh [--r59|--r64] [source-dir]"; exit 2; }
SRC=${1:-}
if [ -z "$SRC" ]; then
    SRC=$(ls -d RTL812xLucy-*/ 2>/dev/null | head -1)
fi
[ -n "$SRC" ] || { echo "source dir not found (RTL812xLucy-*/)"; exit 1; }
SRC=${SRC%/}
DRV="$SRC/RTL812xLucy"
SDK="$SRC/MacKernelSDK"
W="build-lucy"
[ -d "$DRV" ] || { echo "driver source dir not found: $DRV"; exit 1; }
if [ "$LUCY_VERSION" = 1.1.240 ] || [ "$LUCY_VERSION" = 1.1.241 ]; then
    grep -qx '#define kRxMemBaseShift 7' "$DRV/RTL812xLucy.hpp" ||
        { echo 'R59/R64 requires the 128-page generated Lucy header' >&2; exit 1; }
elif grep -qx '#define kRxMemBaseShift 7' "$DRV/RTL812xLucy.hpp"; then
    echo '128-page input requires --r59' >&2; exit 1
fi

echo "== 环境 =="
echo "source : $SRC"
echo "driver : $DRV"
echo "sdk    : $SDK"
xcrun clang --version | head -1

[ -d "$SDK/Headers/IOKit" ] || { echo "MacKernelSDK headers missing"; exit 1; }
[ -f "$SDK/Library/x86_64/libkmod.a" ] || { echo "libkmod.a missing"; exit 1; }
[ -d "$SRC/KernelSPI" ] || { echo "KernelSPI overlay missing"; exit 1; }

rm -rf "$W"
mkdir -p "$W"
KEXT="$W/RTL812xLucy.kext"
BIN="$KEXT/Contents/MacOS/RTL812xLucy"
mkdir -p "$KEXT/Contents/MacOS"

# ---- 源文件清单 ----
# 必须同时包含 .cpp 与 .c：驱动目录里有三个 C 文件
#   rtl812x_eeprom.c / rtl812x_firmware.c / rtl812x_phy.c
# 它们提供 rtl8125_eeprom_type()、rtl8125_set_eeprom_sel_low() 等函数，
# 被 RTL812xLucyHardware.cpp 调用。只编 .cpp 会留下未定义符号，
# 链接虽能通过（-kext 允许未定义），但**加载时会解析失败**。
# xcodeproj 靠 PBXFileSystemSynchronized 自动收集，所以没有显式清单可抄。
SOURCES=""
for f in "$DRV"/*.cpp "$DRV"/*.c; do
    [ -f "$f" ] || continue
    SOURCES="$SOURCES $f"
done
echo "== 源文件 =="
for f in $SOURCES; do echo "  $(basename "$f")"; done

# ---- 编译 ----
# 关键宏说明：
#   KERNEL / KERNEL_PRIVATE / DRIVER_PRIVATE  内核态构建，且启用私有 API
#   __APPLE_KEXT__                            走 kext 分支（非 dext）
#
# 必须用 -include 引入仓库自带的 RTL8125LucyPrefix.pch（xcodeproj 的
# GCC_PREFIX_HEADER 指向它）。它不只是"方便"——它做了三件关键的事：
#   1. include 全部基础类型与网络/IOKit 头（UInt32、mbuf_t 等都来自这里）；
#   2. 定义 __PRIVATE_SPI__，启用 IONetworkingFamily 的 polled-mode SPI；
#   3. **定义 USE_NEW_TX_DESC** —— RTL8127 必须用 32 字节 tx 描述符
#      （r8127 无条件置 0xEB58 BIT_0）。若漏掉它，RtlTxDesc 少 16 字节，
#      描述符环布局与硬件不符，收发包会直接错乱。
#   它同时定义了 ENABLE_TX_NO_CLOSE。
#
# 刻意**不**在命令行定义 DEBUG：
#   会打开大量 IOLog，拖慢启动且刷爆 msgbuf。pch 里 DEBUG 未定义即静默。
# 也不要覆盖 USE_NEW_TX_DESC —— 以 pch 为准。
# 编译选项对齐 xcodeproj 的 Release 配置：
#   GCC_OPTIMIZATION_LEVEL = 0    → -O0（作者刻意不优化，避免内核态 UB 被放大）
#   GCC_STRICT_ALIASING            → 默认 YES，即不加 -fno-strict-aliasing
#   DEAD_CODE_STRIPPING = YES      → 链接后 strip 未用代码
#   栈保护：Xcode 默认开，因此这里保留 -fstack-protector
# 与预编译二进制的导入差异（___stack_chk_*、___memcpy_chk 等）主要来自这些选项。
echo "== 编译 =="
CFLAGS="-arch x86_64 -mkernel -fapple-kext -mno-red-zone \
 -nostdinc++ -std=gnu++17 -O0 \
 -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -D__APPLE_KEXT__ \
 -fno-builtin -fno-common -fno-exceptions -fno-rtti \
 -fstack-protector -fno-threadsafe-statics \
 -Wno-unused-parameter -Wno-unused-function \
 -I $SDK/Headers \
 -I $SRC/KernelSPI \
 -I $DRV \
 -I $DRV/linux \
 -include $DRV/RTL8125LucyPrefix.pch"

# C 文件用的选项：同样的架构/宏/头路径，去掉 C++ 专属开关。
# 注意仍然 -include 前缀头——这些 .c 依赖 linux/linux.h 里的类型。
CFLAGS_C="-arch x86_64 -mkernel -fapple-kext -mno-red-zone -O0 \
 -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -D__APPLE_KEXT__ \
 -fno-builtin -fno-common -fstack-protector \
 -Wno-unused-parameter -Wno-unused-function \
 -I $SDK/Headers \
 -I $SRC/KernelSPI \
 -I $DRV \
 -I $DRV/linux \
 -include $DRV/RTL8125LucyPrefix.pch"

OBJS=""
for f in $SOURCES; do
    o="$W/$(basename "$f" | sed 's/\.[^.]*$//').o"
    echo "  CC $(basename "$f")"
    case "$f" in
        *.c)
            # C 文件用 clang（C 前端），并去掉仅 C++ 有意义的开关
            # shellcheck disable=SC2086
            xcrun clang -x c $CFLAGS_C -c "$f" -o "$o"
            ;;
        *)
            # shellcheck disable=SC2086
            xcrun clang++ $CFLAGS -c "$f" -o "$o"
            ;;
    esac
    OBJS="$OBJS $o"
done

# ---- kmod_info 与 C++ 入口 ----
# xcodebuild 会跑 CreateKModInfo.perl 自动生成 kmod_info；我们绕开 Xcode，
# 就必须自己提供，否则二进制没有 _kmod_info，kextload 会直接拒绝。
echo "== kmod_info =="
xcrun clang++ $CFLAGS "-DLUCY_KMOD_VERSION=\"$LUCY_VERSION\"" -c tools/lucy-kmod-info.cpp -o "$W/lucy-kmod-info.o"
OBJS="$OBJS $W/lucy-kmod-info.o"

# ---- 链接 ----
echo "== 链接 =="
# 链接顺序很重要（见 MacKernelSDK/Library/kmod/README）：
#   *.o libkmodc++.a kmod_info.o libkmod.a
# libkmodc++ 提供 _start（C++ 运行时初始化）与 .constructors_used；
# libkmod 提供 C 侧的兜底符号。
# 注意：libkmodc++.a 只在 universal/ 下，x86_64/ 里没有它。
# shellcheck disable=SC2086
xcrun ld -kext -arch x86_64 \
    $OBJS \
    "$SDK/Library/universal/libkmodc++.a" \
    "$SDK/Library/x86_64/libkmod.a" \
    -o "$BIN"

# ---- 结构检查 ----
echo "== 结构检查 =="
nm "$BIN" | grep -q ' _kmod_info$' || { echo "missing _kmod_info"; exit 1; }
nm "$BIN" | grep -q ' __start$'    || { echo "missing __start";    exit 1; }
nm "$BIN" | grep -q ' __stop$'     || { echo "missing __stop";     exit 1; }
FT=$(otool -h "$BIN" | awk 'NR>1{print $5}' | tail -1)
[ "$FT" = "11" ] || { echo "filetype is $FT, expected 11 (MH_KEXT_BUNDLE)"; exit 1; }
echo "filetype=$FT OK"

# ---- 未定义符号检查（关键）----
# -kext 链接允许未定义符号（它们由内核在加载时解析），所以缺源文件不会在
# 链接阶段报错。必须单独检查：除了内核必然提供的 _RESERVED* 与基础 C 库，
# 不该有我们自己的符号悬空。
echo "== 未定义符号检查 =="
UNDEF=$(nm -u "$BIN" | awk '{print $NF}' | grep -v '^_' || true)
# 找出看起来属于本驱动自己的未定义符号（rtl8125_* / rtl812x_* / RTL8125*）
MISSING=$(nm -u "$BIN" | awk '{print $NF}' | grep -Ei '^_(rtl812[0-9x]*_|RTL8125)' || true)
if [ -n "$MISSING" ]; then
    echo "FAIL: 以下驱动内部符号未定义（很可能漏编了源文件）："
    echo "$MISSING" | sed 's/^/  /'
    exit 1
fi
echo "驱动内部符号全部已定义 OK"
echo "未定义符号总数（含内核 RESERVED）：$(nm -u "$BIN" | wc -l | tr -d ' ')"

# ---- Info.plist：用仓库自带的（含 IOPCIPrimaryMatch 与 Driver Parameters）----
echo "== Info.plist =="
# xcodeproj 用 GENERATE_INFOPLIST_FILE=YES 生成 plist，源码树里没有现成文件。
# 这里从已发布的同版本二进制里取 plist 结构做模板是**不必要**的：
# 我们直接生成一个等价的最小 plist。
# Round46：pinned RTL812xLucy.hpp 的实际键是小写 enableTSO4/enableTSO6。
# getParams() 在 attachInterface() 前读取它们，getFeatures() 据此公布能力。
# 在普通 per-device IOMapper 路径上开启 IPv4 和 IPv6 TSO。
# 一旦加入字典，缺省 µsPollTime2G 会由原 160000ns 变成 120000ns，
# 因此同时写 160µs 保留原值；其余缺省值（ASPM/10G/5G）与无字典一致。
cat > "$KEXT/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleExecutable</key>
	<string>RTL812xLucy</string>
	<key>CFBundleIdentifier</key>
	<string>com.insanelymac.RTL812xLucy</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>RTL812xLucy</string>
	<key>CFBundlePackageType</key>
	<string>KEXT</string>
	<key>CFBundleShortVersionString</key>
	<string>$LUCY_VERSION</string>
	<key>CFBundleVersion</key>
	<string>$LUCY_VERSION</string>
	<key>IOKitPersonalities</key>
	<dict>
		<key>RTL8125</key>
		<dict>
			<key>CFBundleIdentifier</key>
			<string>com.insanelymac.RTL812xLucy</string>
			<key>Driver Parameters</key>
			<dict>
				<key>enableTSO4</key>
				<true/>
				<key>enableTSO6</key>
				<true/>
				<key>µsPollTime2G</key>
				<integer>160</integer>
			</dict>
			<key>IOClass</key>
			<string>RTL8125</string>
			<key>IOPCIPrimaryMatch</key>
			<string>0x812510ec 0x81251186 0x300010ec 0x812610ec 0x500010ec 0x812710ec 0x0e1010ec</string>
			<key>IOPCITunnelCompatible</key>
			<true/>
			<key>IOProbeScore</key>
			<integer>5000</integer>
			<key>IOProviderClass</key>
			<string>IOPCIDevice</string>
		</dict>
	</dict>
	<key>OSBundleLibraries</key>
	<dict>
		<key>com.apple.iokit.IONetworkingFamily</key>
		<string>1.8.0</string>
		<key>com.apple.iokit.IOPCIFamily</key>
		<string>2.6</string>
		<key>com.apple.kpi.bsd</key>
		<string>8.10.0</string>
		<key>com.apple.kpi.iokit</key>
		<string>8.10.0</string>
		<key>com.apple.kpi.libkern</key>
		<string>8.10.0</string>
		<key>com.apple.kpi.mach</key>
		<string>8.10.0</string>
		<!-- The device mapper must be resident before this driver starts: its
		     copyMapperForDevice() lookup happens once inside start(), so an
		     iommu-parent published afterwards would always be too late.
		     The requested version must sit inside the provider's compatible
		     range (OSBundleCompatibleVersion <= requested <= CFBundleVersion),
		     otherwise kmutil cannot resolve the dependency at all.
		     Select the minimum needed by this client's RX grouping and pre-open claim. -->
		<key>org.maz1.AMDMapperProbe</key>
		<string>$PROBE_DEP</string>
	</dict>
	<key>OSBundleRequired</key>
	<string>Network-Root</string>
</dict>
</plist>
PLIST
plutil -lint "$KEXT/Contents/Info.plist"

# ---- 签名 ----
echo "== 签名（ad-hoc）=="
codesign --force --sign - --timestamp=none "$KEXT"
codesign --verify --strict "$KEXT" && echo "codesign OK"

printf '%s\n' "$KEXT" > "$ROOT/latest-lucy-build.txt"
echo
echo "BUILD OK: $KEXT"
