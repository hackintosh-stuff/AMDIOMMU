#!/bin/sh
# build-m1a.sh — 在 Mac 上构建 M1-A 探针。不需要 sudo。
#
# 用法： sh build-m1a.sh
# 输出： build-m1a/AMDMapperProbe.kext（路径写入 latest-m1a-build.txt）
#
# 探针由多个源文件组成（见 kext/AMDMapperProbe*.cpp）。它们共用
# kext/AMDMapperProbeInternal.hpp 里的 static 辅助函数，所以每个文件都是
# 独立的编译单元，最后一起链接进同一个 kext。

set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

SDK=$(xcrun --sdk macosx --show-sdk-path)
SDKVER=$(xcrun --sdk macosx --show-sdk-version)
HEADERS="$SDK/System/Library/Frameworks/Kernel.framework/Versions/A/Headers"
# PROBE_DEBUG=1 selects the Debug variant: the retired M2 experiment
# subsystem (kext/*Debug.cpp) is compiled back in, restoring the historical
# amdiommu=arm/mmio/write/table/enable/cmd/pgt* modes. The default production
# build accepts only amdiommu=passive / auto-attach.
PROBE_DEBUG=${PROBE_DEBUG:-0}
if [ "$PROBE_DEBUG" = "1" ]; then
    W="$ROOT/build-m1a-debug"
    BUILD_RECORD="$ROOT/latest-m1a-debug-build.txt"
    DEBUG_DEFINE="-DAMD_MAPPER_PROBE_DEBUG=1"
else
    W="$ROOT/build-m1a"
    BUILD_RECORD="$ROOT/latest-m1a-build.txt"
    DEBUG_DEFINE=""
fi

rm -rf "$W"
mkdir -p "$W"
KEXT="$W/AMDMapperProbe.kext"
BIN="$KEXT/Contents/MacOS/AMDMapperProbe"
mkdir -p "$KEXT/Contents/MacOS"

cp kext/AMDMapperProbe-Info.plist "$KEXT/Contents/Info.plist"
plutil -lint "$KEXT/Contents/Info.plist"

# 探针的所有编译单元。新增模块必须同时出现在这里和 split-probe.py 的
# MEMBERS 表中，否则链接时会缺少符号。
SRCS="kext/AMDMapperProbe.cpp \
      kext/AMDMapperProbeNic.cpp \
      kext/AMDMapperProbeAuto.cpp \
      kext/AMDMapperProbeDiscovery.cpp \
      kext/AMDMapperProbeMapper.cpp \
      src/Ivrs.cpp \
      src/IvrsTopology.cpp"

# Debug-only translation units. AMDMapperProbeDebug.cpp provides the historic
# start/stop/iovm* implementations (mutually exclusive with the production
# versions via AMD_MAPPER_PROBE_DEBUG); the other modules implement the
# retired M2 experiment stages.
DEBUG_SRCS="kext/AMDMapperProbeDebug.cpp \
      kext/AMDMapperProbeNicDebug.cpp \
      kext/AMDMapperProbeB1B2Debug.cpp \
      kext/AMDMapperProbeMmioDebug.cpp \
      kext/AMDMapperProbeTableDebug.cpp \
      kext/AMDMapperProbeDmaDebug.cpp \
      kext/AMDMapperProbeObsDebug.cpp \
      kext/AMDMapperProbeRxSetDebug.cpp \
      kext/AMDMapperProbeTxDebug.cpp \
      kext/AMDMapperProbePgtDebug.cpp"

if [ "$PROBE_DEBUG" = "1" ]; then
    SRCS="$SRCS $DEBUG_SRCS"
fi

for f in $SRCS; do
    [ -f "$f" ] || { echo "missing source: $f"; exit 1; }
done
[ -f kext/AMDMapperProbeInternal.hpp ] || {
    echo "missing kext/AMDMapperProbeInternal.hpp"; exit 1; }

echo "== 编译（$(echo "$SRCS" | wc -w | tr -d ' ') 个编译单元）=="
# 注意：不定义 IOKIT_ENABLE_SHARED_PTR。SDK 默认未定义，此时 OSPtr<T> 就是 T*。
# 打开它会让 IOKit 直接 #error（要求额外定义 EXPERIMENTAL 宏，且声明 API 不稳定）。
CFLAGS="-arch x86_64 -mkernel -fapple-kext -mno-red-zone \
    -isysroot $SDK -mmacosx-version-min=$SDKVER \
    -I $HEADERS -I $ROOT/include -nostdinc++ -std=c++17 \
    -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE \
    -fno-builtin -fno-common -fno-exceptions -fno-rtti \
    -fno-stack-protector -Wall -Wextra -Werror -O0 -g $DEBUG_DEFINE"

OBJS=""
for f in $SRCS; do
    b=$(basename "$f" .cpp)
    o="$W/$b.o"
    echo "  cc $f"
    # shellcheck disable=SC2086
    xcrun clang++ $CFLAGS -c "$f" -o "$o"
    OBJS="$OBJS $o"
done

echo "== 链接 =="
# shellcheck disable=SC2086
xcrun ld -kext -arch x86_64 -sysroot "$SDK" \
    -platform_version macos "$SDKVER" "$SDKVER" \
    $OBJS "$SDK/usr/lib/libkmod.a" -o "$BIN" 2>/dev/null || \
xcrun ld -kext -arch x86_64 -syslibroot "$SDK" \
    -platform_version macos "$SDKVER" "$SDKVER" \
    $OBJS "$SDK/usr/lib/libkmod.a" -o "$BIN"

echo "== 结构检查 =="
nm "$BIN" | grep -q ' _kmod_info$' || { echo "missing _kmod_info"; exit 1; }
nm "$BIN" | grep -q ' __start$'    || { echo "missing __start";    exit 1; }
nm "$BIN" | grep -q ' __stop$'     || { echo "missing __stop";     exit 1; }
FT=$(otool -h "$BIN" | awk 'NR>1{print $5}' | tail -1)
[ "$FT" = "11" ] || { echo "filetype is $FT, expected 11 (MH_KEXT_BUNDLE)"; exit 1; }
echo "filetype=$FT OK"

# 拆分后的关键回归：每个模块的方法都必须真的进了二进制。少一个模块时链接
# 会因为缺符号而失败，但"多定义/被静态化"这类问题不会，所以显式点名检查。
echo "== 模块符号检查 =="
# Search by the readable name inside the mangled symbol. Each of these lives in
# a different module, so together they prove the registered translation units were
# compiled AND linked in. A missing module fails the link anyway; this catches
# the subtler case of a module whose functions were made static or dropped.
PROD_NAMES="initHardware \
    AttachAuto \
    MapMemory \
    PowerTransition \
    SuspendAuto \
    ResumeAuto"
DEBUG_NAMES="findTarget \
    runB1SelfTest \
    runM20ConfigProbe \
    runM22bTableProbe \
    observeDeviceDma \
    m2b2ReadDriverObs \
    runM22b2PageTableProbe \
    m2b2BindDriverInstance \
    m2b2WalkBusinessRanges \
    m2b2RxSetRead \
    m2b2WalkRxSet \
    m2b2PublishRxSet"
if [ "$PROBE_DEBUG" = "1" ]; then
    MODULE_NAMES="$PROD_NAMES $DEBUG_NAMES"
else
    MODULE_NAMES="$PROD_NAMES"
fi
for name in $MODULE_NAMES
do
    nm "$BIN" | grep -q "T .*org_maz1_AMDMapperProbe.*$name" || {
        echo "missing module symbol: $name"; exit 1; }
done
# Firmware discovery reuses the host parser as independent translation units.
for name in DiscoverHardware buildTopology resolveRequester; do
    nm "$BIN" | grep -q "T .*$name" || {
        echo "missing discovery/parser symbol: $name"; exit 1; }
done
echo "all module entry points present OK"

# ---- the weak-reference guard -------------------------------------------
#
# A function whose stack frame exceeds 4 KiB makes clang call
# ____chkstk_darwin, which arrives as a WEAK undefined symbol. kmutil then
# refuses the bundle outright:
#
#     Has weak references but does not test for them.
#     Test for weak references with OSKextSymbolIsResolved().
#
# The aux collection is left UNCHANGED, so the old kext loads and the only
# symptom is a capture with none of the new fields. This project has hit it
# three times now (round 6 M2B2_RAW_KEEP 8->32, round 10's ObsJoin temporaries,
# and round 11's variable-length array in m2b2WalkBusinessRanges). Checking it
# at BUILD time turns a reboot-and-wonder into an immediate, named failure --
# and the message names the likely cause instead of only the symptom.
echo "== 弱引用检查（栈帧 > 4 KiB 会触发 ____chkstk_darwin）=="
if nm -u "$BIN" | grep -q 'chkstk'; then
    echo "FAIL: the binary has a weak reference to ____chkstk_darwin."
    echo "      A function's stack frame exceeds 4 KiB. kmutil will refuse"
    echo "      this bundle with 'Has weak references but does not test for"
    echo "      them', and the aux collection will silently stay as it was."
    echo
    echo "      Usual causes: a large local array, a struct returned by value,"
    echo "      or a VARIABLE-LENGTH ARRAY -- note that indexing a static const"
    echo "      member through an OBJECT (obj.kMax) is not a constant expression"
    echo "      and makes the array a VLA. Use Class::kMax instead."
    nm -u "$BIN" | grep 'chkstk' | sed 's/^/      /'
    exit 1
fi
echo "no weak chkstk reference OK"

echo "== 签名（ad-hoc）=="
codesign --force --sign - --timestamp=none "$KEXT"
codesign --verify --strict "$KEXT" && echo "codesign OK"

echo "== 布局检查 =="
xcrun clang++ -std=c++17 -O0 -o "$W/layout-check" tools/dev/layout-check.cpp
"$W/layout-check"

echo "== 导入符号 =="
nm -u "$BIN" > "$W/imported-symbols.txt"
echo "count: $(wc -l < "$W/imported-symbols.txt" | tr -d ' ')"

printf '%s\n' "$KEXT" > "$BUILD_RECORD"
echo
echo "BUILD OK: $KEXT"
