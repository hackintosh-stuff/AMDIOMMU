#!/bin/sh
# build-lucy.sh — builds RTL812xLucy from source without Xcode.app (Command Line Tools only).
#
# Usage: sh tools/build/lucy.sh [source-dir]
# A relative source dir is resolved against the project root; explicit absolute
# paths keep working; when omitted the directory is selected automatically.
# Output: build-lucy/RTL812xLucy.kext
#
# Why not xcodebuild:
#   This machine only has Command Line Tools installed and /usr/bin/xcodebuild is
#   a stub; any -project invocation fails with "requires Xcode". A kext build
#   itself only needs clang + SDK headers + libkmod, all of which CLT provides.
#
# Why use the repo's bundled MacKernelSDK headers instead of the system SDK headers:
#   The driver depends on IONetworkingFamily's polled-mode SPI, which Apple has
#   removed from the public SDK; the repo restores it with the KernelSPI/ overlay
#   headers. MacKernelSDK provides the matching set of kernel headers; mixing in
#   system headers easily causes version mismatches.

set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
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
[ "$#" -le 1 ] || { echo "usage: sh tools/build/lucy.sh [--r59|--r64] [source-dir]"; exit 2; }
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

echo "== environment =="
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

# ---- source file list ----
# Both .cpp and .c must be included: the driver directory holds three C files
#   rtl812x_eeprom.c / rtl812x_firmware.c / rtl812x_phy.c
# which provide rtl8125_eeprom_type(), rtl8125_set_eeprom_sel_low() and similar
# functions called from RTL812xLucyHardware.cpp. Compiling only .cpp leaves
# undefined symbols; the link still succeeds (-kext allows undefined symbols),
# but **resolution fails at load time**.
# The xcodeproj collects these through PBXFileSystemSynchronized, so there is no
# explicit list to copy.
SOURCES=""
for f in "$DRV"/*.cpp "$DRV"/*.c; do
    [ -f "$f" ] || continue
    SOURCES="$SOURCES $f"
done
echo "== sources =="
for f in $SOURCES; do echo "  $(basename "$f")"; done

# ---- compile ----
# Key defines:
#   KERNEL / KERNEL_PRIVATE / DRIVER_PRIVATE  kernel-space build with private APIs enabled
#   __APPLE_KEXT__                            selects the kext branch (not dext)
#
# The repo's own RTL8125LucyPrefix.pch must be pulled in with -include (the
# xcodeproj's GCC_PREFIX_HEADER points at it). It is not merely a convenience:
# it does three critical things:
#   1. includes all base types and networking/IOKit headers (UInt32, mbuf_t, etc. come from here);
#   2. defines __PRIVATE_SPI__, enabling IONetworkingFamily's polled-mode SPI;
#   3. **defines USE_NEW_TX_DESC** — RTL8127 requires 32-byte tx descriptors
#      (r8127 unconditionally sets 0xEB58 BIT_0). If it is missing, RtlTxDesc is
#      16 bytes short, the descriptor ring layout no longer matches the hardware,
#      and RX/TX breaks outright.
# It also defines ENABLE_TX_NO_CLOSE.
#
# DEBUG is deliberately **not** defined on the command line:
#   it would enable a lot of IOLog, slowing boot and flooding msgbuf. With DEBUG
#   left undefined in the pch, logging stays silent.
# Do not override USE_NEW_TX_DESC either — the pch is authoritative.
# Compiler options mirror the xcodeproj Release configuration:
#   GCC_OPTIMIZATION_LEVEL = 0    → -O0 (the author deliberately does not optimize, to avoid amplifying kernel-space UB)
#   GCC_STRICT_ALIASING            → YES by default, i.e. -fno-strict-aliasing is not added
#   DEAD_CODE_STRIPPING = YES      → strip unused code after linking
#   Stack protector: enabled by default in Xcode, so -fstack-protector is kept here
# The import differences versus the prebuilt binary (___stack_chk_*, ___memcpy_chk, etc.) mostly come from these options.
echo "== compile =="
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

# Options for the C files: same architecture/defines/include paths, minus the
# C++-only switches. Note that the prefix header is still -included — these .c
# files depend on types from linux/linux.h.
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
            # C files go through clang (C front end) without the C++-only switches
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

# ---- kmod_info and the C++ entry point ----
# xcodebuild runs CreateKModInfo.perl to generate kmod_info; since we bypass
# Xcode we must supply it ourselves, otherwise the binary has no _kmod_info and
# kextload rejects it outright.
echo "== kmod_info =="
xcrun clang++ $CFLAGS "-DLUCY_KMOD_VERSION=\"$LUCY_VERSION\"" -c tools/build/lucy-kmod-info.cpp -o "$W/lucy-kmod-info.o"
OBJS="$OBJS $W/lucy-kmod-info.o"

# ---- link ----
echo "== link =="
# Link order matters (see MacKernelSDK/Library/kmod/README):
#   *.o libkmodc++.a kmod_info.o libkmod.a
# libkmodc++ provides _start (C++ runtime initialization) and .constructors_used;
# libkmod provides the C-side fallback symbols.
# Note: libkmodc++.a exists only under universal/; x86_64/ does not have it.
# shellcheck disable=SC2086
xcrun ld -kext -arch x86_64 \
    $OBJS \
    "$SDK/Library/universal/libkmodc++.a" \
    "$SDK/Library/x86_64/libkmod.a" \
    -o "$BIN"

# ---- structural checks ----
echo "== structural checks =="
nm "$BIN" | grep -q ' _kmod_info$' || { echo "missing _kmod_info"; exit 1; }
nm "$BIN" | grep -q ' __start$'    || { echo "missing __start";    exit 1; }
nm "$BIN" | grep -q ' __stop$'     || { echo "missing __stop";     exit 1; }
FT=$(otool -h "$BIN" | awk 'NR>1{print $5}' | tail -1)
[ "$FT" = "11" ] || { echo "filetype is $FT, expected 11 (MH_KEXT_BUNDLE)"; exit 1; }
echo "filetype=$FT OK"

# ---- undefined symbol check (critical) ----
# A -kext link allows undefined symbols (the kernel resolves them at load time),
# so a missing source file does not fail at the link stage. This must be checked
# separately: apart from the _RESERVED* and base C library symbols the kernel
# always provides, none of our own symbols may be left dangling.
echo "== undefined symbol check =="
UNDEF=$(nm -u "$BIN" | awk '{print $NF}' | grep -v '^_' || true)
# Find undefined symbols that look like they belong to this driver (rtl8125_* / rtl812x_* / RTL8125*)
MISSING=$(nm -u "$BIN" | awk '{print $NF}' | grep -Ei '^_(rtl812[0-9x]*_|RTL8125)' || true)
if [ -n "$MISSING" ]; then
    echo "FAIL: driver-internal symbols are undefined (a source file was probably left out):"
    echo "$MISSING" | sed 's/^/  /'
    exit 1
fi
echo "all driver-internal symbols defined OK"
echo "total undefined symbols (including kernel RESERVED): $(nm -u "$BIN" | wc -l | tr -d ' ')"

# ---- Info.plist: use the one bundled with the repo (holds IOPCIPrimaryMatch and Driver Parameters) ----
echo "== Info.plist =="
# The xcodeproj generates the plist with GENERATE_INFOPLIST_FILE=YES; there is
# no ready-made file in the source tree. Taking the plist structure from a
# published binary of the same version as a template is **unnecessary**: we
# generate an equivalent minimal plist directly.
# Round46: the actual keys in the pinned RTL812xLucy.hpp are the lowercase
# enableTSO4/enableTSO6. getParams() reads them before attachInterface(), and
# getFeatures() advertises capabilities based on them.
# Enable IPv4 and IPv6 TSO on the ordinary per-device IOMapper path.
# Once the dictionary is present, the default µsPollTime2G changes from the
# original 160000ns to 120000ns, so 160µs is written as well to keep the
# original value; the remaining defaults (ASPM/10G/5G) match the no-dictionary
# case.
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

# ---- signing ----
echo "== signing (ad-hoc) =="
codesign --force --sign - --timestamp=none "$KEXT"
codesign --verify --strict "$KEXT" && echo "codesign OK"

printf '%s\n' "$KEXT" > "$ROOT/latest-lucy-build.txt"
echo
echo "BUILD OK: $KEXT"
