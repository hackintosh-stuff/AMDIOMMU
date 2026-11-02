#!/bin/sh
# build-r9-lucy.sh -- build the round-9 patched RTL812xLucy from source.
#
# WHY THIS EXISTS: the project rule is to build the driver from source, never
# to use a prebuilt binary. build-lucy.sh already does that for the pristine
# tree; this variant points at the patched tree and adds one extra check --
# that the round-9 observation-log symbols are actually present in the linked
# binary, so a build that silently dropped the patch cannot be mistaken for
# one that kept it.
set -eu

SRC=${1:-$HOME/rtl812x-src/RTL812xLucy-639144d1f284a9fee222a518691b01494f5e265d}
DRV=${2:-$HOME/r9-lucy/RTL812xLucy}
W=${3:-$HOME/r9-lucy/build}

SDK=$SRC/MacKernelSDK
# lucy-kmod-info.cpp generates _kmod_info; xcodebuild does that automatically,
# and we do not use xcodebuild. It is kept beside this script because the
# upstream tarball does not ship it.
KMOD=${KMOD:-$(dirname "$0")/lucy-kmod-info.cpp}

[ -d "$DRV" ] || { echo "driver dir not found: $DRV"; exit 1; }
[ -f "$DRV/RTL812xObsLog.hpp" ] || { echo "patch not applied: no RTL812xObsLog.hpp"; exit 1; }
[ -f "$KMOD" ] || { echo "lucy-kmod-info.cpp not found: $KMOD"; exit 1; }
[ -d "$SDK/Headers/IOKit" ] || { echo "MacKernelSDK headers missing"; exit 1; }

rm -rf "$W"
mkdir -p "$W"

COMMON="-arch x86_64 -mkernel -fapple-kext -mno-red-zone -O0 \
 -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -D__APPLE_KEXT__ \
 -fno-builtin -fno-common -fstack-protector \
 -Wno-unused-parameter -Wno-unused-function \
 -I $SDK/Headers -I $SRC/KernelSPI -I $DRV -I $DRV/linux \
 -include $DRV/RTL8125LucyPrefix.pch"

CXXFLAGS="$COMMON -nostdinc++ -std=gnu++17 -fno-exceptions -fno-rtti \
 -fno-threadsafe-statics"

OBJS=""
for f in "$DRV"/*.cpp "$DRV"/*.c; do
    [ -f "$f" ] || continue
    b=$(basename "$f")
    o="$W/${b%.*}.o"
    case "$f" in
        *.c) xcrun clang -x c $COMMON -c "$f" -o "$o" ;;
        *)   xcrun clang++ $CXXFLAGS -c "$f" -o "$o" ;;
    esac
    OBJS="$OBJS $o"
done

xcrun clang++ $CXXFLAGS -c "$KMOD" -o "$W/lucy-kmod-info.o"
OBJS="$OBJS $W/lucy-kmod-info.o"

# shellcheck disable=SC2086
xcrun ld -kext -arch x86_64 $OBJS \
    "$SDK/Library/universal/libkmodc++.a" \
    "$SDK/Library/x86_64/libkmod.a" \
    -o "$W/RTL812xLucy"

# ---- the round-9 patch must be in the linked image ----------------------
N=$(nm "$W/RTL812xLucy" | grep -c "obsWrite\|obsPublish\|obsInit\|obsFree" || true)
[ "$N" -ge 4 ] || { echo "FAIL: observation-log symbols missing (found $N)"; exit 1; }
echo "obs symbols: $N OK"

nm "$W/RTL812xLucy" | grep -i chkstk && { echo "FAIL: chkstk reference"; exit 1; }
echo "no chkstk OK"

FT=$(otool -h "$W/RTL812xLucy" | awk 'NR>1{print $5}' | tail -1)
[ "$FT" = "11" ] || { echo "FAIL: filetype $FT"; exit 1; }
echo "filetype=11 OK"

MISSING=$(nm -u "$W/RTL812xLucy" | awk '{print $NF}' | grep -Ei '^_(rtl812[0-9x]*_|RTL8125)' || true)
[ -z "$MISSING" ] || { echo "FAIL: undefined driver symbols:"; echo "$MISSING"; exit 1; }
echo "driver symbols resolved OK"

# ---- package the bundle -------------------------------------------------
# The linker emits a bare Mach-O. A kext is a BUNDLE: without Contents/Info.plist
# and Contents/MacOS/<exe>, kmutil will not accept it and codesign has nothing
# to seal.
#
# DO NOT COPY THE UPSTREAM Info.plist. The one in the source tree is an
# UNEXPANDED Xcode template: it literally contains
#     CFBundleName        = $(PRODUCT_NAME)
#     CFBundleIdentifier  = com.insanelymac.${PRODUCT_NAME:rfc1034identifier}
#     CFBundleExecutable  = $(EXECUTABLE_NAME)
# and no CFBundleVersion at all. Xcode substitutes those at build time; we do
# not use Xcode, so installing that plist produces a bundle whose identifier is
# the literal string "com.insanelymac.${PRODUCT_NAME:rfc1034identifier}".
# kmutil then cannot match it to anything and the collection is rebuilt WITHOUT
# the driver -- silently. That is exactly what happened on round 9's first
# attempt: the aux collection came back listing only the probe and the NVIDIA
# kexts, the old driver stayed loaded, and the capture had no records.
#
# So the plist is generated here with the same values round 8 used, which are
# the values the shipping binary carries.
KEXT="$W/RTL812xLucy.kext"
rm -rf "$KEXT"
mkdir -p "$KEXT/Contents/MacOS"
cp "$W/RTL812xLucy" "$KEXT/Contents/MacOS/RTL812xLucy"

cat > "$KEXT/Contents/Info.plist" <<'PLIST'
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
	<string>1.1.2</string>
	<key>CFBundleVersion</key>
	<string>1.1.200</string>
	<key>IOKitPersonalities</key>
	<dict>
		<key>RTL8125</key>
		<dict>
			<key>CFBundleIdentifier</key>
			<string>com.insanelymac.RTL812xLucy</string>
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
	</dict>
	<key>OSBundleRequired</key>
	<string>Network-Root</string>
</dict>
</plist>
PLIST
plutil -lint "$KEXT/Contents/Info.plist"
BID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' \
      "$KEXT/Contents/Info.plist")
[ "$BID" = "com.insanelymac.RTL812xLucy" ] || \
    { echo "FAIL: bundle id is '$BID' (unexpanded template?)"; exit 1; }
echo "bundle id OK: $BID"

# Sign the BINARY first, then the bundle. Signing the bundle alone fails with
# "code object is not signed at all / In subcomponent: .../Contents/MacOS/..."
# because codesign seals the bundle around an already-signed executable; it
# does not sign the executable for you when the bundle is new.
codesign --force --sign - --timestamp=none "$KEXT/Contents/MacOS/RTL812xLucy"
codesign --force --sign - --timestamp=none "$KEXT"
codesign --verify --strict "$KEXT" && echo "codesign OK"

KU=$(xcrun dwarfdump --uuid "$KEXT/Contents/MacOS/RTL812xLucy" | awk '{print $2}' | head -1)
echo "driver uuid: $KU"

echo "BUILD OK: $KEXT"
