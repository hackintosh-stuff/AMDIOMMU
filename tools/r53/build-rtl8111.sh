#!/bin/sh
# Build the pinned RTL8111 adapter with the already-present Lucy SDK/KernelSPI.
# Usage: sh tools/r53/build-rtl8111.sh <rtl8111-source> <lucy-source>
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
[ "$#" -eq 2 ] || { echo "usage: sh tools/r53/build-rtl8111.sh <rtl8111-source> <lucy-source>" >&2; exit 2; }
RTL_SRC=$(CDPATH= cd -- "$1" && pwd)
LUCY_SRC=$(CDPATH= cd -- "$2" && pwd)
DRV="$RTL_SRC/RealtekRTL8111"
SDK="$LUCY_SRC/MacKernelSDK"
[ -d "$SDK/Headers/IOKit" ] || { echo "missing existing MacKernelSDK" >&2; exit 1; }
[ -d "$LUCY_SRC/KernelSPI" ] || { echo "missing existing KernelSPI overlay" >&2; exit 1; }
[ -f "$SDK/Library/x86_64/libkmod.a" ] || { echo "missing libkmod.a" >&2; exit 1; }
[ -f "$SDK/Library/universal/libkmodc++.a" ] || { echo "missing libkmodc++.a" >&2; exit 1; }
python3 tools/r53/apply-rtl8111.py "$RTL_SRC"

W="$ROOT/build-rtl8111"
rm -rf "$W"
KEXT="$W/RealtekRTL8111.kext"
BIN="$KEXT/Contents/MacOS/RealtekRTL8111"
mkdir -p "$W/objects" "$KEXT/Contents/MacOS" "$KEXT/Contents/Resources"

compile() {
    xcrun clang++ -arch x86_64 -mkernel -fapple-kext -mno-red-zone \
        -nostdinc++ -std=gnu++17 -O0 \
        -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -D__APPLE_KEXT__ \
        -fno-builtin -fno-common -fno-exceptions -fno-rtti \
        -fstack-protector -fno-threadsafe-statics \
        -Wno-unused-parameter -Wno-unused-function \
        -I "$SDK/Headers" -I "$LUCY_SRC/KernelSPI" -I "$DRV" \
        -include "$DRV/RealtekRTL8111-V2-Prefix.pch" \
        -c "$1" -o "$2"
}

# Explicit pinned compilation units; no xcodebuild, SDK download or repo copy.
for name in RealtekRTL8111 RealtekRTL8111Setup RealtekRTL8111VTD \
            RealtekRTL8111Hardware RealtekRTL8111Linux-804704 RealtekRxPool; do
    echo "CC $name.cpp"
    compile "$DRV/$name.cpp" "$W/objects/$name.o"
done
compile "$ROOT/tools/r53/rtl8111-kmod-info.cpp" "$W/objects/rtl8111-kmod-info.o"
xcrun ld -kext -arch x86_64 "$W"/objects/*.o \
    "$SDK/Library/universal/libkmodc++.a" \
    "$SDK/Library/x86_64/libkmod.a" -o "$BIN"

nm "$BIN" > "$W/symbols.txt"
grep -q ' _kmod_info$' "$W/symbols.txt"
grep -q ' __start$' "$W/symbols.txt"
grep -q ' __stop$' "$W/symbols.txt"
grep -q 'r53SnapshotAction' "$W/symbols.txt"
FT=$(otool -h "$BIN" | awk 'NR>1{print $5}' | tail -1)
[ "$FT" = "11" ] || { echo "expected MH_KEXT_BUNDLE (11), got $FT" >&2; exit 1; }
nm -u "$BIN" | c++filt > "$W/undefined.txt"
if grep -E 'rtl8168_|RTL8111::|RealtekRxPool::' "$W/undefined.txt"; then
    echo "driver-internal symbol unresolved" >&2
    exit 1
fi
cp "$DRV/Info.plist" "$KEXT/Contents/Info.plist"
cp "$DRV/gpl.txt" "$DRV/APPLE_LICENSE" "$KEXT/Contents/Resources/"
plutil -lint "$KEXT/Contents/Info.plist"
codesign --force --sign - --timestamp=none "$KEXT"
codesign --verify --strict "$KEXT"
printf '%s\n' "$KEXT" > "$ROOT/latest-rtl8111-build.txt"
echo "BUILD OK: $KEXT (RealtekRTL8111 3.0.53)"
