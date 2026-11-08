#!/bin/sh
# build-hook.sh - Build AMDMapperHook.kext (a Lilu plugin) with only the
# Command Line Tools. No Xcode.app, no sudo.
#
# Usage (run on macOS, from anywhere):
#   sh tools/build/build-hook.sh [hook-source-dir] [lilu-source-root] [MacKernelSDK-root]
#
# Defaults: hook source is <repo>/hook/AMDMapperHook, Lilu source is
# $LILU_SRC or ~/lilu-src, MacKernelSDK is $MACKERNELSDK or one of the usual
# locations. Output is <repo>/build-hook/AMDMapperHook.kext; set
# HOOK_BUILD_DIR to put it elsewhere. Build only: nothing is deployed and
# no kernel collection or ESP is touched.
#
# The plugin is two translation units: its own source plus Lilu's shared
# Lilu/Library/plugin_start.cpp, which supplies the kext entry points, the
# requestAccess()/shouldLoad() handshake and (unless LILU_CUSTOM_IOKIT_INIT is
# set) the IOService class. This plugin sets LILU_CUSTOM_IOKIT_INIT because it
# needs an instance to publish its state properties on.
set -eu

[ "$(uname -s)" = "Darwin" ] || { echo "This script can only run on macOS" >&2; exit 1; }

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
SRC=${1:-$ROOT/hook/AMDMapperHook}
LILU=${2:-${LILU_SRC:-$HOME/lilu-src}}
NAME=AMDMapperHook
MODULE_NAME=org.maz1.AMDMapperHook
MODULE_VERSION=1.0.0

SRC=$(CDPATH= cd -- "$SRC" && pwd)
LILU=$(CDPATH= cd -- "$LILU" && pwd)

[ -f "$SRC/$NAME.cpp" ] || { echo "Missing $SRC/$NAME.cpp" >&2; exit 1; }
[ -f "$SRC/Info.plist" ] || { echo "Missing $SRC/Info.plist" >&2; exit 1; }
[ -f "$LILU/Lilu/Library/plugin_start.cpp" ] || { echo "Missing Lilu plugin_start.cpp under $LILU" >&2; exit 1; }
[ -f "$LILU/Lilu/Headers/kern_api.hpp" ] || { echo "Missing Lilu headers under $LILU" >&2; exit 1; }

SDK=${3:-${MACKERNELSDK:-}}
if [ -z "$SDK" ]; then
    for cand in "$HOME/lucy-new/MacKernelSDK" "$HOME/MacKernelSDK" "$LILU/MacKernelSDK"; do
        if [ -d "$cand/Headers" ]; then SDK=$cand; break; fi
    done
fi
[ -n "$SDK" ] || { echo "MacKernelSDK not found; pass it as the third argument or set MACKERNELSDK" >&2; exit 1; }
SDK=$(CDPATH= cd -- "$SDK" && pwd)
[ -f "$SDK/Library/universal/libkmodc++.a" ] || { echo "Missing libkmodc++.a in $SDK" >&2; exit 1; }
[ -f "$SDK/Library/x86_64/libkmod.a" ] || { echo "Missing library in $SDK" >&2; exit 1; }

echo "== Environment =="
echo "repo     : $ROOT"
echo "source   : $SRC"
echo "lilu     : $LILU"
echo "kernelSDK: $SDK"
xcrun clang++ --version | head -1

W=${HOOK_BUILD_DIR:-$ROOT/build-hook}
KEXT="$W/$NAME.kext"
BIN="$KEXT/Contents/MacOS/$NAME"
rm -rf "$KEXT"
mkdir -p "$KEXT/Contents/MacOS" "$W/objects"

# ---- kmod_info ----
# plugin_start.cpp defines the entry point pair internally; the kmod_info that
# Xcode would generate from MODULE_NAME/MODULE_START/MODULE_STOP is written here.
KMOD="$W/kmod-info.cpp"
cat > "$KMOD" <<KMOD_EOF
#include <mach/kmod.h>
#include <libkern/OSKextLib.h>

extern "C" {
extern kern_return_t ${NAME}_kern_start(kmod_info_t *, void *);
extern kern_return_t ${NAME}_kern_stop(kmod_info_t *, void *);

KMOD_EXPLICIT_DECL($MODULE_NAME, "$MODULE_VERSION", ${NAME}_kern_start, ${NAME}_kern_stop);

__attribute__((visibility("hidden"))) kmod_start_func_t *_realmain = nullptr;
__attribute__((visibility("hidden"))) kmod_stop_func_t  *_antimain = nullptr;
__attribute__((visibility("hidden"))) int _kext_apple_cc = __APPLE_CC__;
}
KMOD_EOF

CFLAGS="-arch x86_64 -mkernel -fapple-kext -mno-red-zone -nostdinc++ -O2 \
 -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -D__APPLE_KEXT__ \
 -DPRODUCT_NAME=$NAME -DMODULE_VERSION=$MODULE_VERSION -DLILU_CUSTOM_IOKIT_INIT=1 \
 -fno-builtin -fno-common -fno-exceptions -fno-rtti \
 -fno-threadsafe-statics -fno-asynchronous-unwind-tables \
 -Wno-unused-parameter -Wno-unused-function -Wno-unknown-pragmas \
 -Wno-deprecated-declarations -Wno-sign-conversion -Wno-shadow -std=c++14"
# Lilu's headers are included as <Headers/...>, which resolves against Lilu/
INCLUDES="-I $SDK/Headers -I $LILU/Lilu"

echo "== Compilation =="
echo "  CXX $NAME.cpp"
# shellcheck disable=SC2086
xcrun clang++ $CFLAGS $INCLUDES -c "$SRC/$NAME.cpp" -o "$W/objects/$NAME.o"
echo "  CXX plugin_start.cpp (Lilu)"
# shellcheck disable=SC2086
xcrun clang++ $CFLAGS $INCLUDES -c "$LILU/Lilu/Library/plugin_start.cpp" -o "$W/objects/plugin_start.o"
echo "  CXX kmod-info.cpp"
# shellcheck disable=SC2086
xcrun clang++ $CFLAGS $INCLUDES -c "$KMOD" -o "$W/objects/kmod-info.o"

echo "== Linking =="
# -kext leaves Lilu's API undefined on purpose: it is resolved when the kernel
# loads this plugin after Lilu. That is checked explicitly below.
xcrun ld -kext -arch x86_64 "$W"/objects/*.o \
    "$SDK/Library/universal/libkmodc++.a" \
    "$SDK/Library/x86_64/libkmod.a" \
    -o "$BIN"

echo "== Bundle validation =="
nm "$BIN" > "$W/symbols.txt"
for sym in ' _kmod_info$' " _${NAME}_kern_start\$" " _${NAME}_kern_stop\$"; do
    grep -q "$sym" "$W/symbols.txt" || { echo "Missing symbol: $sym" >&2; exit 1; }
done
FT=$(otool -h "$BIN" | awk 'NR>1{print $5}' | tail -1)
[ "$FT" = "11" ] || { echo "filetype=$FT; expected 11 (MH_KEXT_BUNDLE)" >&2; exit 1; }
echo "  MH_KEXT_BUNDLE OK"

# The plugin must LINK AGAINST Lilu, not carry its own copy: a locally defined
# _lilu would mean the patcher state is not the one Lilu initialised.
nm -u "$BIN" > "$W/undefined.txt"
# `nm -u` prints bare symbol names on this toolchain (no type column), so match
# whole lines rather than a whitespace-separated field.
grep -qx '_lilu' "$W/undefined.txt" || { echo "AMDMapperHook does not reference Lilu's lilu object" >&2; exit 1; }
grep -q 'KernelPatcher' "$W/undefined.txt" || { echo "AMDMapperHook does not reference KernelPatcher" >&2; exit 1; }
if grep -qE '^[0-9a-f]+ [TDB] _lilu$' "$W/symbols.txt"; then
    echo "AMDMapperHook defines its own _lilu; it must use Lilu's" >&2
    exit 1
fi
echo "  links against Lilu: OK"

# Regression guard for a crash this plugin already had. OSDynamicCast on an
# IOPCIFamily class (IOPCIDevice, IOMapper) emits a reference to <Class>::metaClass,
# an external data symbol. In this plugin that reference was bound to an unusable
# address and the first dereference page-faulted (hookCopyMapperForDevice+0x30,
# type 14, caller AppleUSBHostController::start). metaCast(const char *) references
# no per-class data symbol, so any _metaClassE here means the old pattern is back.
if nm -u "$BIN" | grep -qE '_metaClassE$'; then
    echo "undefined <Class>::metaClass data symbol; use metaCast(const char *) instead:" >&2
    nm -u "$BIN" | grep -E '_metaClassE$' >&2
    exit 1
fi
echo "  no metaClass data references: OK"

# Same trap the probe documents: a >4 KiB stack frame makes clang emit a weak
# ____chkstk_darwin reference and kmutil then refuses the whole bundle.
if nm -u "$BIN" | grep -q 'chkstk'; then
    echo "weak ____chkstk_darwin reference: a stack frame exceeds 4 KiB" >&2
    exit 1
fi
echo "  no weak chkstk reference: OK"

cp "$SRC/Info.plist" "$KEXT/Contents/Info.plist"
plutil -lint "$KEXT/Contents/Info.plist"

echo "== Signing (ad hoc) =="
codesign --force --sign - --timestamp=none "$KEXT"
codesign --verify --strict "$KEXT"

echo
ls -la "$BIN"
nm -u "$BIN" | grep -E '_lilu$|KernelPatcher' | head -5
echo "BUILD OK: $KEXT ($MODULE_NAME $MODULE_VERSION)"
