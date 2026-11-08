#!/bin/sh
# Compile/package ONLY. Writes fresh user-owned output beneath this project.
# Does not resolve installed-KC dependencies or claim runtime ABI compatibility.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
python3 "$ROOT/tools/verify/source.py"
SDK=$(xcrun --sdk macosx --show-sdk-path)
SDK_VERSION=$(xcrun --sdk macosx --show-sdk-version)
HEADERS="$SDK/System/Library/Frameworks/Kernel.framework/Versions/A/Headers"
WORK=$(mktemp -d "$ROOT/build-work.XXXXXX")
KEXT="$WORK/AMDIdentityMapper.kext"
BIN="$KEXT/Contents/MacOS/AMDIdentityMapper"
mkdir -p "$KEXT/Contents/MacOS"
cp "$ROOT/probe/Info.plist" "$KEXT/Contents/Info.plist"
plutil -lint "$KEXT/Contents/Info.plist"
# Compile the standalone validator too; it remains UNWIRED to IOMapper methods.
for UNIT in probe/AMDIdentityMapper src/IdentityMap; do
    NAME=$(basename "$UNIT")
    xcrun clang++ -arch x86_64 -mkernel -fapple-kext -mno-red-zone \
        -isysroot "$SDK" -mmacosx-version-min="$SDK_VERSION" \
        -I "$HEADERS" -I "$ROOT/include" \
        -nostdinc++ -std=c++17 -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE \
        -fno-builtin -fno-common -fno-exceptions -fno-rtti \
        -fno-stack-protector -Wall -Wextra -Werror -O0 -g \
        -c "$ROOT/$UNIT.cpp" -o "$WORK/$NAME.o"
done
xcrun ld -kext -arch x86_64 -syslibroot "$SDK" \
    -platform_version macos "$SDK_VERSION" "$SDK_VERSION" \
    "$WORK/AMDIdentityMapper.o" "$WORK/IdentityMap.o" \
    "$SDK/usr/lib/libkmod.a" -o "$BIN"
nm "$BIN" | grep ' _kmod_info$'
nm "$BIN" | grep ' __start$'
nm "$BIN" | grep ' __stop$'
[ "$(otool -h "$BIN" | awk '/0xfeed/{print $5}')" = 11 ]
nm -u "$BIN" > "$WORK/imported-symbols.txt"
xcrun dsymutil "$BIN" -o "$WORK/AMDIdentityMapper.dSYM"
codesign --force --sign - --timestamp=none "$KEXT"
codesign --verify --strict "$KEXT"
file "$BIN"
xcrun dwarfdump --uuid "$BIN"
{
    printf 'SDK=%s\n' "$SDK"
    xcrun --sdk macosx --show-sdk-version
    xcrun clang++ --version
    uname -a
} > "$WORK/toolchain.txt"
(cd "$ROOT" && shasum -a 256 include/amd_iommu/IdentityMap.hpp \
    src/IdentityMap.cpp probe/AMDIdentityMapper.hpp probe/AMDIdentityMapper.cpp \
    probe/Info.plist tools/build/kext.sh tools/verify/source.py) \
    > "$WORK/source-manifest.sha256"
shasum -a 256 "$HEADERS/IOKit/IOMapper.h" \
    "$HEADERS/IOKit/IOMemoryDescriptor.h" "$HEADERS/IOKit/IODMACommand.h" \
    > "$WORK/header-manifest.sha256"
printf '%s\n' "$KEXT" > "$ROOT/latest-build.txt"
printf '\nBUILD_ONLY_OK=%s\nNOT_INSTALLABLE_AS_A_WORKING_MAPPER\n' "$KEXT"
