#!/bin/sh
# deploy-m1a.sh — 部署 M1-A 探针（需 sudo，必须在 Mac 上本地执行）
#
# 用法（在 Mac 终端里，不是远程）：
#   sh deploy-m1a.sh /tmp/m1a-build/AMDMapperProbe.kext
#
# 前置：kext 已由 tools/build-m1a.sh 构建，且三项前置检查通过。
#
# 本脚本刻意做成「先检查、再备份、最后才写」的顺序，
# 任何一步失败都会在改动系统前停止。

set -eu

KEXT=${1:-/tmp/m1a-build/AMDMapperProbe.kext}
BUNDLE_ID=org.example.AMDMapperProbe
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
DEST=/Library/Extensions/AMDMapperProbe.kext
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=$HOME/m1a-backup-$STAMP

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf 'ABORT: %s\n' "$1" >&2; exit 1; }

say "0. 参数与产物检查"
[ -d "$KEXT" ] || die "kext not found: $KEXT"
[ -f "$KEXT/Contents/MacOS/AMDMapperProbe" ] || die "missing executable in kext"
codesign --verify --strict "$KEXT" || die "codesign verify failed"
plutil -lint "$KEXT/Contents/Info.plist" >/dev/null || die "Info.plist invalid"
BID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$KEXT/Contents/Info.plist")
[ "$BID" = "$BUNDLE_ID" ] || die "unexpected bundle id: $BID"
echo "bundle id : $BID"
echo "kext path : $KEXT"

say "1. 内核 UUID 必须与 KDK 一致"
RUN_UUID=$(sysctl -n kern.uuid)
KDK_UUID=$(xcrun dwarfdump --uuid \
    /Library/Developer/KDKs/KDK_26.7.2_25G330.kdk/System/Library/Kernels/kernel \
    2>/dev/null | awk '{print $2}' | head -1)
echo "running kernel : $RUN_UUID"
echo "KDK kernel     : $KDK_UUID"
[ "$RUN_UUID" = "$KDK_UUID" ] || die "kernel UUID mismatch; do NOT deploy with --allow-missing-kdk"

say "2. 备份现有 AuxKC 与扩展目录清单"
mkdir -p "$BACKUP_DIR"
sudo cp -p "$AUXKC" "$BACKUP_DIR/AuxiliaryKernelExtensions.kc.before"
ls -1 /Library/Extensions > "$BACKUP_DIR/extensions-before.txt"
shasum -a 256 "$AUXKC" | tee "$BACKUP_DIR/auxkc-before.sha256"
echo "backup dir: $BACKUP_DIR"

say "3. 安装 kext"
if [ -d "$DEST" ]; then
    echo "existing $DEST found; moving aside"
    sudo mv "$DEST" "$BACKUP_DIR/AMDMapperProbe.kext.previous"
fi
sudo cp -R "$KEXT" "$DEST"
sudo chown -R root:wheel "$DEST"
sudo chmod -R go-w "$DEST"
ls -ld "$DEST"

say "4. 重建 AuxKC（不碰 Boot/System KC，不关闭 SIP）"
sudo kmutil create -n aux -R / \
    -B /System/Library/KernelCollections/BootKernelExtensions.kc \
    -S /System/Library/KernelCollections/SystemKernelExtensions.kc \
    -A "$AUXKC" \
    -r /Library/Extensions --allow-missing-kdk -z -v
echo "kmutil create rc=$?"

say "5. 确认新 AuxKC 含本 kext 且仍含原有驱动"
sudo kmutil inspect -a -A "$AUXKC" 2>/dev/null | grep -E "$BUNDLE_ID|com.nullmoth|HighPoint" || true
echo "--- expected: $BUNDLE_ID plus com.nullmoth.{NVRM,NVRMAGDC,NVRMFB,NVAccel} and HighPoint ---"

say "6. 完成，需要重启"
cat <<EOF

部署已完成，尚未生效。

下一步：
  1) 重启： sudo reboot
  2) 重启后验证：
       kmutil showloaded --list-only | grep AMDMapperProbe
       log show --last boot | grep AMDMapperProbe
     期望看到：
       AMDMapperProbe: SELFTEST PASS copyMapperForDevice returned 0x...
       AMDMapperProbe: SELFTEST CLEAN removed property, lookup now NULL
       AMDMapperProbe: gSystem remains NULL as expected

回退（任何异常时）：
  sudo rm -rf $DEST
  sudo cp -p $BACKUP_DIR/AuxiliaryKernelExtensions.kc.before $AUXKC
  # 或重新构建：
  sudo kmutil create -n aux -R / \\
    -B /System/Library/KernelCollections/BootKernelExtensions.kc \\
    -S /System/Library/KernelCollections/SystemKernelExtensions.kc \\
    -A $AUXKC -r /Library/Extensions --allow-missing-kdk -z -v
  sudo reboot

备份保留在： $BACKUP_DIR
EOF
