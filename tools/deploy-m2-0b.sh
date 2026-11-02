#!/bin/sh
# deploy-m2-0b.sh — 部署探针 0.8.0（M2-0b：只读 PCI 配置空间探测）
#
# 用法（在 Mac 上执行）：
#   sh deploy-m2-0b.sh
#
# 与 deploy-b2b.sh 的差别：
#   - 只替换探针，不动 Lucy（Lucy 已在位，是已验证的 0.7.0 状态）
#   - 不加/不改 boot-arg（amdiommu=arm 已在 config.plist 里，保持不变）
#   - 因此本次唯一变量就是探针本身，出问题可以立刻归因
#
# 0.8.0 新增的全部代码是**只读**的 PCI 配置空间访问：
#   configRead8/16/32 → extendedConfigRead8/16/32
# 不碰 MMIO、不写任何寄存器、不改变任何设备状态。

set -eu

BUNDLE_ID=org.example.AMDMapperProbe
LUCY_ID=com.insanelymac.RTL812xLucy
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
DEST_PROBE=/Library/Extensions/AMDMapperProbe.kext
SRC_PROBE=$HOME/iommu-work/build-m1a/AMDMapperProbe.kext
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=$HOME/m20b-backup-$STAMP

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf 'ABORT: %s\n' "$1" >&2; exit 1; }

say "0. 产物检查"
[ -d "$SRC_PROBE" ] || die "probe not found: $SRC_PROBE"
codesign --verify --strict "$SRC_PROBE" || die "probe codesign failed"
PB=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$SRC_PROBE/Contents/Info.plist")
echo "probe : $SRC_PROBE (v$PB)"
[ "$PB" = "0.8.0" ] || die "unexpected probe version: $PB (expected 0.8.0)"

say "1. 内核 UUID 必须与 KDK 一致"
RUN_UUID=$(sysctl -n kern.uuid)
KDK_UUID=$(xcrun dwarfdump --uuid \
    /Library/Developer/KDKs/KDK_26.7.2_25G330.kdk/System/Library/Kernels/kernel \
    2>/dev/null | awk '{print $2}' | head -1)
echo "running : $RUN_UUID"
echo "KDK     : $KDK_UUID"
[ "$RUN_UUID" = "$KDK_UUID" ] || die "kernel UUID mismatch"

say "2. 网络安全检查（SSH 必须走 en0）"
DEF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
echo "default interface: $DEF"
[ "$DEF" = "en0" ] || die "默认路由不是 en0（SSH 可能受影响）"

say "3. 备份"
mkdir -p "$BACKUP_DIR"
sudo cp -p "$AUXKC" "$BACKUP_DIR/AuxiliaryKernelExtensions.kc.before"
ls -1 /Library/Extensions > "$BACKUP_DIR/extensions-before.txt"
# 记录 boot-arg 与 config.plist 原值（本次不修改，仅留档以便归因）
nvram -p 2>/dev/null | grep -i boot-args > "$BACKUP_DIR/bootargs-before.txt" || true
cat "$BACKUP_DIR/bootargs-before.txt" 2>/dev/null || echo "(no boot-args)"
echo "backup: $BACKUP_DIR"

say "4. 安装探针（Lucy 保持不动）"
if [ -d "$DEST_PROBE" ]; then
    sudo mv "$DEST_PROBE" "$BACKUP_DIR/AMDMapperProbe.kext.previous"
    echo "moved aside: $DEST_PROBE"
fi
sudo cp -R "$SRC_PROBE" "$DEST_PROBE"
sudo chown -R root:wheel "$DEST_PROBE"
sudo chmod -R go-w "$DEST_PROBE"
echo "installed : $DEST_PROBE"

say "5. 重建 AuxKC"
sudo kmutil create -n aux -R / \
    -B /System/Library/KernelCollections/BootKernelExtensions.kc \
    -S /System/Library/KernelCollections/SystemKernelExtensions.kc \
    -A "$AUXKC" \
    -r /Library/Extensions --allow-missing-kdk -z -v 2>&1 | tail -3
echo "kmutil rc=$?"

say "6. 确认 AuxKC 内容"
sudo kmutil inspect -A "$AUXKC" 2>/dev/null \
    | grep -E "$BUNDLE_ID|$LUCY_ID" || true

say "完成，需要重启"
cat <<EOF

备份：$BACKUP_DIR

重启：  sudo reboot

重启后验证（M2-0b 新增属性）：
  ioreg -l -w0 -c org_example_AMDMapperProbe | grep -E 'm2-'

  关键判据（按重要性排序）：
    m2-config            必须是 "channel-ok" 或 "capability-found"
                         若为 "FAIL-channel-not-usable"，说明 configRead
                         被 configAccess() 拒绝，BAR 读数不可信，M2-1 需换路
    m2-cfg-vid / did     必须 0x1022 / 0x1481（通道自检）
    m2-cfg-iommu-cap     期望 0x40（与 macOS 的 SecureCapability 一致）
    m2-cfg-bar           这是本次的核心答案：
                           == 0xFD380000 → IVRS 正确，_CRS 陈旧，M2-1 可继续
                           == 0xFEB80000 → 反过来，M2-0 结论要推翻
                           == 第三个值   → 两个来源都不可信，M2-1 必须用 BAR
    m2-cfg-efr-match     "yes" 说明我们读 capability 的位置正确，
                         从而 BAR 读数也可信（独立第二重判据）
    m2-config-verdict    机器可读的判定结论

  同时确认 B2-b 无回归：
    m1bb-realmapok 应仍为 0x3，m1bb-publishhits 应仍为 0x1

回退（任何异常）：
  sudo rm -rf $DEST_PROBE
  sudo cp -R $BACKUP_DIR/AMDMapperProbe.kext.previous $DEST_PROBE
  sudo cp -p $BACKUP_DIR/AuxiliaryKernelExtensions.kc.before $AUXKC
  sudo reboot
EOF
