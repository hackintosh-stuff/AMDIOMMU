#!/bin/sh
# deploy-m2-1.sh — 部署探针 0.9.0（M2-1：只读 MMIO 探测）
#
# 用法（在 Mac 上执行）：
#   sh deploy-m2-1.sh            # 只装 kext，不加 boot-arg → M2-1 完全不执行（惰性）
#   sh deploy-m2-1.sh --mmio     # 同时把 config.plist 的 boot-args 改成 amdiommu=mmio
#
# 为什么分成两步（这是本项目第一次碰 MMIO）：
#   第一步装惰性版本：证明 0.9.0 除了新增一个被门控的函数之外，
#   行为与 0.8.0 完全一致。若这一步就有问题，与 MMIO 无关，好定位。
#   第二步才真正打开门控去读 IOMMU 寄存器。
#
# 为什么改 config.plist 而不是 nvram：
#   OpenCore 的 config.plist 里 NVRAM/Add/.../boot-args 是固定值且
#   WriteFlash=true，每次启动都会覆盖 nvram。直接 nvram 写会消失
#   （B2-b 已踩过这个坑）。

set -eu

DO_MMIO=0
[ "${1:-}" = "--mmio" ] && DO_MMIO=1

BUNDLE_ID=org.maz1.AMDMapperProbe
LUCY_ID=com.insanelymac.RTL812xLucy
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
DEST_PROBE=/Library/Extensions/AMDMapperProbe.kext
SRC_PROBE=$HOME/iommu-work/build-m1a/AMDMapperProbe.kext
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=$HOME/m21-backup-$STAMP
CONFIG=/Volumes/EFI/EFI/OC/config.plist

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf 'ABORT: %s\n' "$1" >&2; exit 1; }

say "0. 产物检查"
[ -d "$SRC_PROBE" ] || die "probe not found: $SRC_PROBE"
codesign --verify --strict "$SRC_PROBE" || die "probe codesign failed"
PB=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$SRC_PROBE/Contents/Info.plist")
echo "probe : $SRC_PROBE (v$PB)"
[ "$PB" = "0.9.0" ] || die "unexpected probe version: $PB (expected 0.9.0)"

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
nvram -p 2>/dev/null | grep -i boot-args > "$BACKUP_DIR/bootargs-before.txt" || true
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

if [ "$DO_MMIO" = "1" ]; then
    say "7. 修改 config.plist 的 boot-args → amdiommu=mmio"
    [ -f "$CONFIG" ] || die "config.plist not found: $CONFIG (EFI 挂载了吗？)"
    cp "$CONFIG" "$BACKUP_DIR/config.plist.before"
    echo "备份: $BACKUP_DIR/config.plist.before"

    CUR=$(/usr/libexec/PlistBuddy -c \
        'Print :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args' \
        "$CONFIG" 2>/dev/null || echo "")
    echo "当前 boot-args: ${CUR:-(空)}"

    # 去掉已有的 amdiommu=*，再加上 mmio。
    # 注意 PE_parse_boot_argn 只能取到一个值，arm 与 mmio 不能共存。
    NEW=$(printf '%s' "$CUR" | sed 's/ *amdiommu=[A-Za-z0-9]*//g' | sed 's/^ *//; s/ *$//')
    if [ -n "$NEW" ]; then NEW="$NEW amdiommu=mmio"; else NEW="amdiommu=mmio"; fi
    echo "新值: $NEW"

    /usr/libexec/PlistBuddy -c \
        'Set :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args' \
        "$NEW" "$CONFIG" 2>/dev/null \
        || /usr/libexec/PlistBuddy -c \
            'Add :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args string '"$NEW" \
            "$CONFIG"
    plutil -lint "$CONFIG" || die "config.plist 语法错误，已备份"
    echo "已写入并校验"
else
    say "7. 未改 boot-arg（M2-1 门控关闭，不会碰 MMIO）"
fi

say "完成，需要重启"
cat <<EOF

备份：$BACKUP_DIR

重启：  sudo reboot

重启后验证：

  [惰性模式，未加 --mmio]
    ioreg -l -w0 -c org_maz1_AMDMapperProbe | grep 'm2-m1'
    期望：m2-m1-gate = "closed"
          m2-m1-stage = "1-skipped-no-bootarg"
    同时确认无回归：
          m1bb-realmapok = 0x3，m1bb-publishhits = 0x1

  [MMIO 模式，已加 --mmio]
    ioreg -l -w0 -c org_maz1_AMDMapperProbe | grep 'm2-m1'
    核心判据：
      m2-m1-efr      必须 == 0x58f77ef22294a5a
      m2-m1-verdict  必须 == "PASS-efr-match"
    附加情报：
      m2-m1-control         期望 bit0 == 0（IOMMU 未使能）
      m2-m1-iommu-enabled   期望 "no-as-expected"
      m2-m1-devicetable     期望 0x0（从未被编程）
      m2-m1-devicetable-clean 期望 "yes"

  若 efr 不匹配：
      m2-m1-verdict = "FAIL-efr-mismatch"，且不会继续读其他寄存器。
      不要改地址重试——回到 M2-0 重新推理。

回退（任何异常）：
  惰性模式回退：
    sudo rm -rf $DEST_PROBE
    sudo cp -R $BACKUP_DIR/AMDMapperProbe.kext.previous $DEST_PROBE
    sudo cp -p $BACKUP_DIR/AuxiliaryKernelExtensions.kc.before $AUXKC
    sudo reboot

  MMIO 模式回退（去掉 boot-arg）：
    挂载 EFI 后：
      sudo cp -p $BACKUP_DIR/config.plist.before $CONFIG
    或手动把 boot-args 里的 amdiommu=mmio 改成 amdiommu=arm
EOF
