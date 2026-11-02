#!/bin/sh
# deploy-m2-2a3.sh — 部署探针 0.12.0（M2-2a-3：短窗口使能测试）
#
# 用法（在 Mac 上执行）：
#   sh deploy-m2-2a3.sh           # 只装 kext，boot-arg 保持 arm → 使能测试不执行（惰性）
#   sh deploy-m2-2a3.sh --enable  # 把 config.plist 的 boot-args 改成 amdiommu=enable
#
# 这是本项目**风险最高**的一步：使能 IOMMU 后全系统 DMA 走设备表。
# 但窗口极短——使能、读状态、立即禁用。
#
# 如果短窗口就崩溃，说明设备表地址、size 编码或命令缓冲配置有根本问题，
# 不必冒险长时间运行。这是本步骤存在的全部意义。

set -eu

DO_ENABLE=0
[ "${1:-}" = "--enable" ] && DO_ENABLE=1

BUNDLE_ID=org.example.AMDMapperProbe
LUCY_ID=com.insanelymac.RTL812xLucy
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
DEST_PROBE=/Library/Extensions/AMDMapperProbe.kext
SRC_PROBE=$HOME/iommu-work/build-m1a/AMDMapperProbe.kext
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=$HOME/m22a3-backup-$STAMP
CONFIG=/Volumes/EFI/EFI/OC/config.plist

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf 'ABORT: %s\n' "$1" >&2; exit 1; }

say "0. 产物检查"
[ -d "$SRC_PROBE" ] || die "probe not found: $SRC_PROBE"
codesign --verify --strict "$SRC_PROBE" || die "probe codesign failed"
PB=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$SRC_PROBE/Contents/Info.plist")
echo "probe : $SRC_PROBE (v$PB)"
[ "$PB" = "0.12.0" ] || die "unexpected probe version: $PB (expected 0.12.0)"

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

if [ "$DO_ENABLE" = "1" ]; then
    say "7. 修改 config.plist 的 boot-args → amdiommu=enable"
    if [ ! -f "$CONFIG" ]; then
        echo "EFI 未挂载，尝试挂载..."
        EFI_PART=$(diskutil list | awk '/EFI EFI/ {print $NF; exit}')
        [ -n "$EFI_PART" ] || die "找不到 EFI 分区"
        sudo diskutil mount "$EFI_PART" || die "挂载 EFI 失败"
    fi
    [ -f "$CONFIG" ] || die "config.plist not found: $CONFIG"

    cp "$CONFIG" "$BACKUP_DIR/config.plist.before"
    echo "备份: $BACKUP_DIR/config.plist.before"

    CUR=$(/usr/libexec/PlistBuddy -c \
        'Print :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args' \
        "$CONFIG" 2>/dev/null || echo "")
    echo "当前 boot-args: ${CUR:-(空)}"

    NEW=$(printf '%s' "$CUR" | sed 's/ *amdiommu=[A-Za-z0-9]*//g' | sed 's/^ *//; s/ *$//')
    if [ -n "$NEW" ]; then NEW="$NEW amdiommu=enable"; else NEW="amdiommu=enable"; fi
    echo "新值: $NEW"

    # 值必须内联进 -c 字符串；作为独立参数时 PlistBuddy 会把它当文件路径。
    /usr/libexec/PlistBuddy -c \
        "Set :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args $NEW" \
        "$CONFIG" || die "PlistBuddy Set 失败"
    plutil -lint "$CONFIG" || die "config.plist 语法错误，已备份"
    echo
    /usr/libexec/PlistBuddy -c \
        'Print :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args' "$CONFIG"
else
    say "7. 未改 boot-arg（使能门控关闭）"
fi

say "完成，需要重启"
cat <<EOF

备份：$BACKUP_DIR

重启：  sudo reboot

重启后验证：

  [惰性模式]
    ioreg -l -w0 -c org_example_AMDMapperProbe | grep 'm2-3'
    期望：m2-3-gate = "closed"，m2-3-stage = "1-skipped-no-bootarg"
    确认无回归：m1bb-realmapok = 0x3

  [使能模式]
    ioreg -l -w0 -c org_example_AMDMapperProbe | grep 'm2-3'

    核心判据：
      m2-3-identity      必须 "confirmed"（写前 EFR 复验）
      m2-3-tbl-pa        设备表物理地址
      m2-3-cmd-pa        命令缓冲物理地址
      m2-3-devicetable-entry   基址 | 0x1FF
      m2-3-cmdbuf-entry        基址 | (0x9 << 56)   ← size 编码在高位！
      m2-3-cmdbuf-enabled      "yes"
      m2-3-enabled             "yes"   ← IOMMU 真的起来了
      m2-3-disabled            "yes"   ← 并且成功关掉了
      m2-3-verdict             "PASS-enable-disable-window"

    安全检查：
      m2-3-orig-control    期望 0x220000000400（进来时的状态）
      m2-3-control-enabled 应为 orig | 0x1 | 0x1000
      m2-3-control-disabled 应为 orig | 0x1000（IOMMU_EN 已清）
      m2-3-final-control   应回到 0x220000000400
      m2-3-final-devicetable 应回到 0x0
      m2-3-final-cmdbuf      应回到 0x0

  若 m2-3-enabled = "no"：
      写 IOMMU_EN 后读回该位仍为 0。可能是固件锁定了该位，或需要
      额外前提条件。不要反复重试。

  若 m2-3-disabled = "no"：
      最坏情况：IOMMU 使能后关不掉。此时系统可能已经不稳定。
      立即断电重启（NanoKVM），并把 boot-arg 改回 arm。

  若这次启动直接 panic：
      说明使能动作本身不安全。检查 m2-3-devicetable-entry 与
      m2-3-cmdbuf-entry 的编码，尤其是 CMD_BUF 的 size 在高位这一点。
      回退 boot-arg 后重启。

回退（任何异常）：
  挂载 EFI 后：
    sudo cp -p $BACKUP_DIR/config.plist.before $CONFIG
EOF
