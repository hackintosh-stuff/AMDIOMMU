#!/bin/sh
# deploy-m2-2a2.sh — 部署探针 0.11.0（M2-2a-2：建设备表，不使能）
#
# 用法（在 Mac 上执行）：
#   sh deploy-m2-2a2.sh          # 只装 kext，boot-arg 保持 arm → 建表不执行（惰性）
#   sh deploy-m2-2a2.sh --table  # 把 config.plist 的 boot-args 改成 amdiommu=table
#
# 本步骤**不使能 IOMMU**：
#   IOMMU 关闭时硬件不读设备表，所以系统行为必须完全不变。
#   这验证「表建立」本身无害，把「表对不对」与「使能后稳不稳」分开。

set -eu

DO_TABLE=0
[ "${1:-}" = "--table" ] && DO_TABLE=1

BUNDLE_ID=org.example.AMDMapperProbe
LUCY_ID=com.insanelymac.RTL812xLucy
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
DEST_PROBE=/Library/Extensions/AMDMapperProbe.kext
SRC_PROBE=$HOME/iommu-work/build-m1a/AMDMapperProbe.kext
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=$HOME/m22a2-backup-$STAMP
CONFIG=/Volumes/EFI/EFI/OC/config.plist

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf 'ABORT: %s\n' "$1" >&2; exit 1; }

say "0. 产物检查"
[ -d "$SRC_PROBE" ] || die "probe not found: $SRC_PROBE"
codesign --verify --strict "$SRC_PROBE" || die "probe codesign failed"
PB=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$SRC_PROBE/Contents/Info.plist")
echo "probe : $SRC_PROBE (v$PB)"
[ "$PB" = "0.11.0" ] || die "unexpected probe version: $PB (expected 0.11.0)"

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

if [ "$DO_TABLE" = "1" ]; then
    say "7. 修改 config.plist 的 boot-args → amdiommu=table"
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
    if [ -n "$NEW" ]; then NEW="$NEW amdiommu=table"; else NEW="amdiommu=table"; fi
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
    say "7. 未改 boot-arg（建表门控关闭）"
fi

say "完成，需要重启"
cat <<EOF

备份：$BACKUP_DIR

重启：  sudo reboot

重启后验证：

  [惰性模式]
    ioreg -l -w0 -c org_example_AMDMapperProbe | grep 'm2-2b'
    期望：m2-2b-gate = "closed"，m2-2b-stage = "1-skipped-no-bootarg"
    确认无回归：m1bb-realmapok = 0x3

  [建表模式]
    ioreg -l -w0 -c org_example_AMDMapperProbe | grep 'm2-2b'

    核心判据：
      m2-2b-2mib        "ok" 表示拿到了 2 MiB 连续内存；
                        若 "FAILED" 则退到 4 KiB，看 m2-2b-tablesize
      m2-2b-tablesize   期望 0x200000（2 MiB）
      m2-2b-pa          设备表物理地址
      m2-2b-contiguous  "yes"
      m2-2b-aligned     "yes"
      m2-2b-dtecount    65536（2 MiB / 32）
      m2-2b-fillcheck   "ok"
      m2-2b-tableset    "yes"
      m2-2b-verdict     "PASS-table-built"

    安全检查（最重要）：
      m2-2b-control          必须 == 0x220000000400（与 M2-1/M2-2a-1 相同）
      m2-2b-iommu-enabled    必须 "no-as-expected"
      m2-2b-restore          必须 "ok"

    注意：本步骤结束后 DEV_TABLE 寄存器已恢复原值 0，
          设备表内存已释放。这是有意的——M2-2a-3 会重新建表并使能。

  若 m2-2b-2mib = "FAILED"：
      说明 start() 早期拿不到 2 MiB 物理连续内存。
      这不是失败，是需要知道的事实：M2-2a-3 之前必须解决内存分配策略
      （例如推迟到更晚的时机，或用 IOKit 的 physical mask 接口）。

回退（任何异常）：
  挂载 EFI 后：
    sudo cp -p $BACKUP_DIR/config.plist.before $CONFIG
EOF
