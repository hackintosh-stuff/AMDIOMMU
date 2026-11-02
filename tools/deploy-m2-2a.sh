#!/bin/sh
# deploy-m2-2a.sh — 部署探针 0.10.0（M2-2a-1：最小 MMIO 写测试）
#
# 用法（在 Mac 上执行）：
#   sh deploy-m2-2a.sh           # 只装 kext，boot-arg 保持 arm → 写测试不执行（惰性）
#   sh deploy-m2-2a.sh --write   # 把 config.plist 的 boot-args 改成 amdiommu=write
#
# 这是本项目第一次**写**硬件。风险等级高于 M2-1（只读）：
#   写 MMIO 若落错地址，可能改到别的设备寄存器。
#   缓解措施：写前先读 EFR 确认身份；只写 DEV_TABLE 一个寄存器；
#             写完立即恢复原值；最后确认 CONTROL 未变。
#
# 为什么改 config.plist 而不是 nvram：
#   OpenCore 每次启动用 config.plist 覆盖 nvram（B2-b 已踩过）。

set -eu

DO_WRITE=0
[ "${1:-}" = "--write" ] && DO_WRITE=1

BUNDLE_ID=org.example.AMDMapperProbe
LUCY_ID=com.insanelymac.RTL812xLucy
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
DEST_PROBE=/Library/Extensions/AMDMapperProbe.kext
SRC_PROBE=$HOME/iommu-work/build-m1a/AMDMapperProbe.kext
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=$HOME/m22a-backup-$STAMP
CONFIG=/Volumes/EFI/EFI/OC/config.plist

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf 'ABORT: %s\n' "$1" >&2; exit 1; }

say "0. 产物检查"
[ -d "$SRC_PROBE" ] || die "probe not found: $SRC_PROBE"
codesign --verify --strict "$SRC_PROBE" || die "probe codesign failed"
PB=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$SRC_PROBE/Contents/Info.plist")
echo "probe : $SRC_PROBE (v$PB)"
[ "$PB" = "0.10.0" ] || die "unexpected probe version: $PB (expected 0.10.0)"

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

if [ "$DO_WRITE" = "1" ]; then
    say "7. 修改 config.plist 的 boot-args → amdiommu=write"
    # EFI 可能因重启被卸载，先确保挂载
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
    if [ -n "$NEW" ]; then NEW="$NEW amdiommu=write"; else NEW="amdiommu=write"; fi
    echo "新值: $NEW"

    # 值必须内联进 -c 字符串；作为独立参数时 PlistBuddy 会把它当文件路径。
    /usr/libexec/PlistBuddy -c \
        "Set :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args $NEW" \
        "$CONFIG" || die "PlistBuddy Set 失败"
    plutil -lint "$CONFIG" || die "config.plist 语法错误，已备份"
    echo "已写入并校验"
    echo
    echo "验证:"
    /usr/libexec/PlistBuddy -c \
        'Print :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args' "$CONFIG"
else
    say "7. 未改 boot-arg（写测试门控关闭，不会写 MMIO）"
fi

say "完成，需要重启"
cat <<EOF

备份：$BACKUP_DIR

重启：  sudo reboot

重启后验证：

  [惰性模式，未加 --write]
    ioreg -l -w0 -c org_example_AMDMapperProbe | grep 'm2-2a'
    期望：m2-2a-gate = "closed"
          m2-2a-stage = "1-skipped-no-bootarg"
    同时确认无回归：m1bb-realmapok = 0x3

  [写测试模式，已加 --write]
    ioreg -l -w0 -c org_example_AMDMapperProbe | grep 'm2-2a'

    核心判据（按顺序）：
      m2-2a-identity        必须 "confirmed"（写前 EFR 复验通过）
      m2-2a-devicetable-orig 期望 0x0
      m2-2a-readback        必须 == 0xdeadbeef00000000
      m2-2a-writable        必须 "yes"
      m2-2a-restored        必须 == 0x0（原值）
      m2-2a-restore         必须 "ok"
      m2-2a-verdict         必须 "PASS-mmio-writable"

    安全检查：
      m2-2a-control-after    必须与 M2-1 的 0x220000000400 相同
                             （写 DEV_TABLE 不应改变 CONTROL）
      m2-2a-iommu-enabled    必须 "no-as-expected"

  若 readback 不等于写入值：
      m2-2a-verdict = "FAIL-write-did-not-stick"
      说明该 MMIO 窗口在 macOS 下不可写（可能是只读映射或固件保护）。
      不要反复重试——先分析原因。

  若 restore 不匹配：
      m2-2a-verdict = "FAIL-restore-mismatch"
      这是最坏情况：写入生效但无法恢复。立即回退 boot-arg 并重启。

回退（任何异常）：
  挂载 EFI 后：
    sudo cp -p $BACKUP_DIR/config.plist.before $CONFIG
  或手动把 boot-args 里的 amdiommu=write 改回 amdiommu=arm
EOF
