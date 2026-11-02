#!/bin/sh
# deploy-m2-2b1.sh — 部署探针 0.13.0（M2-2b-1：命令通道验证）
#
# 用法（在 Mac 上执行）：
#   sh deploy-m2-2b1.sh         # 只装 kext，boot-arg 保持 arm → 命令测试不执行
#   sh deploy-m2-2b1.sh --cmd   # 把 config.plist 的 boot-args 改成 amdiommu=cmd
#
# 这是本项目**第一次真正驱动硬件执行动作**：
#   前几步只是配置寄存器，这一步发出一条命令并等待硬件完成。
#
# 仍是短窗口：使能 → 发一条 CMD_COMPL_WAIT → 轮询 cmd_sem → 立即禁用。

set -eu

DO_CMD=0
[ "${1:-}" = "--cmd" ] && DO_CMD=1

BUNDLE_ID=org.example.AMDMapperProbe
LUCY_ID=com.insanelymac.RTL812xLucy
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
DEST_PROBE=/Library/Extensions/AMDMapperProbe.kext
SRC_PROBE=$HOME/iommu-work/build-m1a/AMDMapperProbe.kext
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=$HOME/m22b1-backup-$STAMP
CONFIG=/Volumes/EFI/EFI/OC/config.plist

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf 'ABORT: %s\n' "$1" >&2; exit 1; }

say "0. 产物检查"
[ -d "$SRC_PROBE" ] || die "probe not found: $SRC_PROBE"
codesign --verify --strict "$SRC_PROBE" || die "probe codesign failed"
PB=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$SRC_PROBE/Contents/Info.plist")
echo "probe : $SRC_PROBE (v$PB)"
[ "$PB" = "0.13.0" ] || die "unexpected probe version: $PB (expected 0.13.0)"

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

if [ "$DO_CMD" = "1" ]; then
    say "7. 修改 config.plist 的 boot-args → amdiommu=cmd"
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
    if [ -n "$NEW" ]; then NEW="$NEW amdiommu=cmd"; else NEW="amdiommu=cmd"; fi
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
    say "7. 未改 boot-arg（命令测试门控关闭）"
fi

say "完成，需要重启"
cat <<EOF

备份：$BACKUP_DIR

重启：  sudo reboot

重启后验证：

  [惰性模式]
    ioreg -l -w0 -c org_example_AMDMapperProbe | grep 'm2-b1'
    期望：m2-b1-gate = "closed"，m2-b1-stage = "1-skipped-no-bootarg"

  [命令测试模式]
    ioreg -l -w0 -c org_example_AMDMapperProbe | grep 'm2-b1'

    核心判据：
      m2-b1-identity       必须 "confirmed"
      m2-b1-tbl-pa         设备表物理地址（4 KiB 对齐）
      m2-b1-cmd-pa         命令缓冲物理地址
      m2-b1-sem-pa         完成信号物理地址
      m2-b1-enabled        "yes"
      m2-b1-cmd            "written"
      m2-b1-tail           0x10（16 字节，一条命令）
      m2-b1-sem-value      必须 == 0x1     ← **这是关键：硬件真的写回了**
      m2-b1-cmd-executed   "yes"
      m2-b1-verdict        "PASS-command-channel-works"
      m2-b1-disabled       "yes"

    诊断信息：
      m2-b1-hw-head        硬件消费到的 head 位置，应为 0x10
      m2-b1-hw-tail        我们写的 tail，应为 0x10
      m2-b1-status         状态寄存器
      m2-b1-evt-overflow   "no" 为正常

    若 m2-b1-sem-value = 0x0：
      命令没被执行。可能原因：
        - tail 写入方式错（应为字节偏移，不是索引）
        - cmd_sem 地址编码错
        - 命令 type 位置错（应在 data[1] 的 bit28..31）
        - 硬件要求先开事件日志才能处理命令
      检查 m2-b1-cmd-d0..d3 与 m2-b1-hw-head。

  若这次启动直接 panic：
      说明命令通道配置不安全。回退 boot-arg 后重启，
      重点检查 m2-b1-sem-pa 是否落在合法物理内存内。

回退（任何异常）：
  挂载 EFI 后：
    sudo cp -p $BACKUP_DIR/config.plist.before $CONFIG
EOF
