#!/bin/sh
# deploy-m2-2b2.sh — 部署探针 0.23.0（M2-2b-2：4 级恒等页表 + 单设备 DTE 切换）
#
# 用法（在 Mac 上执行）：
#   sh deploy-m2-2b2.sh         # 只装 kext，boot-arg 保持原样 → 页表测试不执行
#   sh deploy-m2-2b2.sh --pgt   # 把 config.plist 的 boot-args 改成 amdiommu=pgt
#
# 这一步是 M2 里**第一次让硬件真的按我们写的页表翻译 DMA**。
# 前面所有步骤设备表都是"直通"（TV=1, MODE=0），硬件从不看页表。
#
# 安全设计：
#   - 恒等映射（IOVA == PA）：即使页表有错，最坏是 DMA 失败，不会写错内存
#   - 只切一个设备（RTL8127，devid 运行时取自 IOPCIDevice，本机 0x2500；
#     不是默认路由的网卡）
#   - 开事件日志：任何 fault 都会被记录，我们能读到
#   - 观察 2 秒后 DTE 改回直通，全部寄存器还原
#
# 页表规模：16 GiB 用 2 MiB 大页 = 1 根表 + 1 L2 + 16 叶子 = 18 页 = 72 KiB

set -eu

DO_PGT=0
[ "${1:-}" = "--pgt" ] && DO_PGT=1

BUNDLE_ID=org.maz1.AMDMapperProbe
LUCY_ID=com.insanelymac.RTL812xLucy
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
DEST_PROBE=/Library/Extensions/AMDMapperProbe.kext
SRC_PROBE=$HOME/iommu-work/build-m1a/AMDMapperProbe.kext
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=$HOME/m22b2-backup-$STAMP
CONFIG=/Volumes/EFI/EFI/OC/config.plist

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf 'ABORT: %s\n' "$1" >&2; exit 1; }

say "0. 产物检查"
[ -d "$SRC_PROBE" ] || die "probe not found: $SRC_PROBE"
codesign --verify --strict "$SRC_PROBE" || die "probe codesign failed"
PB=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$SRC_PROBE/Contents/Info.plist")
echo "probe : $SRC_PROBE (v$PB)"
[ "$PB" = "0.24.0" ] || die "unexpected probe version: $PB (expected 0.24.0)"

say "1. 内核 UUID 必须与 KDK 一致"
RUN_UUID=$(sysctl -n kern.uuid)
KDK_UUID=$(xcrun dwarfdump --uuid \
    /Library/Developer/KDKs/KDK_26.7.2_25G330.kdk/System/Library/Kernels/kernel \
    2>/dev/null | awk '{print $2}' | head -1)
echo "running : $RUN_UUID"
echo "KDK     : $KDK_UUID"
[ "$RUN_UUID" = "$KDK_UUID" ] || die "kernel UUID mismatch"

say "2. 网络安全检查（SSH 走的是直连路由，不是默认路由）"
# 【2026-10-31 修正】两点都必须对：
#   a) 原先检查 `default` 是否走 en0 —— 无依据。SSH 到 192.168.50.204 与
#      操作端同在 192.168.50.0/24，走直连路由，与默认路由无关。
#      实测 en2 抢走默认路由期间 SSH 全程未断。
#   b) 修正后又误查了**本机自己的 IP**（192.168.50.204 → 必然 lo0）。
#      要查的是**操作端/对端**的地址。
# 真正需要保证的：192.168.50.0/24 的直连路由存在且挂在 en0 上。
PEER_IP=192.168.50.159          # 操作端（Windows）地址
SELF_IP=$(ipconfig getifaddr en0 2>/dev/null)
PEER_IF=$(route -n get "$PEER_IP" 2>/dev/null | awk '/interface:/{print $2}')
PEER_DEST=$(route -n get "$PEER_IP" 2>/dev/null | awk '/destination:/{print $2}')
DEF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
echo "本机 en0 地址: ${SELF_IP:-none}"
echo "到操作端 $PEER_IP: destination=$PEER_DEST interface=$PEER_IF"
echo "默认路由(仅记录，不作判据): $DEF"
[ "$PEER_IF" = "en0" ] || die "到操作端的路由不走 en0（实际 $PEER_IF），拒绝继续"
netstat -rn -f inet | grep -qE "^192\.168\.50 .*en0" \
    || die "192.168.50.0/24 直连路由不在 en0 上，拒绝继续"
echo "OK: 192.168.50.0/24 直连路由在 en0，SSH 通路不受 en2 影响"

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

if [ "$DO_PGT" = "1" ]; then
    say "7. 修改 config.plist 的 boot-args → amdiommu=pgt"
    if [ ! -f "$CONFIG" ]; then
        # 【2026-10-30 教训】不能取 `diskutil list` 里第一个 "EFI EFI"：
        # 本机有多个 EFI 分区，disk0s1 是 209.7 MB 的空分区（只有 Spotlight
        # 痕迹），macOS 的 OpenCore EFI 是 disk2s1（272.6 MB）。
        # 盲目取第一个会挂到错的分区，然后 PlistBuddy 对不存在的路径
        # 打印 "File Doesn't Exist, Will Create:" ——看起来像成功，其实没写。
        # 正确做法：挂载后**必须验证 config.plist 真的存在且语法正确**。
        echo "EFI 未挂载，按容量定位 macOS 的 EFI 分区..."
        EFI_PART=""
        for p in $(diskutil list | awk '/EFI EFI/ {print $NF}'); do
            if [ -f "/Volumes/EFI/EFI/OC/config.plist" ]; then
                EFI_PART="$p"; break
            fi
        done
        if [ -z "$EFI_PART" ]; then
            # 逐个尝试挂载，找到真正含 OpenCore config.plist 的那个
            for p in $(diskutil list | awk '/EFI EFI/ {print $NF}'); do
                sudo diskutil mount "$p" >/dev/null 2>&1 || continue
                if [ -f "/Volumes/EFI/EFI/OC/config.plist" ]; then
                    EFI_PART="$p"; break
                fi
                sudo diskutil unmount "/Volumes/EFI" >/dev/null 2>&1 || true
            done
        fi
        [ -n "$EFI_PART" ] || die "找不到含 OpenCore config.plist 的 EFI 分区"
        echo "使用 EFI 分区: $EFI_PART"
    fi
    [ -f "$CONFIG" ] || die "config.plist not found: $CONFIG"
    plutil -lint "$CONFIG" >/dev/null || die "config.plist 语法错误，不敢修改"

    cp "$CONFIG" "$BACKUP_DIR/config.plist.before"
    echo "备份: $BACKUP_DIR/config.plist.before"

    CUR=$(/usr/libexec/PlistBuddy -c \
        'Print :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args' \
        "$CONFIG" 2>/dev/null || echo "")
    echo "当前 boot-args: ${CUR:-(空)}"

    NEW=$(printf '%s' "$CUR" | sed 's/ *amdiommu=[A-Za-z0-9]*//g' | sed 's/^ *//; s/ *$//')
    if [ -n "$NEW" ]; then NEW="$NEW amdiommu=pgt"; else NEW="amdiommu=pgt"; fi
    echo "新值: $NEW"

    # 【2026-10-30 重要修正】PlistBuddy 的 Set 必须把值**内联在 -c 字符串里**。
    # 写成 `PlistBuddy -c 'Set :path' "$NEW" "$CONFIG"` 时，PlistBuddy 会把
    # "$NEW" 当成**第二个文件路径**，于是报
    #   File Doesn't Exist, Will Create: -v keepsyms=1 ...
    #   Invalid Arguments
    # 并 rc=1。而 plutil -lint 仍然通过（文件根本没被改），
    # 所以失败是**静默**的——这正是 M2-1 到 M2-2b-1 期间 config.plist
    # 一直停在 amdiommu=arm、而 nvram 却是 cmd 的原因。
    # 正确写法：把整条命令拼成一个 -c 参数。
    /usr/libexec/PlistBuddy -c \
        "Set :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args $NEW" \
        "$CONFIG" || die "PlistBuddy Set 失败"
    plutil -lint "$CONFIG" || die "config.plist 语法错误，已备份"

    # 验证真的写进去了（不能只看 plutil）
    AFTER=$(/usr/libexec/PlistBuddy -c \
        'Print :NVRAM:Add:7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args' \
        "$CONFIG")
    echo "写入后: $AFTER"
    case "$AFTER" in
        *amdiommu=pgt*) echo "验证: config.plist 已含 amdiommu=pgt" ;;
        *) die "config.plist 未包含 amdiommu=pgt，写入未生效" ;;
    esac
else
    say "7. 未改 boot-arg（页表测试门控关闭）"
fi

say "完成，需要重启"
cat <<EOF

备份：$BACKUP_DIR

重启：  sudo reboot

重启后验证：

  [惰性模式]
    ioreg -l -w0 -c org_maz1_AMDMapperProbe | grep 'm2-b2'
    期望：m2-b2-gate = "closed"，m2-b2-stage = "1-skipped-no-bootarg"

  [页表测试模式]
    ioreg -l -w0 -c org_maz1_AMDMapperProbe | grep 'm2-b2'

    内存布局（先看这些，地址不对后面都不可信）：
      m2-b2-pt-pa          页表物理基址，必须 4 KiB 对齐
      m2-b2-pt-pages       必须是 0x12 (18)
      m2-b2-pt-bytes       必须是 0x12000 (73728)
      m2-b2-tbl-pa         设备表物理地址（2 MiB 对齐更好）
      m2-b2-cmd-pa         命令缓冲
      m2-b2-sem-pa         完成信号
      m2-b2-evt-pa         事件日志

    页表自检（软件走表，不碰硬件）：
      m2-b2-walk           "ok"        ← 若 FAIL，后面的硬件测试不会执行
      m2-b2-walk-bad       0
      m2-b2-walk-samples   0xb (11)

    硬件侧：
      m2-b2-identity       "confirmed"
      m2-b2-enabled        "yes"
      m2-b2-evt-log        "enabled"
      m2-b2-inv-all        "done"          ← 使能后第一次清缓存
      m2-b2-dte            "switched-to-translation"
      m2-b2-dte-before     0x6000000000000003（直通）
      m2-b2-dte-after      应形如 0x6000000000000803 | rootPA
                           （V|TV|MODE=4|IR|IW，MODE=4 在 bit9..11）
      m2-b2-inv            "dev-entry+pages-flushed"

    核心判据（2026-10-31 修订：旧判据"evt-count2 必须为 0"已被推翻）：
      不要再用"有没有 fault"当判据——正确页表本身在 2 秒窗口里就有
      6~56 个 fault。用下面这组有区分力的字段：

      m2-b2-evt-dominant       事件类型（此前从未记录过，这是关键盲区）
                               IO_PAGE_FAULT       PTE 不存在/权限不足
                               PAGE_TAB_ERR        PTE 结构本身畸形
                               DEV_TAB_ERR         DTE 本身非法
                               ILL_CMD/CMD_HARD_ERR 命令错 → 页表结论无效
      m2-b2-fault-inrange      落在映射范围内的 fault 数
      m2-b2-fault-outofrange   落在映射范围外的 fault 数
                               ← 若 inrange=0 且 outofrange>0，
                                 页表根本没被真正测到，旧 FAIL 结论不安全
      m2-b2-fault-walk-verdict TABLE-MISSING-ENTRIES  范围内地址页表里查不到
                               TABLE-OK-HARDWARE-SIDE 全部命中 → 问题在硬件侧
                               NO-IN-RANGE-FAULT      没测到

      m2-b2-leafprobe-baseline 表完好时的稳态 fault 数
      m2-b2-leafprobe-faults   整张叶子表清零后的 fault 数
      m2-b2-leafprobe-verdict  LEAF-LEVEL-REACHED        硬件走得到叶子层
                               LEAF-LEVEL-NOT-REACHED    走不到
                               INCONCLUSIVE-...          仍无法区分

      m2-b2-disabled       "yes"
      m2-b2-dte-restore    "done"
      m2-b2-restore-inv    "done"
      m2-b2-final-control  必须回到 0x220000000400
      m2-b2-final-devicetable / -cmdbuf / -evtbuf  必须回到原值

    一键汇总（在 Mac 上）：
      ioreg -l -w0 -c org_maz1_AMDMapperProbe | python3 tools/analyze-m2b2.py -

    关于事件类型：
      IO_PAGE_FAULT  页表没覆盖这个地址，或大小编码/权限位错
      DEV_TAB_ERR    设备表项本身不合法
      PAGE_TAB_ERR   页表项结构错（NEXT_LEVEL / PR）
      ILL_CMD        命令格式错
      CMD_HARD_ERR   命令缓冲地址或对齐问题
    设备 devid 是运行时取的（本机 0x2500），不要再对照 0x3700。

    若 m2-b2-verdict = "FAIL-software-walk"：
      页表在交给硬件前就被自己的自检拦下了，硬件从未见过这张表。
      看 m2-b2-walk-firstbad 是哪个 IOVA。
      这是最安全的一种失败。

  若这次启动直接 panic：
      页表或 DTE 编码有根本错误。回退 boot-arg 后重启。
      注意：本步骤用恒等映射，理论上不该出现"写错内存"型损坏；
      若真的 panic，重点查 DTE 的 MODE 字段（bit9..11）是否为 4。

回退（任何异常）：
  挂载 EFI 后：
    sudo cp -p $BACKUP_DIR/config.plist.before $CONFIG
EOF
