#!/bin/sh
# deploy-b2b.sh — 部署 B2-b（探针 0.6.0 + 从源码构建的 RTL812xLucy）
#
# 用法（在 Mac 上执行）：
#   sh deploy-b2b.sh                 # 只装探针，不放行真实设备（安全）
#   sh deploy-b2b.sh --arm           # 同时加 boot-arg amdiommu=arm（会放行网卡）
#
# 与 deploy-m1a.sh 的差别：
#   1. 同时安装 Lucy（从源码构建，非预编译二进制）；
#   2. --arm 会修改 boot-arg，必须能一键回退。
#
# 本脚本刻意做成「先检查、再备份、最后才写」的顺序。

set -eu

ARM=0
[ "${1:-}" = "--arm" ] && ARM=1

BUNDLE_ID=org.example.AMDMapperProbe
LUCY_ID=com.insanelymac.RTL812xLucy
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
DEST_PROBE=/Library/Extensions/AMDMapperProbe.kext
DEST_LUCY=/Library/Extensions/RTL812xLucy.kext
SRC_PROBE=$HOME/iommu-work/build-m1a/AMDMapperProbe.kext
SRC_LUCY=$HOME/rtl812x-src/build-lucy/RTL812xLucy.kext
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=$HOME/b2b-backup-$STAMP

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf 'ABORT: %s\n' "$1" >&2; exit 1; }

say "0. 产物检查"
[ -d "$SRC_PROBE" ] || die "probe not found: $SRC_PROBE"
[ -d "$SRC_LUCY" ]  || die "lucy not found: $SRC_LUCY (先跑 build-lucy.sh)"
codesign --verify --strict "$SRC_PROBE" || die "probe codesign failed"
codesign --verify --strict "$SRC_LUCY"  || die "lucy codesign failed"
PB=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$SRC_PROBE/Contents/Info.plist")
LB=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$SRC_LUCY/Contents/Info.plist")
echo "probe : $SRC_PROBE (v$PB)"
echo "lucy  : $SRC_LUCY (v$LB, 源码构建)"
[ "$PB" = "0.7.0" ] || die "unexpected probe version: $PB"

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
EN1=$(ifconfig en1 2>/dev/null | grep -c 'inet ' || true)
echo "en1 IPv4 地址数: $EN1 （0 表示不可能抢路由）"

say "3. 备份"
mkdir -p "$BACKUP_DIR"
sudo cp -p "$AUXKC" "$BACKUP_DIR/AuxiliaryKernelExtensions.kc.before"
ls -1 /Library/Extensions > "$BACKUP_DIR/extensions-before.txt"
# 记录 boot-arg 原值，供回退
nvram -p 2>/dev/null | grep -i boot-args > "$BACKUP_DIR/bootargs-before.txt" || true
cat "$BACKUP_DIR/bootargs-before.txt" 2>/dev/null || echo "(no boot-args)"
echo "backup: $BACKUP_DIR"

say "4. 安装两个 kext"
for pair in "$SRC_PROBE:$DEST_PROBE" "$SRC_LUCY:$DEST_LUCY"; do
    s=${pair%%:*}; d=${pair##*:}
    if [ -d "$d" ]; then
        sudo mv "$d" "$BACKUP_DIR/$(basename "$d").previous"
        echo "moved aside: $d"
    fi
    sudo cp -R "$s" "$d"
    sudo chown -R root:wheel "$d"
    sudo chmod -R go-w "$d"
    echo "installed : $d"
done

say "5. 重建 AuxKC"
sudo kmutil create -n aux -R / \
    -B /System/Library/KernelCollections/BootKernelExtensions.kc \
    -S /System/Library/KernelCollections/SystemKernelExtensions.kc \
    -A "$AUXKC" \
    -r /Library/Extensions --allow-missing-kdk -z -v 2>&1 | tail -3
echo "kmutil rc=$?"

say "6. 确认 AuxKC 内容"
sudo kmutil inspect -A "$AUXKC" 2>/dev/null \
    | grep -E "$BUNDLE_ID|$LUCY_ID|com.nullmoth|HighPoint" || true

if [ "$ARM" = "1" ]; then
    say "7. 加 boot-arg amdiommu=arm（放行真实网卡）"
    CUR=$(nvram -p 2>/dev/null | awk '/boot-args/{ $1=""; sub(/^ /,""); print }' || true)
    echo "当前: ${CUR:-(空)}"
    case " $CUR " in
        *" amdiommu=arm "*) echo "已存在，跳过" ;;
        *) NEW=$(printf '%s amdiommu=arm' "$CUR" | sed 's/^ //')
           echo "新值: $NEW"
           sudo nvram boot-args="$NEW"
           echo "已写入" ;;
    esac
    nvram -p | grep -i boot-args || true
else
    say "7. 未加 amdiommu=arm（网卡不会被放行）"
fi

say "完成，需要重启"
cat <<EOF

备份：$BACKUP_DIR

重启：  sudo reboot

重启后验证（探针）：
  ioreg -l -w0 -c org_example_AMDMapperProbe | grep -E 'm1bb-|m1b2a-selftest'
  # 期望（未 arm）：m1bb-armed = "no"，m1bb-parent = "not-armed"
  # 期望（已 arm）：m1bb-armed = "yes"，m1bb-parent = "set"
  #                 m1bb-nic-busy 必须是 "no-good-timing"
  #                 m1bb-realmapok 应 >= 3（三个描述符环）

验证（Lucy）：
  kmutil showloaded --list-only | grep RTL812xLucy
  ioreg -l -w0 -c RTL8125 | grep -E 'IOModel|BSD Name'
  ifconfig en2 2>/dev/null || ifconfig -l

回退（任何异常）：
  sudo rm -rf $DEST_PROBE $DEST_LUCY
  sudo cp -p $BACKUP_DIR/AuxiliaryKernelExtensions.kc.before $AUXKC
  sudo nvram -d boot-args   # 或恢复 $BACKUP_DIR/bootargs-before.txt 里的原值
  sudo reboot
EOF
