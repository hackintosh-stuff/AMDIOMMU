#!/bin/sh
# set-bootargs-kdp.sh — 把 boot-args 改为串口 KDP 形态（需 sudo，在 Mac 本地执行）
#
# 用法：
#   sh set-bootargs-kdp.sh            # 应用新参数
#   sh set-bootargs-kdp.sh --revert   # 恢复本脚本最近一次保存的旧值
#   sh set-bootargs-kdp.sh --dry-run  # 只显示将写入什么，不写
#
# 改动只有两处：
#   debug=0x108  ->  debug=0x288        （补 DB_KDP_GETC_ENA 0x200）
#   追加 kdp_match_name=serial          （x86_64 上串口 KDP 必须显式请求）
# 其余参数逐字保留。

set -eu

SAVE=$HOME/.bootargs-before-kdp.txt
DRY=0
REVERT=0
for a in "$@"; do
    case "$a" in
        --dry-run) DRY=1 ;;
        --revert)  REVERT=1 ;;
        *) echo "unknown arg: $a" >&2; exit 2 ;;
    esac
done

cur() { nvram boot-args 2>/dev/null | sed 's/^boot-args[[:space:]]*//'; }

if [ "$REVERT" = "1" ]; then
    [ -f "$SAVE" ] || { echo "no saved value at $SAVE" >&2; exit 1; }
    OLD=$(cat "$SAVE")
    echo "reverting to: [$OLD]"
    sudo nvram boot-args="$OLD"
    echo "now: [$(cur)]"
    echo "重启后生效。"
    exit 0
fi

CUR=$(cur)
[ -n "$CUR" ] || { echo "cannot read current boot-args" >&2; exit 1; }

NEW=$(echo "$CUR" | sed 's/debug=0x108/debug=0x288/')
case "$NEW" in
    *kdp_match_name=serial*) : ;;
    *) NEW="$NEW kdp_match_name=serial" ;;
esac

# 自检：必须确实含 0x288 与 kdp_match_name=serial
case " $NEW " in *" debug=0x288 "*) : ;; *) echo "ERROR: debug=0x288 not produced" >&2; exit 1 ;; esac
case " $NEW " in *" kdp_match_name=serial "*) : ;; *) echo "ERROR: kdp_match_name=serial not produced" >&2; exit 1 ;; esac

echo "OLD=[$CUR]"
echo "NEW=[$NEW]"
echo
echo "--- token diff ---"
for t in $CUR; do case " $NEW " in *" $t "*) : ;; *) echo "  removed: $t" ;; esac; done
for t in $NEW; do case " $CUR " in *" $t "*) : ;; *) echo "  added: $t" ;; esac; done
echo

if [ "$DRY" = "1" ]; then
    echo "dry-run: nothing written."
    exit 0
fi

printf '%s' "$CUR" > "$SAVE"
echo "saved previous value to $SAVE"
sudo nvram boot-args="$NEW"
echo "written. current: [$(cur)]"
echo
echo "重启后生效。回退： sh $0 --revert"
echo
echo "注意：若重启后串口不通、且发生 panic，机器可能停在等待调试器连接。"
echo "      届时用 NanoKVM 长按电源键约 6 秒强制关机，再用本脚本 --revert 恢复。"
