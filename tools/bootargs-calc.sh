#!/bin/sh
# bootargs-calc.sh — 只读：计算并展示 boot-args 的目标值与差异。不写 NVRAM。
CUR=$(nvram boot-args 2>/dev/null | sed 's/^boot-args[[:space:]]*//')
NEW=$(echo "$CUR" | sed 's/debug=0x108/debug=0x288/')
case "$NEW" in
  *kdp_match_name=serial*) : ;;
  *) NEW="$NEW kdp_match_name=serial" ;;
esac

echo "OLD=[$CUR]"
echo
echo "NEW=[$NEW]"
echo
echo "--- token diff ---"
for t in $CUR; do
  case " $NEW " in *" $t "*) : ;; *) echo "  removed: $t" ;; esac
done
for t in $NEW; do
  case " $CUR " in *" $t "*) : ;; *) echo "  added: $t" ;; esac
done
echo
echo "--- length ---"
printf 'old=%s new=%s\n' "$(printf '%s' "$CUR" | wc -c | tr -d ' ')" "$(printf '%s' "$NEW" | wc -c | tr -d ' ')"
