#!/bin/bash
# 回滚安装：按 manifest 还原被覆盖的文件，并恢复旧 watchdog。
#
# 用法：
#   bash rollback.sh              # 交互确认后回滚
#   bash rollback.sh --yes        # 不确认
#   bash rollback.sh --purge      # 回滚并删除 /opt/wifimgr（保留数据库）

set -u
APP_DIR=/opt/wifimgr
CONF=/etc/wifimgr.json
UNIT=/etc/systemd/system/wifimgr.service
NGINX_INC=/etc/nginx/locations.d/wifimgr.conf
TMPFILES=/etc/tmpfiles.d/wifimgr.conf
LEGACY_SCRIPT=/usr/local/bin/wifi-check.sh
LEGACY_CRON=/etc/cron.d/wifi-check

ASSUME_YES=0
PURGE=0
for a in "$@"; do
  case "$a" in
    --yes|-y) ASSUME_YES=1 ;;
    --purge)  PURGE=1 ;;
    *) echo "未知参数: $a"; exit 1 ;;
  esac
done

RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYC=$'\033[36m'; RST=$'\033[0m'
ok()   { printf '  %s✓%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '  %s!%s %s\n' "$YLW" "$RST" "$*"; }
die()  { printf '  %s✗%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
step() { printf '\n%s==>%s %s\n' "$CYC" "$RST" "$*"; }

[ "$(id -u)" = "0" ] || die "必须以 root 运行"

if [ "$ASSUME_YES" != "1" ]; then
  warn "将执行以下操作："
  say "    1. 停止并禁用 wifimgr 服务"
  say "    2. 移除 systemd unit 与 nginx 片段（若有 .bak 则还原）"
  [ "$PURGE" = "1" ] && say "    3. 删除 $APP_DIR（数据库 /var/lib/wifimgr 保留）"
  say "    4. 恢复旧 wifi-check.sh 与 /etc/cron.d/wifi-check"
  say "    5. 恢复 RD08_IoT 的 autoconnect"
  read -r -p "  确认回滚？[y/N] " ans
  case "$ans" in [yY]*) : ;; *) say "已取消"; exit 0 ;; esac
fi

step "1/5 停止服务"
systemctl disable --now wifimgr.service >/dev/null 2>&1 && ok "已停止并取消自启" || warn "服务未在运行"

step "2/5 还原 nginx"
if [ -f "$NGINX_INC" ]; then
  if [ -f "${NGINX_INC}.bak-"* ] 2>/dev/null; then
    # shellcheck disable=SC2046
    BAK=$(ls -1t "${NGINX_INC}.bak-"* 2>/dev/null | head -1)
    cp -a "$BAK" "$NGINX_INC" && ok "已从 $BAK 还原 nginx 片段"
  else
    rm -f "$NGINX_INC" && ok "已移除 nginx 片段（无备份，原本不存在）"
  fi
  if nginx -t 2>/dev/null; then
    systemctl reload nginx && ok "nginx 已 reload"
  else
    warn "nginx -t 失败，未 reload（请手工检查）"
  fi
else
  ok "无 nginx 片段"
fi

step "3/5 移除 systemd unit / tmpfiles"
[ -f "$UNIT" ] && { rm -f "$UNIT"; ok "已移除 $UNIT"; } || ok "无 unit"
[ -f "$TMPFILES" ] && { rm -f "$TMPFILES"; ok "已移除 $TMPFILES"; } || ok "无 tmpfiles"
systemctl daemon-reload && ok "daemon-reload 完成"
systemctl reset-failed wifimgr.service >/dev/null 2>&1 || true

step "4/5 恢复旧 watchdog"
if [ -f "$LEGACY_CRON" ]; then
  if grep -q '^# disabled-by-wifimgr' "$LEGACY_CRON"; then
    # 去掉「disabled-by-wifimgr 」前缀，恢复原行
    sed -i 's/^# disabled-by-wifimgr //' "$LEGACY_CRON"
    if grep -v '^[[:space:]]*#' "$LEGACY_CRON" | grep -q 'wifi-check\.sh'; then
      ok "已恢复 cron 活动行: $LEGACY_CRON"
    else
      warn "恢复后未检测到活动行，请手工检查 $LEGACY_CRON"
    fi
  else
    ok "cron 未处于停用状态"
  fi
else
  ok "无旧 cron"
fi
if [ -f "$LEGACY_SCRIPT" ]; then
  chmod 0755 "$LEGACY_SCRIPT" && ok "旧脚本权限恢复为 0755"
else
  ok "无旧脚本"
fi

step "5/5 恢复 RD08_IoT autoconnect"
if nmcli -t -f NAME con show 2>/dev/null | grep -qx 'RD08_IoT'; then
  nmcli con mod RD08_IoT connection.autoconnect yes >/dev/null 2>&1 \
    && ok "RD08_IoT autoconnect=yes" || warn "恢复失败"
else
  ok "无 RD08_IoT profile"
fi

if [ "$PURGE" = "1" ]; then
  step "附加：删除 $APP_DIR"
  rm -rf "$APP_DIR" && ok "已删除（数据库 /var/lib/wifimgr 已保留）"
fi

echo
say "${GRN}回滚完成${RST}"
say "  数据库保留在 /var/lib/wifimgr（如需清理请手工 rm -rf）"
say "  各文件的 .bak-* 备份仍在原处，确认无误后可自行删除"
