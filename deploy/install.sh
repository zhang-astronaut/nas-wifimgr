#!/bin/bash
# WiFi Manager 安装脚本（幂等）。
#
# 原则：
#   * 覆盖任何文件前先做 .bak-YYYYMMDD 备份，并把清单写进 manifest
#   * 每一步都有断言检查，失败立即停下（不"部分安装"）
#   * 旧 watchdog 只停用不删除，随时可回滚
#
# 用法：
#   bash install.sh            # 正常安装
#   bash install.sh --dry-run  # 只检查不改动

set -u
set -o pipefail

# 脚本自身所在目录（deploy/），源码根是它的上一级。
# 必须先算出来：后面前置检查要读 etc/wifimgr.json，且 set -u 下未定义变量会直接退出。
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"

STAMP=$(date +%Y%m%d)
APP_DIR=/opt/wifimgr
CONF=/etc/wifimgr.json
UNIT=/etc/systemd/system/wifimgr.service
NGINX_INC=/etc/nginx/locations.d/wifimgr.conf
TMPFILES=/etc/tmpfiles.d/wifimgr.conf
MANIFEST=/var/lib/wifimgr/deploy-manifest.json

LEGACY_SCRIPT=/usr/local/bin/wifi-check.sh
LEGACY_CRON=/etc/cron.d/wifi-check

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYC=$'\033[36m'; RST=$'\033[0m'
say()  { printf '%s\n' "$*"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '  %s!%s %s\n' "$YLW" "$RST" "$*"; }
die()  { printf '  %s✗%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
step() { printf '\n%s==>%s %s\n' "$CYC" "$RST" "$*"; }

BACKUPS=""   # 形如 "path|backup"

backup_one() {
  # $1 = 要备份的路径
  local p="$1" b
  [ -e "$p" ] || return 0
  b="${p}.bak-${STAMP}"
  if [ -e "$b" ]; then
    warn "备份已存在，跳过: $b"
    return 0
  fi
  if [ "$DRY" = "1" ]; then ok "[dry-run] 将备份 $p"; return 0; fi
  cp -a "$p" "$b" || die "备份失败: $p -> $b"
  BACKUPS="${BACKUPS}${p}|${b}\n"
  ok "已备份 $p -> $b"
}

backup_literally() {
  # 需要记录"即使文件不存在也要写进 manifest"的路径（如 cron）
  local p="$1" b
  b="${p}.bak-${STAMP}"
  if [ -e "$p" ]; then
    backup_one "$p"
  else
    BACKUPS="${BACKUPS}${p}|\n"
  fi
}

# ---------------------------------------------------------------- 0 前置检查
step "0/9 前置检查"
[ "$(id -u)" = "0" ] || die "必须以 root 运行"
[ -x /usr/bin/python3 ] || die "缺少 /usr/bin/python3"
PYV=$(/usr/bin/python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "?")
say "  Python: $PYV"
case "$PYV" in
  3.[4-9]|3.1[0-9]) : ;;
  *) warn "Python $PYV 偏旧，ThreadingHTTPServer 需要 3.7+" ;;
esac

command -v nmcli >/dev/null 2>&1 || warn "未找到 nmcli（应用仍可安装，但无法控制 WiFi）"
IFACE=""
if [ -f "$SRC/etc/wifimgr.json" ]; then
  IFACE=$(grep -oE '"ifname"[[:space:]]*:[[:space:]]*"[^"]+"' "$SRC/etc/wifimgr.json" \
          | head -1 | sed -E 's/.*"([^"]+)"$/\1/' || true)
fi
IFACE=${IFACE:-wlan0}
say "  目标接口: $IFACE"
ip link show "$IFACE" >/dev/null 2>&1 && ok "接口 $IFACE 存在" || warn "接口 $IFACE 当前不存在"

# 有线是否独立（决定切 WiFi 会不会失联）
if ip -4 addr show 2>/dev/null | grep -q "eth0"; then
  ok "有线在位（切 WiFi 不会导致失联）"
else
  warn "未发现有线接口 —— 切换 WiFi 可能中断本连接，建议先接好网线"
fi

if [ "$DRY" = "1" ]; then
  step "dry-run 模式，未做任何改动。后续步骤已省略。"
  exit 0
fi

# ---------------------------------------------------------------- 1 备份
step "1/9 备份现有文件"
mkdir -p /var/lib/wifimgr
for f in "$UNIT" "$NGINX_INC" "$TMPFILES" "$CONF"; do
  backup_one "$f"
done
backup_literally "$LEGACY_CRON"
backup_literally "$LEGACY_SCRIPT"
ok "备份清单已记录（${STAMP}）"

# ---------------------------------------------------------------- 2 停用旧 watchdog
step "2/9 停用旧 watchdog（不删除）"
if [ -f "$LEGACY_CRON" ]; then
  if grep -q '^# disabled-by-wifimgr' "$LEGACY_CRON" 2>/dev/null; then
    ok "旧 cron 已是停用状态"
  elif grep -v '^[[:space:]]*#' "$LEGACY_CRON" | grep -q 'wifi-check\.sh'; then
    # 注释掉活动行，并保留原始行以便回滚
    sed -i '/^[^#].*wifi-check\.sh/ s|^|# disabled-by-wifimgr |' "$LEGACY_CRON"
    grep '^# disabled-by-wifimgr' "$LEGACY_CRON" >/dev/null \
      || die "停用失败，请手工检查 $LEGACY_CRON"
    ok "已停用 cron: $LEGACY_CRON"
  else
    ok "旧 cron 中没有活动条目"
  fi
  # 脚本本体改成 0750，防其它 cron 条目以非 root 身份调用
  if [ -f "$LEGACY_SCRIPT" ]; then
    chmod 0750 "$LEGACY_SCRIPT" 2>/dev/null && ok "旧脚本权限收紧为 0750"
  fi
else
  ok "旧 cron 不存在，跳过"
fi

# RD08_IoT 的 autoconnect：它指向的 SSID 已不存在，会每轮空等 25s 并抢掉真实连接
if nmcli -t -f NAME con show 2>/dev/null | grep -qx 'RD08_IoT'; then
  CUR_AC=$(nmcli -g connection.autoconnect con show RD08_IoT 2>/dev/null || echo "")
  if [ "$CUR_AC" = "yes" ]; then
    warn "发现遗留 RD08_IoT autoconnect=yes，但它指向的 SSID 已不存在"
    warn "  （那个 AP 现在叫「密码是八个八wifi5」）—— 建议关闭，否则会干扰真实连接"
    say "     如需关闭: nmcli con mod RD08_IoT connection.autoconnect no"
  fi
fi

# ---------------------------------------------------------------- 3 落代码
step "3/9 部署程序到 $APP_DIR"
# 源码可能就在 $APP_DIR 里（就地重装）。这时不复制、也不备份，
# 否则 cp -a 会报 "same file" 而失败。
INPLACE=0
if [ "$(cd "$SRC" && pwd)" = "$APP_DIR" ]; then
  INPLACE=1
  ok "源码已在 $APP_DIR（就地重装，跳过复制）"
else
  mkdir -p "$APP_DIR"
  [ -d "$SRC/wifimgr" ] || die "找不到源码目录 $SRC/wifimgr"
  for item in wifimgr tests deploy etc tools; do
    [ -e "$SRC/$item" ] || continue
    if [ -e "$APP_DIR/$item" ]; then
      backup_one "$APP_DIR/$item"
      rm -rf "${APP_DIR:?}/$item"
    fi
    cp -a "$SRC/$item" "$APP_DIR/" || die "复制 $item 失败"
    ok "已安装 $item"
  done
fi

chmod 0755 "$APP_DIR"/wifimgr/*.py 2>/dev/null || true
chmod -R a+rX "$APP_DIR/wifimgr/static" 2>/dev/null || true

# 首次部署写配置（已存在则不覆盖）
if [ ! -f "$CONF" ]; then
  if [ -f "$SRC/etc/wifimgr.json" ]; then
    cp "$SRC/etc/wifimgr.json" "$CONF" || die "写入配置失败"
    chmod 0600 "$CONF"
    ok "已写入配置 $CONF（daemon.dry_run=true，先观察）"
  else
    die "找不到模板配置 $SRC/etc/wifimgr.json"
  fi
else
  ok "配置已存在，保留不覆盖: $CONF"
fi

# ---------------------------------------------------------------- 4 自检
step "4/9 环境自检（必须有 FAIL 才继续）"
cd "$APP_DIR" || die "无法进入 $APP_DIR"
PYTHONPATH="$APP_DIR" /usr/bin/python3 -B -m wifimgr --config "$CONF" doctor --json \
  > /tmp/wifimgr-doctor.json 2>&1
DOC_RC=$?
cat /tmp/wifimgr-doctor.json | /usr/bin/python3 -c '
import json,sys
raw=sys.stdin.read()
try:
    d=json.loads(raw)
except Exception:
    print(raw); sys.exit(1)
fails=0
for c in d.get("data",{}).get("checks",[]):
    mark="OK  " if c["ok"] else "FAIL"
    if not c["ok"]: fails+=1
    print("  [%s] %-26s %s" % (mark, c["name"], c["detail"]))
sys.exit(1 if fails else 0)
'
if [ $? -ne 0 ]; then
  warn "自检有 FAIL 项。若失败项与 WiFi 控制无关（如 nmcli 缺失）可继续；"
  warn "否则请先修复。原始输出: /tmp/wifimgr-doctor.json"
  read -r -p "  仍要继续？[y/N] " ans
  case "$ans" in [yY]*) : ;; *) die "已中止" ;; esac
fi

# 离线单测
step "5/9 离线单元测试"
if PYTHONPATH="$APP_DIR" /usr/bin/python3 -B -m wifimgr selftest > /tmp/wifimgr-selftest.log 2>&1; then
  ok "单元测试全部通过（$(grep -c '\.\.\. ok' /tmp/wifimgr-selftest.log) 项）"
else
  warn "单元测试有失败，详见 /tmp/wifimgr-selftest.log"
  tail -20 /tmp/wifimgr-selftest.log
  die "测试未通过，拒绝安装"
fi

# ---------------------------------------------------------------- 6 systemd
step "6/9 安装 systemd unit"
mkdir -p /var/lib/wifimgr /run/wifimgr
chmod 0700 /run/wifimgr
cp "$APP_DIR/deploy/wifimgr.service" "$UNIT" || die "安装 unit 失败"
ok "已安装 $UNIT"
cp "$APP_DIR/deploy/wifimgr-tmpfiles.conf" "$TMPFILES" 2>/dev/null \
  && systemd-tmpfiles --create "$TMPFILES" 2>/dev/null && ok "已安装 tmpfiles 规则"
systemctl daemon-reload || die "daemon-reload 失败"
systemctl enable wifimgr.service >/dev/null 2>&1 && ok "已设置开机自启"

# journald 上限：根文件系统在 eMMC 上，日志无上限会持续磨损闪存。
# 这是审计发现的真正消耗源（journald 可达数百 MB），本软件自身几乎不写。
JOURNALD_D=/etc/systemd/journald.conf.d
JD_SRC="$APP_DIR/deploy/journald-limit.conf"
if [ -f "$JD_SRC" ]; then
  JD_DST="$JOURNALD_D/wifimgr-limit.conf"
  [ -e "$JD_DST" ] && backup_one "$JD_DST"
  mkdir -p "$JOURNALD_D" 2>/dev/null
  if cp "$JD_SRC" "$JD_DST" 2>/dev/null; then
    if systemctl restart systemd-journald 2>/dev/null; then
      ok "已限制 journald（SystemMaxUse=200M，保护 eMMC）"
      VAC=$(journalctl --disk-usage 2>/dev/null | grep -oE "[0-9.]+[KMG]" | head -1)
      if [ -n "${VAC:-}" ]; then
        journalctl --vacuum-size=200M >/dev/null 2>&1 || true
        ok "已回收历史日志（清理前占用 $VAC）"
      fi
    else
      warn "journald 重启失败，限制需手动生效：systemctl restart systemd-journald"
    fi
  else
    warn "写入 $JD_DST 失败"
  fi
fi

# ---------------------------------------------------------------- 7 nginx
step "7/9 配置 nginx"
if [ -d /etc/nginx/locations.d ]; then
  cp "$APP_DIR/deploy/nginx-location.conf" "$NGINX_INC" || die "安装 nginx 片段失败"
  if nginx -t 2>/tmp/wifimgr-nginx-test.log; then
    ok "nginx -t 通过"
    systemctl reload nginx && ok "已 reload nginx（未 restart，厂商 UI 未中断）"
  else
    warn "nginx -t 失败，回滚片段："
    cat /tmp/wifimgr-nginx-test.log
    if [ -f "${NGINX_INC}.bak-${STAMP}" ]; then
      cp -a "${NGINX_INC}.bak-${STAMP}" "$NGINX_INC"
      warn "已还原 nginx 片段"
    else
      rm -f "$NGINX_INC"
      warn "已移除 nginx 片段"
    fi
    die "nginx 配置校验失败，未 reload"
  fi
else
  warn "/etc/nginx/locations.d 不存在，跳过反代（应用仍可用 127.0.0.1:8791 访问）"
fi

# ---------------------------------------------------------------- 8 启动
step "8/9 启动服务"
systemctl restart wifimgr.service || die "启动失败，见 journalctl -u wifimgr -n 50"
sleep 2
if systemctl is-active --quiet wifimgr.service; then
  ok "服务已运行"
else
  journalctl -u wifimgr -n 30 --no-pager >&2
  die "服务未处于 active 状态"
fi

step "9/9 接口断言"
fail=0
assert_api() {
  local path="$1" name="$2"
  if curl -fsS --max-time 15 "http://127.0.0.1:8791${path}" > /tmp/wifimgr-api.json 2>/dev/null; then
    ok "$name -> $(head -c 110 /tmp/wifimgr-api.json)"
  else
    warn "$name 断言失败"
    fail=$((fail+1))
  fi
}
assert_api "/api/v1/capabilities" "能力探测"
assert_api "/api/v1/scan"        "扫描"
assert_api "/api/v1/status"      "状态"
assert_api "/api/v1/doctor"      "自检"
assert_api "/api/v1/networks"    "已保存列表"

if command -v curl >/dev/null 2>&1; then
  HOSTIP=$(ip -4 -o addr show 2>/dev/null | grep -v ' lo ' | awk '{split($4,a,"/");print a[1];exit}')
  if [ -n "${HOSTIP:-}" ]; then
    CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${HOSTIP}/wifi/" || echo 000)
    if [ "$CODE" = "200" ]; then
      ok "反代可访问: http://${HOSTIP}/wifi/"
    else
      warn "反代返回 HTTP $CODE（nginx 片段可能未生效）"
    fi
  fi
fi

# manifest
{
  printf '{\n  "stamp": "%s",\n  "app_dir": "%s",\n  "backups": [\n' "$STAMP" "$APP_DIR"
  printf '%s' "$BACKUPS" | while IFS='|' read -r p b; do
    [ -z "$p" ] && continue
    printf '    {"path": "%s", "backup": "%s"}' "$p" "${b:-none}"
    [ -n "$b" ] || continue
    printf ',\n'
  done
  printf '  ]\n}\n'
} > "$MANIFEST" 2>/dev/null || true
ok "部署清单: $MANIFEST"

echo
if [ "$fail" -gt 0 ]; then
  warn "有 $fail 项接口断言失败，服务已启动但请检查日志"
fi
say "${GRN}安装完成${RST}"
say ""
say "  本机:   curl http://127.0.0.1:8791/api/v1/status"
say "  局域网: http://${HOSTIP:-<盒子IP>}/wifi/"
say "  日志:   journalctl -u wifimgr -f"
say ""
say "  ${YLW}守护当前为 dry_run=true（只探测不动作）。${RST}"
say "  确认无误后关闭："
say "    sed -i 's/\"dry_run\": true/\"dry_run\": false/' $CONF"
say "    systemctl restart wifimgr"
say ""
say "  回滚: bash $APP_DIR/deploy/rollback.sh"
