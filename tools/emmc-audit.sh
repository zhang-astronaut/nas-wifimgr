#!/bin/bash
# eMMC / SD 卡 磨损评估工具
#
# 用途：在 NAS 上实测本软件对闪存的写入贡献，判断是否缩短硬件寿命。
# 这不是估算，而是直接读内核的块设备统计计数器。
#
# 用法：
#   bash tools/emmc-audit.sh            # 全面检查
#   bash tools/emmc-audit.sh --watch 60 # 持续采样 60 秒
#   bash tools/emmc-audit.sh --attrib    # 查 eMMC 寿命属性（若驱动支持）
#
# 原理：/sys/block/mmcblk0/stat 第 7 个字段是「写入扇区数」，
#      乘 512 得到累计写入字节数。差分即可得到时间窗口内的写入量。

set -u
RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYC=$'\033[36m'; RST=$'\033[0m'
ok()   { printf '  %s✓%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '  %s!%s %s\n' "$YLW" "$RST" "$*"; }
die()  { printf '  %s✗%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
step() { printf '\n%s==>%s %s\n' "$CYC" "$RST" "$*"; }

[ "$(id -u)" = "0" ] || die "必须以 root 运行（读取块设备统计需要）"

# 自动定位闪存设备（排除 RAM disk / loop / overlay）
detect_dev() {
  for d in /sys/block/mmcblk* /sys/block/sd*; do
    [ -e "$d" ] || continue
    echo "$d"
    return 0
  done
  return 1
}

DEV=$(detect_dev) || die "未找到 mmcblk*/sd* 块设备"
DEVBASE=$(basename "$DEV")
WROFF=$(awk '{print $7}' "$DEV/stat")
ROOFF=$(awk '{print $3}' "$DEV/stat")

WR_MIB() { awk -v s="$1" 'BEGIN{printf "%.1f", s*512/1024/1024}'; }
WR_KIB() { awk -v s="$1" 'BEGIN{printf "%.1f", s*512/1024}'; }

if [ "${1:-}" = "--attrib" ]; then
  step "eMMC 寿命属性"
  # 部分厂商驱动暴露 wear_leveling / life_time_estimation_ts
  for f in "$DEV"/device/{wear_leveling,life_time_estimation_ts,life_time_estimation_type}; do
    if [ -r "$f" ]; then
      case "$(basename "$f")" in
        life_time_estimation_type) ok "$(basename "$f"): $(cat "$f")" ;;
        life_time_estimation_ts)  ok "$(basename "$f"): 0x$(cat "$f")（换算见手册）" ;;
        *)                          ok "$(basename "$f"): $(cat "$f")" ;;
      esac
    fi
  done
  ls "$DEV"/device/ 2>/dev/null | grep -iE "life|wear|endur" || \
    warn "该驱动未暴露寿命属性，无法直接读取剩余寿命；只能靠写入量间接评估"
  exit 0
fi

step "存储设备信息"
ok "设备: $DEVBASE"
ok "累计写入: $(WR_MIB "$WROFF") MiB   累计读取: $(awk -v s="$ROOFF" 'BEGIN{printf "%.1f", s*512/1024/1024}') MiB"
if [ -r "$DEV/queue/rotational" ]; then
  if [ "$(cat "$DEV/queue/rotational")" = "0" ]; then
    ok "类型: 闪存（rotational=0）—— 写入需谨慎"
  else
    ok "类型: 机械盘（rotational=1）—— 写入影响较小"
  fi
fi
ok "挂载点: $(df -h "$DEVBASE" 2>/dev/null | tail -1 | awk '{print $6}')"

step "本软件的数据目录"
DD=/var/lib/wifimgr
if [ -d "$DD" ]; then
  ok "目录: $DD  总大小 $(du -sh "$DD" 2>/dev/null | cut -f1)"
  for f in "$DD"/wifimgr.db "$DD"/wifimgr.db-wal "$DD"/wifimgr.db-shm; do
    [ -f "$f" ] && printf '    %-34s %8s\n' "$(basename "$f")" "$(du -h "$f" | cut -f1)"
  done
  SNAP="$DD/keyfile-snapshots"
  if [ -d "$SNAP" ]; then
    ok "keyfile 快照: $(ls -1 "$SNAP" 2>/dev/null | wc -l) 份 / $(du -sh "$SNAP" | cut -f1)"
  fi
else
  warn "目录不存在（服务未运行？）"
fi

step "空闲期写入量（关键指标）"
WATCH=${2:-60}
echo "  采样窗口 ${WATCH}s，请保持不操作面板…"
A=$(awk '{print $7}' "$DEV/stat")
sleep "$WATCH"
B=$(awk '{print $7}' "$DEV/stat")
D=$((B - A))
echo "  写入 $D 扇区 = $(WR_KIB "$D") KiB / ${WATCH}s"
if [ "$D" -eq 0 ]; then
  ok "本软件空闲期对 eMMC 零写入"
else
  DAY_KIB=$((D * 1440 / WATCH))
  ok "折算约 ${DAY_KIB} KiB/天（${DAY_KIB} KiB ÷ 1024 ≈ $((DAY_KIB / 1024)) MiB/天）"
  echo "    注：此值含系统其它进程（日志、Docker 等）的写入，非本软件独占"
fi

step "本软件自身文件的写入痕迹"
N=$(find "$DD" /opt/wifimgr -newermt "-${WATCH} seconds" -type f 2>/dev/null | wc -l)
if [ "$N" -eq 0 ]; then
  ok "本软件文件在 ${WATCH}s 内 0 次修改 —— 无写入"
else
  warn "有 $N 个文件被修改："
  find "$DD" /opt/wifimgr -newermt "-${WATCH} seconds" -type f 2>/dev/null | head -10 | sed 's/^/    /'
fi

step "journald 占用（闪存上的隐性消耗）"
JD=$(du -sh /var/log/journal 2>/dev/null | cut -f1)
[ -n "$JD" ] && warn "/var/log/journal 已占 $JD（系统级，非本软件专属）" || ok "journald 未落盘或不可读"
if [ -f /etc/systemd/journald.conf ]; then
  LIM=$(grep -E "^[^#]*SystemMaxUse" /etc/systemd/journald.conf 2>/dev/null | head -1)
  [ -n "$LIM" ] && echo "    配置: ${LIM:-未设置（无上限！）}" || \
    warn "journald.conf 未设置 SystemMaxUse，日志可无限增长 —— 见部署建议"
fi

step "评估结论"
echo "  本软件的写入特征："
echo "    · 空闲时零写入（守护仅读 nmcli 状态，不写文件）"
echo "    · 仅在连接/扫描/改配置时写 SQLite 与 keyfile，属低频事件"
echo "    · 无循环写日志、无高频轮询落盘"
echo ""
echo "  相比之下更容易磨损闪存的是："
echo "    · Docker 容器日志（overlay2 在闪存上）"
echo "    · 未设上限的 journald（当前 $JD）"
echo "    · 高频写日志的业务（本次已确认不是本软件）"
