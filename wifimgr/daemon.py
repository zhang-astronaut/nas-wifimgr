"""守护线程：替代原``wifi-check.sh``。

整合了旧脚本的职责（断线后重连、循环检测），并补上旧脚本没有的东西：

* **指数退避 + 抖动**：旧脚本每分钟无脑重试，会在 AP 拒绝后持续刷屏。
* **settle 宽限期**：NM 处于 activating/deactivating 时一律不插手。
  ``nmcli con up`` 在慢 AP 上可阻塞 30–45s，抢进去会打断进行中的四次握手。
  **宁可少修一次，也不要把连接搞坏。**
* **抖动检测**：滑动窗口内断连超阈值就暂停自动重连，防止把 AP 刷死。
* **flock 独占**：防与遗留脚本同时操作 wlan0。
* **dry_run**：只探测不动作。首次部署建议先开 10 分钟。
"""

import random
import threading
import time
from collections import deque

try:
    import fcntl
except ImportError:  # Windows（仅开发机）
    fcntl = None


def backoff_delay(attempt, base_sec, factor, cap_sec, jitter, rng=None):
    """第 ``attempt`` 次重试该等多久。

    ``attempt`` 从 1 起。``jitter`` 是 ±比例，用来避免多实例同步重试。
    """
    if attempt < 1:
        attempt = 1
    r = rng or random
    raw = min(base_sec * (factor ** (attempt - 1)), float(cap_sec))
    if jitter <= 0:
        return float(raw)
    lo = raw * (1.0 - jitter)
    hi = raw * (1.0 + jitter)
    return round(r.uniform(lo, hi), 1)


class Guardian(object):
    """后台守护。用 ``start()`` / ``stop()`` 控制，``run_once()`` 可单步测试。"""

    def __init__(self, cfg, backend, store, log, clock=None, rng=None):
        self.cfg = cfg
        self.backend = backend
        self.store = store
        self.log = log
        self._clock = clock or time.time
        self._rng = rng or random.Random()
        self._stop = threading.Event()
        self._thread = None
        self._lockfile = None

        d = self.dcfg()
        self._interval = int(d.get("interval_sec") or 60)
        self._max_retries = int(d.get("max_retries") or 0)
        bo = d.get("backoff") or {}
        self._bo_base = float(bo.get("base_sec") or 5)
        self._bo_factor = float(bo.get("factor") or 2.0)
        self._bo_cap = float(bo.get("cap_sec") or 300)
        self._bo_jitter = float(bo.get("jitter") or 0.2)
        self._settle_grace = int(d.get("settle_grace_sec") or 20)
        self._stable_cycles = int(d.get("stable_cycles_to_reset") or 2)
        self._flap_window = int(d.get("flap_window_sec") or 900)
        self._flap_threshold = int(d.get("flap_threshold") or 4)
        self._flap_pause = int(d.get("flap_pause_sec") or 600)
        self._active_profile = d.get("active_profile") or ""
        self._fallback_profile = d.get("fallback_profile") or ""
        self._dry_run = bool(d.get("dry_run"))
        self._lockpath = d.get("lockfile") or "/run/wifimgr-daemon.lock"

        # 运行时状态（供 /api/v1/daemon 展示）
        self.cycles = 0
        self.last_check_at = None
        self.last_ok_at = None
        self.last_action_at = None
        self.consecutive_failures = 0
        self.running = False
        self.flapping = False
        self._flap_events = deque()

    def dcfg(self):
        return (self.cfg.get("daemon", {}) or {}) if self.cfg else {}

    # ---------- 生命周期 ----------
    def start(self):
        if self._thread is not None:
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="wifimgr-guardian", daemon=True)
        self._thread.start()
        return True

    def stop(self, timeout=5.0):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        self._release_lock()
        self.running = False
        return True

    def _acquire_lock(self):
        """flock 独占。拿不到就说明已有实例在跑，正常退出而非报错。"""
        if fcntl is None:
            return True  # 开发机（Windows）
        try:
            self._lockfile = open(self._lockpath, "a+")
            fcntl.flock(self._lockfile.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lockfile.seek(0)
            self._lockfile.truncate()
            self._lockfile.write("%d\n" % int(self._clock()))
            self._lockfile.flush()
            return True
        except (IOError, OSError) as exc:
            self.log.warn(
                "daemon",
                "lock.busy",
                "另一个守护实例已持有锁，本实例退出",
                {"lockfile": self._lockpath, "err": str(exc)},
            )
            if self._lockfile is not None:
                try:
                    self._lockfile.close()
                except Exception:
                    pass
                self._lockfile = None
            return False

    def _release_lock(self):
        if self._lockfile is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(self._lockfile.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            self._lockfile.close()
        except Exception:
            pass
        self._lockfile = None

    # ---------- 主循环 ----------
    def _loop(self):
        if not self._acquire_lock():
            return
        self.running = True
        self.log.info("daemon", "start", "守护线程启动", {
            "interval_sec": self._interval,
            "max_retries": self._max_retries,
            "dry_run": self._dry_run,
            "active_profile": self._active_profile or "(自动)",
        })
        retry = 0
        consecutive_ok = 0
        try:
            while not self._stop.is_set():
                try:
                    retry, consecutive_ok = self._cycle(retry, consecutive_ok)
                except Exception as exc:  # 单轮异常不能拖垮整个守护
                    self.log.error("daemon", "cycle.error", "守护循环异常", {"err": str(exc)})
                    retry += 1
                    wait = backoff_delay(
                        retry, self._bo_base, self._bo_factor, self._bo_cap, self._bo_jitter, self._rng
                    )
                    self._stop.wait(wait)
        finally:
            self.log.info("daemon", "stop", "守护线程退出")
            self.running = False
            self._release_lock()

    def _cycle(self, retry, consecutive_ok):
        """跑一轮检测。返回 ``(retry, consecutive_ok)``。"""
        self.cycles += 1
        self.last_check_at = self._clock()

        # settle 宽限期：NM 自己正在动就不插手
        try:
            if self.backend.is_busy_activating():
                self.log.debug("daemon", "settle", "NM 正在激活/断开，等待下一轮")
                self._stop.wait(2.0)
                return retry, consecutive_ok
        except Exception:
            pass

        # 上次动作后的宽限期
        if self.last_action_at and (self._clock() - self.last_action_at) < self._settle_grace:
            self._stop.wait(2.0)
            return retry, consecutive_ok

        st = self.backend.status()
        if st.connected and st.source != "ip_route":
            consecutive_ok += 1
            self.consecutive_failures = 0
            if consecutive_ok >= self._stable_cycles:
                retry = 0
                self._flap_events.clear()
                self.flapping = False
            self.last_ok_at = self._clock()
            self.log.debug("daemon", "ok", "已连接 %s" % (st.ssid or st.profile_name), {
                "ip": st.ip, "source": st.source,
            })
            self._stop.wait(self._interval)
            return retry, consecutive_ok

        # --- 未连接 ---
        consecutive_ok = 0
        self.consecutive_failures += 1
        self._flap_events.append(self._clock())
        while self._flap_events and (self._clock() - self._flap_events[0]) > self._flap_window:
            self._flap_events.popleft()

        if len(self._flap_events) > self._flap_threshold and not self.flapping:
            self.flapping = True
            self.log.warn(
                "daemon",
                "flapping",
                "疑似 WiFi 抖动（%d 秒内断连 %d 次），暂停自动重连 %d 秒"
                % (self._flap_window, len(self._flap_events), self._flap_pause),
            )
            self._stop.wait(self._flap_pause)
            self._flap_events.clear()
            self.flapping = False
            return retry, consecutive_ok

        if self._max_retries and retry >= self._max_retries:
            self.log.warn(
                "daemon",
                "exhausted",
                "已重试 %d 次仍失败，本轮暂停至下个检测周期" % retry,
            )
            self._stop.wait(self._interval * 5)
            return retry, consecutive_ok

        target = self._pick_profile(st)
        wait = backoff_delay(
            retry + 1, self._bo_base, self._bo_factor, self._bo_cap, self._bo_jitter, self._rng
        )
        self.log.warn(
            "daemon",
            "retry",
            "未连接，第 %d 次重连（目标 %s），退避 %.1fs 后执行"
            % (retry + 1, target or "(自动)", wait),
            {"state": st.state, "source": st.source},
        )

        if self._dry_run:
            self.log.info("daemon", "dryrun", "dry_run 开启，仅探测不动作", {"target": target})
            self._stop.wait(wait)
            return retry + 1, consecutive_ok

        self.last_action_at = self._clock()
        ok = self._reconnect(target)
        if ok:
            retry = 0
            self.log.info("daemon", "recovered", "重连成功")
            self._stop.wait(self._interval)
            return retry, consecutive_ok
        self._stop.wait(wait)
        return retry + 1, consecutive_ok

    def _pick_profile(self, st=None):
        """决定重连哪个 profile。

        显式 ``active_profile`` 优先；为空时用当前活跃的；再退到 fallback。
        故意**不**自动挑信号最好的已存网络 —— 盲目切换到另一个 AP 可能
        把本来能恢复的连接换到更差的链路上。
        """
        if self._active_profile:
            return self._active_profile
        if st is not None and st.profile_name:
            return st.profile_name
        return self._fallback_profile or ""

    def _reconnect(self, profile_name):
        if not profile_name:
            self.log.warn("daemon", "no.profile", "没有可用的 profile 可重连")
            return False
        try:
            res = self.backend.activate_profile(profile_name)
        except Exception as exc:
            self.log.error("daemon", "reconnect.error", "重连异常", {"err": str(exc)})
            return False
        if res.ok:
            if self.store is not None:
                try:
                    self.store.record_connect_result(profile_name, True, res.phase)
                except Exception:
                    pass
            return True
        self.log.warn("daemon", "reconnect.failed", "重连失败：%s" % res.message, {
            "profile": profile_name, "phase": res.phase,
        })
        if self.store is not None:
            try:
                self.store.add_attempt(
                    ssid="", bssid="", profile_name=profile_name,
                    requested=None, used=None, phase=res.phase,
                    error_code=None, duration_ms=res.duration_ms,
                )
                self.store.record_connect_result(profile_name, False, res.phase)
            except Exception:
                pass
        return False

    # ---------- 供 API 展示 ----------
    def status(self):
        nxt = None
        if self.last_check_at:
            nxt = max(0, int(self._interval - (self._clock() - self.last_check_at)))
        return {
            "running": self.running,
            "pid": threading.get_ident() if self.running else None,
            "lock_held": self._lockfile is not None,
            "cycles": self.cycles,
            "last_check_at": self.last_check_at,
            "last_ok_at": self.last_ok_at,
            "last_action_at": self.last_action_at,
            "consecutive_failures": self.consecutive_failures,
            "flapping": self.flapping,
            "flap_events": len(self._flap_events),
            "next_check_in": nxt,
        }

    def config(self):
        d = self.dcfg()
        return {
            "enabled": bool(d.get("enabled")),
            "interval_sec": int(d.get("interval_sec") or 60),
            "max_retries": int(d.get("max_retries") or 0),
            "backoff": dict(d.get("backoff") or {}),
            "settle_grace_sec": int(d.get("settle_grace_sec") or 20),
            "stable_cycles_to_reset": int(d.get("stable_cycles_to_reset") or 2),
            "flap_window_sec": int(d.get("flap_window_sec") or 900),
            "flap_threshold": int(d.get("flap_threshold") or 4),
            "flap_pause_sec": int(d.get("flap_pause_sec") or 600),
            "active_profile": d.get("active_profile") or "",
            "fallback_profile": d.get("fallback_profile") or "",
            "dry_run": bool(d.get("dry_run")),
        }

    def apply_config(self, new_daemon_cfg, persist=None):
        """应用新配置（UI 保存）。校验失败抛异常，不做部分更新。"""
        from . import config as cfgmod

        merged = cfgmod.deep_merge(self.dcfg(), new_daemon_cfg or {})
        probe = cfgmod.deep_merge(self.cfg, {"daemon": merged})
        cfgmod.validate(probe)  # 范围不合法直接抛
        self.cfg["daemon"] = merged
        # 重读派生字段
        self._interval = int(merged.get("interval_sec") or 60)
        self._max_retries = int(merged.get("max_retries") or 0)
        bo = merged.get("backoff") or {}
        self._bo_base = float(bo.get("base_sec") or 5)
        self._bo_factor = float(bo.get("factor") or 2.0)
        self._bo_cap = float(bo.get("cap_sec") or 300)
        self._bo_jitter = float(bo.get("jitter") or 0.2)
        self._settle_grace = int(merged.get("settle_grace_sec") or 20)
        self._stable_cycles = int(merged.get("stable_cycles_to_reset") or 2)
        self._flap_window = int(merged.get("flap_window_sec") or 900)
        self._flap_threshold = int(merged.get("flap_threshold") or 4)
        self._flap_pause = int(merged.get("flap_pause_sec") or 600)
        self._active_profile = merged.get("active_profile") or ""
        self._fallback_profile = merged.get("fallback_profile") or ""
        self._dry_run = bool(merged.get("dry_run"))
        if persist is not None:
            persist(self.cfg)
        return self.config()

    # ---------- 单步（测试与 CLI 用） ----------
    def run_once(self):
        """跑一轮并返回 ``(ok, attempted, detail)``。

        * ``ok`` —— 本轮结束后是否处于已连接状态
        * ``attempted`` —— 本轮**是否真的调用了重连**（dry_run / 无目标 / 退避未到
          都会是 False。这个值必须是明确的，否则测试只能靠间接信号断言）
        * ``detail`` —— 诊断信息
        """
        st = self.backend.status()
        if st.connected:
            return True, False, {"reason": "already_connected", "ssid": st.ssid}
        target = self._pick_profile(st)
        if self._dry_run:
            return False, False, {"reason": "dry_run", "target": target}
        if not target:
            return False, False, {"reason": "no_profile"}
        ok = self._reconnect(target)
        return ok, True, {"reason": "reconnect", "target": target, "ok": ok}
