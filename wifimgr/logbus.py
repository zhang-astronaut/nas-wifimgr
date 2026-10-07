"""日志：同时写 syslog（等价 ``logger -t wifimgr``）与内存环形缓冲。

事件双写的原因：
  * syslog/journald 持久留存，事后 ``journalctl -u wifimgr`` 可查
  * 内存环形缓冲让 UI 能直接显示最近事件，不必反查日志文件
"""

import sys
import threading
import time
from collections import deque

LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}


class LogBus(object):
    def __init__(self, ident="wifimgr", buffer_size=500, level="info", store=None, use_syslog=True):
        self.ident = ident
        self.level = LEVELS.get((level or "info").lower(), 20)
        self._buffer = deque(maxlen=max(10, int(buffer_size)))
        self._lock = threading.Lock()
        self._seq = 0
        self._store = store
        self._syslog = None
        if use_syslog:
            try:
                import syslog

                syslog.openlog(ident, syslog.LOG_PID, syslog.LOG_DAEMON)
                self._syslog = syslog
            except Exception:
                self._syslog = None

    def set_level(self, level):
        self.level = LEVELS.get((level or "info").lower(), 20)

    def _next_seq(self):
        with self._lock:
            self._seq += 1
            return self._seq

    def log(self, level, source, code, message, data=None):
        """记录一条事件。``data`` 会经脱敏，绝不会把密码写进日志。"""
        from .errors import redact

        lvl = (level or "info").lower()
        if LEVELS.get(lvl, 20) < self.level:
            return None
        ev = {
            "id": self._next_seq(),
            "ts": time.time(),
            "level": lvl,
            "source": source,
            "code": code,
            "message": str(message),
            "data": redact(data) if data else {},
        }
        with self._lock:
            self._buffer.append(ev)
        line = "[%s] %s: %s" % (ev["source"], ev["code"], ev["message"])
        if ev["data"]:
            line += " %s" % (_compact(ev["data"]),)
        # 写 syslog
        if self._syslog is not None:
            try:
                prio = {
                    "debug": self._syslog.LOG_DEBUG,
                    "info": self._syslog.LOG_INFO,
                    "warn": self._syslog.LOG_WARNING,
                    "error": self._syslog.LOG_ERR,
                }.get(lvl, self._syslog.LOG_INFO)
                self._syslog.syslog(prio, line)
            except Exception:
                pass
        # 落库（失败只记一次，避免磁盘故障时日志风暴）
        if self._store is not None:
            try:
                self._store.add_event(ev)
            except Exception as exc:
                if not getattr(self, "_db_warned", False):
                    self._db_warned = True
                    sys.stderr.write("wifimgr: event persist failed once: %s\n" % (exc,))
        return ev

    def debug(self, source, code, message, data=None):
        return self.log("debug", source, code, message, data)

    def info(self, source, code, message, data=None):
        return self.log("info", source, code, message, data)

    def warn(self, source, code, message, data=None):
        return self.log("warn", source, code, message, data)

    def error(self, source, code, message, data=None):
        return self.log("error", source, code, message, data)

    def recent(self, since=0, limit=100, level=None):
        """按 id 增量拉取。id 单调递增，可安全用作游标。"""
        with self._lock:
            items = [e for e in self._buffer if e["id"] > since]
        if level:
            minlvl = LEVELS.get(level.lower(), 0)
            items = [e for e in items if LEVELS.get(e["level"], 20) >= minlvl]
        items.sort(key=lambda e: e["id"])
        if limit and len(items) > limit:
            items = items[-limit:]
        return items

    def flush(self):
        if self._syslog is not None:
            try:
                self._syslog.closelog()
            except Exception:
                pass


def _compact(data):
    try:
        import json

        return json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)
    except Exception:
        return str(data)
