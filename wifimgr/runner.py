"""子进程调用封装 + 全局操作锁。

两个关键点：

1. **绝不走 shell。** ``Popen(list)`` 列表形式，密码永远不进 shell
   解析器；``shell=True`` 在任何情况下都不使用。
2. **超时后杀整个进程组。** nmcli 可能挂在 D-Bus 上，用 ``start_new_session=True``
   建独立进程组，超时时 ``os.killpg`` 才能连它的子进程一起收掉。
"""

import os
import shutil
import signal
import subprocess
import threading
import time

DEFAULT_TIMEOUT = 15
SCAN_TIMEOUT = 20
CONNECT_TIMEOUT = 60

# 显式候选路径：cron 环境 PATH 很精简，只靠 which 会找不到。
NMCLI_CANDIDATES = ("/usr/bin/nmcli", "/bin/nmcli", "nmcli")
IW_CANDIDATES = ("/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw", "iw")
IP_CANDIDATES = ("/sbin/ip", "/usr/sbin/ip", "/bin/ip", "ip")


def which(name, candidates=None):
    """定位可执行文件。显式候选优先，避免 PATH 过于精简。"""
    cands = candidates or (name,)
    for c in cands:
        if os.path.isabs(c):
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        else:
            found = shutil.which(c)
            if found:
                return found
    return None


class CommandResult(object):
    __slots__ = ("argv", "rc", "stdout", "stderr", "elapsed_ms", "timed_out")

    def __init__(self, argv, rc, stdout, stderr, elapsed_ms, timed_out=False):
        self.argv = list(argv)
        self.rc = rc
        self.stdout = stdout or ""
        self.stderr = stderr or ""
        self.elapsed_ms = int(elapsed_ms or 0)
        self.timed_out = bool(timed_out)

    @property
    def ok(self):
        return self.rc == 0 and not self.timed_out

    def to_dict(self, secrets=()):
        from .errors import redact_text

        return {
            "argv": list(self.argv),
            "rc": self.rc,
            "stdout": redact_text(self.stdout, secrets),
            "stderr": redact_text(self.stderr, secrets),
            "elapsed_ms": self.elapsed_ms,
            "timed_out": self.timed_out,
        }

    def __repr__(self):
        return "<CommandResult rc=%s timeout=%s %.0fms %r>" % (
            self.rc,
            self.timed_out,
            self.elapsed_ms,
            self.argv[:3],
        )


def _killpg(proc):
    """超时收尾：先 TERM 整个进程组，再 KILL 兜底。"""
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        pgid = None
    for sig, wait in ((signal.SIGTERM, 2.0), (signal.SIGKILL, 1.0)):
        if proc.poll() is not None:
            return
        try:
            if pgid is not None:
                os.killpg(pgid, sig)
            else:
                proc.send_signal(sig)
        except OSError:
            return
        deadline = time.time() + wait
        while time.time() < deadline:
            if proc.poll() is not None:
                return
            time.sleep(0.05)


def run(argv, timeout=DEFAULT_TIMEOUT, input_text=None, env=None):
    """执行命令并返回 :class:`CommandResult`。

    ``argv`` 必须是列表。**不要**在调用前把密码拼进 argv —— 见 ``nmkey`` 模块。
    """
    argv = [str(a) for a in argv]
    started = time.time()
    full_env = None
    if env:
        full_env = dict(os.environ)
        full_env.update(env)

    proc = None
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL if input_text is None else subprocess.PIPE,
            shell=False,
            start_new_session=True,
            env=full_env,
        )
    except (OSError, ValueError) as exc:
        elapsed = int((time.time() - started) * 1000)
        return CommandResult(argv, -1, "", "执行失败: %s" % (exc,), elapsed)

    try:
        raw_out, raw_err = proc.communicate(
            input=(input_text.encode("utf-8") if input_text is not None else None),
            timeout=timeout,
        )
        elapsed = int((time.time() - started) * 1000)
        return CommandResult(
            argv,
            proc.returncode,
            _dec(raw_out),
            _dec(raw_err),
            elapsed,
        )
    except subprocess.TimeoutExpired:
        _killpg(proc)
        try:
            raw_out, raw_err = proc.communicate(timeout=2)
        except Exception:
            raw_out, raw_err = b"", b""
        elapsed = int((time.time() - started) * 1000)
        return CommandResult(argv, None, _dec(raw_out), _dec(raw_err), elapsed, timed_out=True)
    finally:
        if proc.poll() is None:
            _killpg(proc)


def _dec(raw):
    if not raw:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return raw


class BusyLock(object):
    """带超时的可重入保护锁。

    所有 nmcli **写**操作（scan/connect/load/reload）必须持锁；状态读不持锁。
    nmcli 内部对 D-Bus 的序列化很差，并发调用极易互相打断。
    """

    def __init__(self, timeout=5.0):
        self._lock = threading.Lock()
        self.timeout = timeout
        self._held_by = None
        self._depth = 0

    def acquire(self, timeout=None):
        t = self.timeout if timeout is None else timeout
        me = threading.get_ident()
        if self._depth and self._held_by == me:
            self._depth += 1
            return True
        ok = self._lock.acquire(timeout=t)
        if not ok:
            return False
        self._held_by = me
        self._depth = 1
        return True

    def release(self):
        if self._depth > 1:
            self._depth -= 1
            return
        self._depth = 0
        self._held_by = None
        try:
            self._lock.release()
        except RuntimeError:
            pass

    def is_held(self):
        return self._depth > 0

    def __enter__(self):
        if not self.acquire():
            from .errors import BusyError

            raise BusyError(retry_after=3)
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()
        return False
