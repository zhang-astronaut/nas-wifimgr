"""SQLite 持久化。

**硬约束：本库不存任何密码。** 密码只存在于 NetworkManager 的 keyfile
（``/etc/NetworkManager/system-connections/*.nmconnection``，0600 root）。
``saved_network`` 只记「我认识哪些网络」，``profile_ref.has_psk`` 只是布尔标记。
测试会断言 schema 里不出现 psk/password/passphrase 字样。

线程模型：``threading.local`` 每线程一个连接。**不用** ``check_same_thread=False``
—— 那只是关掉保护，多线程共用一个连接仍会串事务。
"""

import json
import os
import sqlite3
import threading
import time

# 表结构里禁止出现的列名片段（自检用，见 assert_no_secret_columns）
_FORBIDDEN = ("psk", "password", "passphrase", "secret")

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS saved_network (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_name    TEXT NOT NULL UNIQUE,
  uuid            TEXT,
  ssid            TEXT NOT NULL,
  bssid_lock      TEXT,
  security        TEXT NOT NULL DEFAULT 'unknown',
  key_mgmt        TEXT NOT NULL DEFAULT 'unknown',
  iface           TEXT NOT NULL DEFAULT 'wlan0',
  favorite        INTEGER NOT NULL DEFAULT 0,
  note            TEXT,
  connect_count   INTEGER NOT NULL DEFAULT 0,
  last_result     TEXT,
  last_try_at     INTEGER,
  last_ok_at      INTEGER,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_saved_ssid ON saved_network(ssid);

CREATE TABLE IF NOT EXISTS profile_ref (
  profile_name  TEXT PRIMARY KEY,
  uuid          TEXT,
  managed       INTEGER NOT NULL DEFAULT 1,
  key_mgmt      TEXT,
  has_psk       INTEGER NOT NULL DEFAULT 0,
  last_load_at  INTEGER,
  updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS connect_attempt (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ssid          TEXT,
  bssid         TEXT,
  profile_name  TEXT,
  requested     TEXT,
  used          TEXT,
  phase         TEXT NOT NULL,
  error_code    TEXT,
  duration_ms   INTEGER,
  at            INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempt_at ON connect_attempt(at DESC);

CREATE TABLE IF NOT EXISTS event (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      REAL NOT NULL,
  level   TEXT NOT NULL,
  source  TEXT NOT NULL,
  code    TEXT NOT NULL,
  message TEXT NOT NULL,
  data    TEXT
);
CREATE INDEX IF NOT EXISTS idx_event_ts ON event(ts DESC);

CREATE TABLE IF NOT EXISTS setting (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""

SCHEMA_VERSION = "1"


def assert_no_secret_columns(conn):
    """自检：确认表结构里没有任何密码类列名。"""
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    for t in tables:
        cur2 = conn.execute("PRAGMA table_info(%s)" % t)
        for row in cur2.fetchall():
            col = (row[1] or "").lower()
            for bad in _FORBIDDEN:
                # has_psk 是布尔标记，白名单放行
                if bad in col and col not in ("has_psk",):
                    raise AssertionError("表 %s 含疑似密码列: %s" % (t, row[1]))
    return True


class Store(object):
    def __init__(self, path, log=None):
        self.path = path
        self.log = log
        self._local = threading.local()
        self._all_conns = []
        self._all_lock = threading.Lock()
        directory = os.path.dirname(os.path.abspath(path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        self._init_schema()

    # ---------- 连接管理 ----------
    def conn(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=5.0)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA busy_timeout=5000")
            self._local.conn = c
            with self._all_lock:
                self._all_conns.append(c)
        return c

    def close_thread_conn(self):
        c = getattr(self._local, "conn", None)
        if c is not None:
            try:
                c.close()
            except Exception:
                pass
            self._local.conn = None
            with self._all_lock:
                if c in self._all_conns:
                    self._all_conns.remove(c)

    def close_all(self):
        with self._all_lock:
            for c in self._all_conns:
                try:
                    c.close()
                except Exception:
                    pass
            self._all_conns = []

    def _init_schema(self):
        c = self.conn()
        with c:
            c.executescript(SCHEMA)
            c.execute(
                "INSERT OR IGNORE INTO schema_meta(key,value) VALUES('schema_version',?)",
                (SCHEMA_VERSION,),
            )
            c.execute(
                "INSERT OR IGNORE INTO schema_meta(key,value) VALUES('created_at',?)",
                (str(int(time.time())),),
            )
        assert_no_secret_columns(c)

    # ---------- saved_network ----------
    def upsert_saved_network(
        self,
        profile_name,
        ssid,
        uuid=None,
        bssid_lock=None,
        security="unknown",
        key_mgmt="unknown",
        iface="wlan0",
        favorite=False,
        note=None,
    ):
        now = int(time.time())
        c = self.conn()
        with c:
            cur = c.execute("SELECT id FROM saved_network WHERE profile_name=?", (profile_name,))
            row = cur.fetchone()
            if row:
                c.execute(
                    """UPDATE saved_network
                       SET uuid=COALESCE(?,uuid), ssid=?, bssid_lock=?, security=?,
                           key_mgmt=?, iface=?, updated_at=?
                       WHERE profile_name=?""",
                    (uuid, ssid, bssid_lock, security, key_mgmt, iface, now, profile_name),
                )
                return row["id"]
            cur = c.execute(
                """INSERT INTO saved_network
                   (profile_name,uuid,ssid,bssid_lock,security,key_mgmt,iface,
                    favorite,note,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    profile_name,
                    uuid,
                    ssid,
                    bssid_lock,
                    security,
                    key_mgmt,
                    iface,
                    1 if favorite else 0,
                    note,
                    now,
                    now,
                ),
            )
            return cur.lastrowid

    def list_saved_networks(self):
        c = self.conn()
        cur = c.execute(
            "SELECT * FROM saved_network ORDER BY favorite DESC, connect_count DESC, ssid COLLATE NOCASE"
        )
        return [dict(r) for r in cur.fetchall()]

    def get_saved_network(self, profile_name):
        c = self.conn()
        cur = c.execute("SELECT * FROM saved_network WHERE profile_name=?", (profile_name,))
        row = cur.fetchone()
        return dict(row) if row else None

    def delete_saved_network(self, profile_name):
        c = self.conn()
        with c:
            cur = c.execute("DELETE FROM saved_network WHERE profile_name=?", (profile_name,))
            c.execute("DELETE FROM profile_ref WHERE profile_name=?", (profile_name,))
            return cur.rowcount > 0

    def set_favorite(self, profile_name, favorite):
        c = self.conn()
        with c:
            c.execute(
                "UPDATE saved_network SET favorite=?, updated_at=? WHERE profile_name=?",
                (1 if favorite else 0, int(time.time()), profile_name),
            )

    def record_connect_result(self, profile_name, ok, phase):
        now = int(time.time())
        c = self.conn()
        with c:
            c.execute(
                """UPDATE saved_network
                   SET connect_count = connect_count + 1,
                       last_result=?, last_try_at=?,
                       last_ok_at = CASE WHEN ?=1 THEN ? ELSE last_ok_at END,
                       updated_at=?
                   WHERE profile_name=?""",
                (phase, now, 1 if ok else 0, now, now, profile_name),
            )

    def count_saved(self):
        c = self.conn()
        return c.execute("SELECT COUNT(*) AS n FROM saved_network").fetchone()["n"]

    # ---------- profile_ref ----------
    def upsert_profile_ref(self, profile_name, uuid=None, managed=True, key_mgmt=None, has_psk=False):
        now = int(time.time())
        c = self.conn()
        with c:
            c.execute(
                """INSERT INTO profile_ref(profile_name,uuid,managed,key_mgmt,has_psk,last_load_at,updated_at)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(profile_name) DO UPDATE SET
                     uuid=COALESCE(excluded.uuid, uuid),
                     managed=excluded.managed,
                     key_mgmt=excluded.key_mgmt,
                     has_psk=excluded.has_psk,
                     last_load_at=excluded.last_load_at,
                     updated_at=excluded.updated_at""",
                (profile_name, uuid, 1 if managed else 0, key_mgmt, 1 if has_psk else 0, now, now),
            )

    def list_profile_refs(self):
        c = self.conn()
        return [dict(r) for r in c.execute("SELECT * FROM profile_ref").fetchall()]

    def get_profile_ref(self, profile_name):
        c = self.conn()
        cur = c.execute("SELECT * FROM profile_ref WHERE profile_name=?", (profile_name,))
        row = cur.fetchone()
        return dict(row) if row else None

    def is_managed(self, profile_name):
        ref = self.get_profile_ref(profile_name)
        return bool(ref and ref.get("managed"))

    # ---------- connect_attempt ----------
    def add_attempt(
        self,
        ssid,
        bssid,
        profile_name,
        requested,
        used,
        phase,
        error_code=None,
        duration_ms=0,
    ):
        c = self.conn()
        with c:
            c.execute(
                """INSERT INTO connect_attempt
                   (ssid,bssid,profile_name,requested,used,phase,error_code,duration_ms,at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    ssid,
                    bssid,
                    profile_name,
                    requested,
                    used,
                    phase,
                    error_code,
                    int(duration_ms or 0),
                    time.time(),
                ),
            )

    def list_attempts(self, limit=20):
        c = self.conn()
        cur = c.execute(
            "SELECT * FROM connect_attempt ORDER BY at DESC LIMIT ?", (int(limit),)
        )
        return [dict(r) for r in cur.fetchall()]

    def prune(self, retention_days=30, max_attempt_rows=2000):
        c = self.conn()
        with c:
            cutoff = time.time() - retention_days * 86400
            c.execute("DELETE FROM connect_attempt WHERE at < ?", (cutoff,))
            c.execute(
                """DELETE FROM connect_attempt WHERE id NOT IN
                   (SELECT id FROM connect_attempt ORDER BY at DESC LIMIT ?)""",
                (int(max_attempt_rows),),
            )
            c.execute("DELETE FROM event WHERE ts < ?", (cutoff,))

    # ---------- event ----------
    def add_event(self, ev):
        c = self.conn()
        with c:
            c.execute(
                "INSERT INTO event(ts,level,source,code,message,data) VALUES(?,?,?,?,?,?)",
                (
                    float(ev.get("ts") or time.time()),
                    ev.get("level") or "info",
                    ev.get("source") or "?",
                    ev.get("code") or "-",
                    ev.get("message") or "",
                    json.dumps(ev.get("data") or {}, ensure_ascii=False, default=str),
                ),
            )

    def list_events(self, limit=100, level=None):
        c = self.conn()
        if level:
            order = {"debug": 0, "info": 1, "warn": 2, "error": 3}
            cur = c.execute(
                "SELECT * FROM event ORDER BY id DESC LIMIT ?", (int(limit) * 4,)
            )
            rows = [dict(r) for r in cur.fetchall()]
            minlvl = order.get(level.lower(), 1)
            keep = {"debug": 0, "info": 1, "warn": 2, "error": 3}
            rows = [r for r in rows if keep.get(r.get("level"), 1) >= minlvl][: int(limit)]
        else:
            cur = c.execute("SELECT * FROM event ORDER BY id DESC LIMIT ?", (int(limit),))
            rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            try:
                r["data"] = json.loads(r.get("data") or "{}")
            except Exception:
                r["data"] = {}
        return rows

    # ---------- setting ----------
    def set_setting(self, key, value):
        c = self.conn()
        with c:
            c.execute(
                "INSERT INTO setting(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value, ensure_ascii=False, default=str)),
            )

    def get_setting(self, key, default=None):
        c = self.conn()
        cur = c.execute("SELECT value FROM setting WHERE key=?", (key,))
        row = cur.fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except Exception:
            return default

    def all_settings(self):
        c = self.conn()
        out = {}
        for row in c.execute("SELECT key,value FROM setting").fetchall():
            try:
                out[row["key"]] = json.loads(row["value"])
            except Exception:
                out[row["key"]] = row["value"]
        return out

    def db_size_bytes(self):
        total = 0
        for suffix in ("", "-wal", "-shm"):
            p = self.path + suffix
            try:
                total += os.path.getsize(p)
            except OSError:
                pass
        return total
