"""nmcli terse (``-t``) 输出解析，以及 ``-f`` 定宽输出的解析。

背景（全部在 NAS 192.168.31.47 / NM 1.22.10 上实测确认）：

1. ``nmcli -t -f ...`` 会把字段分隔符 ``:`` 和转义符 ``\\`` 本身转义掉。
   所以 **不能** ``line.split(':')``，也 **不能** 顺序调用
   ``replace('\\\\', ...)`` 再 ``replace('\\:', ...)`` —— 那样 ``\\\\:``
   （本意是「反斜杠 + 分隔符」）会被二次解释成 ``:``，字段错位且静默。

2. ``nmcli -t -f A,B,C dev show IFACE`` 返回 **rc=0 但输出完全为空**。
   ``-t`` 对 ``dev show`` 无效。所以 ``dev show`` 一律用 ``-f``（不加 ``-t``），
   解析 ``KEY:  value`` 定宽格式，且 key 可能带索引后缀（``IP4.ADDRESS[1]``）。

3. ``nmcli -g A,B,C ...`` 直接 rc=2 失败 —— ``-g`` 只支持单字段。

4. SSID 可能为空（隐藏 AP），可能含中文，尾随空格有意义 —— 任何位置都不 strip。
"""

import re

BS = chr(92)

# dev show 的定宽行： "GENERAL.STATE:                          100 (connected)"
# key 允许带 [N] 索引后缀，如 IP4.ADDRESS[1]
_DEVSHOW_RE = re.compile(r"^([A-Za-z0-9_.\-]+(?:\[\d+\])?):\s*(.*)$")

# nmcli 失败时会把 "Error: ..." 打到 stdout。这行会被上面的正则误当成
# key=Error 的字段，必须显式排除，否则会把错误信息当成状态值。
_ERROR_KEYS = frozenset(["error", "hint", "warning", "note"])


def parse_terse(line, fields):
    """解析一行 ``nmcli -t`` 输出，返回 ``dict(zip(fields, values))``。

    单遍扫描：遇到 ``\\`` 就吞掉它并取下一个字符的**字面值**，不再二次解释。
    这样 ``\\\\:``（反斜杠 + 分隔符）与 ``\\:``（字面冒号）都能正确还原。

    容错：
      * 字段数少于 ``fields`` 时补空串（末尾 ``IN-USE`` 为空、``SECURITY`` 缺失都属正常）
      * 字段数多于 ``fields`` 时并入最后一字段，不静默丢数据
      * 空 SSID 自然得到 ``''``，不做任何特殊处理
    """
    if line is None:
        values = []
    else:
        values = []
        cur = []
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            if ch == BS and i + 1 < n:
                # 关键：吞掉反斜杠，取下一个字符的字面值，不再解释它
                cur.append(line[i + 1])
                i += 2
                continue
            if ch == ":":
                values.append("".join(cur))
                cur = []
                i += 1
                continue
            cur.append(ch)
            i += 1
        values.append("".join(cur))

    if len(values) < len(fields):
        values.extend([""] * (len(fields) - len(values)))
    elif len(values) > len(fields):
        tail = ":".join(values[len(fields) - 1:])
        values = values[: len(fields) - 1] + [tail]
    return dict(zip(fields, values))


def parse_terse_lines(text, fields):
    """解析多行 terse 输出，自动跳过空行。

    故意 **不** 跳过「看起来像空」的其它内容：nmcli 偶尔会在此模式混入
    提示行，宁可多返回一条让上层看到，也不要静默吞掉。
    """
    rows = []
    if not text:
        return rows
    for line in text.splitlines():
        if not line.strip():
            continue
        rows.append(parse_terse(line, fields))
    return rows


def parse_dev_show(text):
    """解析 ``nmcli -f A,B,C dev show IFACE`` 的定宽输出。

    返回 ``{key: value}``，其中多值字段（如 IP4.ADDRESS）会把带索引的
    ``IP4.ADDRESS[1]`` / ``IP4.ADDRESS[2]`` 收进 ``IP4.ADDRESS`` 列表，
    同时保留无索引的 ``_first`` 便捷键。
    """
    out = {}
    if not text:
        return out
    for line in text.splitlines():
        if not line.strip():
            continue
        m = _DEVSHOW_RE.match(line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if key.lower() in _ERROR_KEYS:
            continue
        base, idx = key, None
        im = re.match(r"^(.+)\[(\d+)\]$", key)
        if im:
            base, idx = im.group(1), int(im.group(2))
        if idx is None:
            out[key] = val
            continue
        lst = out.setdefault(base, [])
        if not isinstance(lst, list):
            # 同名无索引值先出现过：把它当作第 0 项保留
            lst = [lst] if lst != "" else []
            out[base] = lst
        # 索引从 1 开始；list 下标 = idx-1
        while len(lst) < idx - 1:
            lst.append("")
        if len(lst) == idx - 1:
            lst.append(val)
        else:
            lst[idx - 1] = val
    # 便捷 first 值
    for key in list(out.keys()):
        val = out[key]
        if isinstance(val, list):
            out[key + "_first"] = val[0] if val else ""
    return out


def unescape_dev_show_value(val):
    """还原 ``nmcli -g`` / ``con show`` 输出里的 ``\\:`` 等转义。

    注意 NM 在部分版本下 ``con show`` 的 bssid 会输出成 ``50\\:4F\\:...``。
    """
    if not val or BS not in val:
        return val
    out = []
    i = 0
    n = len(val)
    while i < n:
        ch = val[i]
        if ch == BS and i + 1 < n:
            out.append(val[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def bssid_to_nm_bytes(bssid):
    """``50:4F:3B:18:31:9B`` -> ``80;79;59;24;49;155;``

    NM keyfile 里 bssid 是分号分隔的十进制字节，**不是** ``50\\:4F\\:...``。
    （实测：写成转义冒号形式会导致连接必然 ssid-not-found。）
    """
    if not bssid:
        return ""
    parts = [p.strip() for p in bssid.split(":") if p.strip()]
    if len(parts) != 6:
        raise ValueError("BSSID 需 6 段十六进制，当前: %r" % (bssid,))
    try:
        nums = [int(p, 16) for p in parts]
    except ValueError:
        raise ValueError("BSSID 含非十六进制字符: %r" % (bssid,))
    for n in nums:
        if not 0 <= n <= 255:
            raise ValueError("BSSID 字节越界: %r" % (bssid,))
    return "".join("%d;" % n for n in nums)


def nm_bytes_to_bssid(text):
    """``80;79;59;24;49;155;`` -> ``50:4F:3B:18:31:9B``（上面函数的逆运算）。"""
    if not text:
        return ""
    nums = [int(p) for p in text.split(";") if p.strip() != ""]
    if len(nums) != 6:
        raise ValueError("NM bssid 字节数应为 6，当前: %r" % (text,))
    return ":".join("%02X" % n for n in nums)


def normalize_bssid(text):
    """把各种来源的 BSSID 统一成大写冒号形式；非法输入返回空串而非抛错。"""
    if not text:
        return ""
    raw = unescape_dev_show_value(str(text)).strip()
    try:
        return nm_bytes_to_bssid(raw)
    except (ValueError, TypeError):
        pass
    try:
        bssid_to_nm_bytes(raw)
        return ":".join(p.strip().upper().zfill(2) for p in raw.split(":"))
    except (ValueError, TypeError):
        return ""
