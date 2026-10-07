"""后端抽象。

目标机有 NetworkManager，所以 :class:`NMBackend` 是主力。
另外两种存在的意义：

* :class:`WpaSupplicantBackend` —— 给没有 NM 的 Linux（OpenWrt 等）用，
  走 ``iw dev X scan dump`` + ``wpa_cli``。
* :class:`FakeBackend` —— 让解析/状态判定逻辑能在**没有 nmcli 的机器**
  （比如开发用的 Windows）上跑真实测试。这是本机唯一的验证手段，
  而 terse 解析恰恰是最容易埋 bug 的地方。
"""

from .base import Backend
from .fake import FakeBackend
from .nmcli import NMBackend
from .wpasup import WpaSupplicantBackend

__all__ = ["Backend", "NMBackend", "WpaSupplicantBackend", "FakeBackend", "auto_detect"]


def auto_detect(cfg, log, force=None):
    """按配置或探测结果挑选后端。``force`` 可跳过探测（测试用）。"""
    from ..errors import BackendUnavailable

    want = force or (cfg.get("wifi", {}) or {}).get("backend", "auto")
    if want == "fake":
        return FakeBackend(cfg, log)
    if want == "nmcli":
        return NMBackend(cfg, log)
    if want == "wpasupplicant":
        return WpaSupplicantBackend(cfg, log)

    nm = NMBackend(cfg, log)
    if nm.available():
        log.info("backend", "auto.nmcli", "使用 NetworkManager 后端")
        return nm
    ws = WpaSupplicantBackend(cfg, log)
    if ws.available():
        log.info("backend", "auto.wpasup", "NM 不可用，回退 wpa_supplicant 后端")
        return ws
    raise BackendUnavailable(
        "既没有可用的 NetworkManager 也没有 wpa_supplicant；"
        "请确认 nmcli 存在且 NetworkManager 服务在运行",
        detail={"ifname": (cfg.get("wifi", {}) or {}).get("ifname")},
    )
