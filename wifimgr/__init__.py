"""WiFi Manager —— NAS 无线网络管理面板（纯 stdlib）。

设计约束（目标机：Ubuntu 20.04 rootfs / Python 3.8.10 / NM 1.22.10 / ARMv7）：
  * 只用标准库。ARMv7 无 manylinux wheel，MarkupSafe 之类 C 扩展需要 gcc，
    厂商 rootfs 没有编译工具链，装 Flask 会在部署期翻车。
  * 代码需兼容 Python 3.8 —— 不用 tomllib、不用 list[str]、不用 functools.cache。
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
