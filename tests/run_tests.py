"""离线测试入口：不需要 nmcli / Linux / root。

    python3 tests/run_tests.py            # 全部
    python3 tests/run_tests.py terse      # 只跑名字含 terse 的

Windows 开发机上也能跑（flock 相关用例会 skip）。
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
# discover 需要 tests/ 是一个包（存在 __init__.py）才能按 top_level_dir 导入
if not os.path.isfile(os.path.join(HERE, "__init__.py")):
    with open(os.path.join(HERE, "__init__.py"), "w", encoding="utf-8") as fh:
        fh.write('"""WiFi Manager 离线测试包（不需要 nmcli / Linux / root）。"""\n')
sys.path.insert(0, HERE)


def main(argv=None):
    argv = argv or sys.argv[1:]
    loader = unittest.TestLoader()
    if argv:
        # 指定模块名过滤
        suite = unittest.TestSuite()
        for name in argv:
            suite.addTests(loader.loadTestsFromName(name))
    else:
        suite = loader.discover(HERE, pattern="test_*.py", top_level_dir=ROOT)
    runner = unittest.TextTestRunner(verbosity=2, buffer=False)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
