# NAS WiFi 管理面板（nas-wifimgr）— 交接记忆文档

> **给下一个接手的 AI / 人类工程师**
> 本文记录截至 **2026-10-08 15:07** 的全部工作状态、实测坑位、决策依据与未完成事项。
> 目标是让你**不必重新踩一遍坑**就能继续改动这个项目。
>
> 本文档生成自一次真实的连续开发会话（4 个 commit），所有"实测"结论均在目标机验证过。

---

## 0. 三十秒速览

| 项目 | 值 |
|---|---|
| 做什么 | 把 NAS 上散落的 `wifi-check.sh` + 硬编码 WiFi 密码，收敛成一个可维护的Web 面板 |
| 目标机 | `192.168.31.47`（海思 Hi3798 NAS，ARMv7，**Linux 4.4.35**） |
| 技术栈 | **纯 Python 标准库** + systemd + nginx 反代，**零第三方依赖** |
| 代码位置 | Windows：`C:\Users\zhang\WorkBuddy\2026-10-08-00-21-03\nas-wifimgr\` |
| WSL 路径 | `/mnt/c/Users/zhang/WorkBuddy/2026-10-08-00-21-03/nas-wifimgr/` |
| NAS 部署位置 | `/opt/wifimgr/`（**不是** `/opt/wifimgr/current`，不存在这层） |
| GitHub | https://github.com/zhang-astronaut/nas-wifimgr （**公开**，main 分支） |
| 测试 | **206 项全绿**，`python tests/run_tests.py`，Windows 上也能跑 |
| 面板地址 | http://192.168.31.47/wifi/ |
| 常驻内存 | 约 9 MB |

---

## 1. 最重要的几条警告（先看这个）

### ⚠️ 1.1 绝不要删掉当前正在使用的 WiFi profile

这是本项目**最危险的操作**。`delete` 会真的删掉 NetworkManager 的 keyfile（含密码），
wlan0 立刻 `disconnected`。

更糟的是：**守护线程（guardian）会紧接着尝试重连，把 profile 重建成
`key-mgmt=none` 的残骸状态**（`[wifi-security]` 段里没有 `psk`），此后
`nmcli con up` 会报：

```
Warning: password for '802-11-wireless-security.wep-key0' not given in 'passwd-file'
Error: Connection activation failed: Secrets were required, but not provided
```

**这个残骸状态比删除前更难恢复**——需要手工从快照恢复 keyfile 才能救回来。
（本次会话中真的发生过一次，详见 §5.3。）

代码层面已加保护：`delete_network()` 会比对当前活跃 profile 名，命中即返回
`400 VALIDATION_FAILED` 且**不做任何改动**。你改代码时不要绕过这个保护。

### ⚠️ 1.2 有线不会因切WiFi 断线（但别依赖这一点）

`192.168.31.47` 在 **eth0**，且 eth0 是 **unmanaged**（`[ifupdown] managed=false`），
默认路由 `default via 192.168.31.1 dev eth0`。NetworkManager 只重建 wlan0。

所以调试切WiFi 时 SSH/网页全程不受影响。**但如果哪天这台机器的 IP 变成走
WiFi 的，这个前提就消失了**，删 profile 前务必先切网络。

### ⚠️ 1.3 密码绝不进 argv

`nmcli connection add ... wifi-sec.psk <password>` 会让 PSK 出现在
`/proc/<pid>/cmdline`，同机的 www-data 都读得到。

**唯一正确的写入路径**是本项目自己的 `apply_profile()`：
渲染 keyfile → 备份旧文件到快照 → `write_keyfile()` 到 keyfiles 目录（0600 root）
→ `nmcli connection reload` → **回读校验**。

---

## 2. 完整架构

### 2.1 目录布局

```
nas-wifimgr/                 # 53 个跟踪文件 / 9591 行
├── wifimgr/                 # 主包（22 文件）
│   ├── __main__.py          # CLI 入口：serve / daemon / probe-sae / selftest
│   ├── api.py               # 业务逻辑，纯函数 (ctx, body) -> (status, dict)
│   ├── httpd.py             # ThreadingHTTPServer + 路由分发（★本次修过）
│   ├── config.py            # 配置加载 /etc/wifimgr.json
│   ├── store.py             # SQLite（★无任何密码列）
│   ├── daemon.py            # 守护线程：指数退避 / flock / 抖动检测
│   ├── nmkey.py             # keyfile 渲染 / 转义 / 原子写入 / 快照
│   ├── terse.py             # nmcli -t 和 -f 输出解析
│   ├── models.py            # ConnStatus / ConnectResult 等数据类
│   ├── errors.py            # AppError / ValidationError / NotFoundError ...
│   ├── security.py          # CSRF 守卫 + 静态路径解析
│   ├── static/
│   │   ├── app.js           # 前端（无框架）
│   │   ├── app.css
│   │   └── index.html
│   └── backends/
│       ├── base.py          # Backend 抽象 + iw 输出解析
│       ├── nmcli.py         # NMBackend（主力，1300+ 行）
│       ├── wpasup.py        # WpaSupplicantBackend（无 NM 的 OpenWrt）
│       └── fake.py          # FakeBackend（回放真实 nmcli 输出）
├── tests/                   # 20 文件 / 206 项测试
│   ├── run_tests.py         # 入口：python tests/run_tests.py
│   ├── fixtures/            # 固化的实机 nmcli 输出
│   └── test_*.py
├── deploy/
│   ├── install.sh           # 幂等安装（--dry-run 可预演）
│   ├── rollback.sh
│   ├── wifimgr.service      # systemd unit
│   ├── nginx-location.conf
│   ├── journald-limit.conf
│   └── wifimgr-tmpfiles.conf
├── tools/
│   └── emmc-audit.sh        # eMMC 写入审计工具
├── etc/wifimgr.json# 配置模板
├── README.md                # 604+ 行，含完整全新安装文档
├── .gitattributes           # ★强制 eol=lf
└── .gitignore
```

### 2.2 为什么是纯标准库（选型理由，别轻易改）

**ARMv7 上没有 manylinux wheel**。MarkupSafe、Cython 之类是C 扩展需要gcc，
而厂商的 ecoo rootfs **没有编译工具链**。

实测对比：纯 stdlib RSS **12.9 MB**（后期稳定在 9 MB），Flask 约 25–35 MB。

同时**不用 Docker**（内存/磁盘余量小）、**不用 PHP**（php7.4-fpm 已被厂商 UI
占用，且 WiFi 控制需要长任务与守护进程）。

### 2.3 NAS 上的目录

| 路径 | 内容 |
|---|---|
| `/opt/wifimgr/wifimgr/` | 程序代码（部署产物，本地是唯一可编辑副本） |
| `/opt/wifimgr/deploy/`, `/etc/`, `/tests/`, `/tools/` | 其他组件 |
| `/etc/wifimgr.json` | 运行时配置 |
| `/var/lib/wifimgr/wifimgr.db` | SQLite |
| `/var/lib/wifimgr/keyfile-snapshots/` | keyfile 备份（★救过命） |
| `/etc/NetworkManager/system-connections/` | 真正的 keyfile 目录 |
| systemd unit | `wifimgr.service` |
| nginx | `/wifi/` 反代到 `127.0.0.1:8791` |

---

## 3. ★ 实测坑位清单（本项目最有价值的部分）

这些**全部在目标机上实测确认**，很多推翻了原本的设计假设。

### 3.1 NetworkManager / nmcli

| # | 坑 | 后果 / 正确做法 |
|---|---|---|
| **D1** | **`nmcli connection load` 假成功** | 返回 `rc=0`，但 journalctl 是 `no settings plugin could load` + `result="fail"`，profile 根本没创建。`/tmp` 和0700 私有目录**都失败**。**唯一可行路线**：直接写 `/etc/NetworkManager/system-connections/<name>.nmconnection`（0600 root）+ `nmcli connection reload`。→ 代码所有 profile 操作**强制回读校验，绝不信 rc** |
| **D2** | keyfile 里 `type` 必须是 `wifi` | 不是 `802-11-wireless`。症状与 D1 完全一样，**极易误判** |
| **D3** | keyfile 里 `bssid` 是**分号十进制** | `50:4F:3B:18:31:9B` → `80;79;59;24;49;155;`。写成转义冒号形式必然 `ssid-not-found`。而 `ssid` 字段明文可用 |
| **D4** | `nmcli -g` 多字段会`rc=2` 失败 | 改用 `-f` 定宽输出 |
| **D5** | `nmcli -t` 对 `dev show` **输出为空** | `rc=0` 但内容为空，**最阴险的一个**。`dev show` 一律用 `-f` 不加 `-t` |
| **D6** | `p2p0` 让扫描结果翻倍 | 22 行 vs `ifname wlan0` 的 11 行 → **强制带 ifname** |
| **D7** | NM 为「有 profile 但扫不到」的 SSID 吐**无 BSSID 占位记录** | 形如 `wlan0:RD08_IoT::0 MHz:0:WPA1 WPA2`，不可连接。判据：按 BSSID 判空丢弃。**真正隐藏网络是 SSID 空但 BSSID 存在，所以此判定不误伤** |
| **D8** | `WIFI-SIGNAL` 字段本驱动**恒空** | 信号强度只能取 `iw dev wlan0 link` |
| **D9** | `iw` 输出非ASCII SSID 用 C 转义 | `\xe5\xaf\x86...`，需**先累积字节再统一 UTF-8 解码**（不能逐字节解）。还要注意大写 `\X` |
| **D10** | keyfile 里 `ssid` 是分号转义（91 字节） | 所以**按明文 SSID 匹配 keyfile 永远匹配不上**。排查时要改用文件名匹配 |

### 3.2 systemd unit

| # | 坑 | 正确做法 |
|---|---|---|
| **S1** | `RestrictAddressFamilies` 必须含 `AF_NETLINK` | 否则 `iw` **静默失败**，信号强度永远为空（不报错！） |
| **S2** | `StartLimitIntervalSec` 属于 `[Unit]` 段 | 写在 `[Service]` 会被忽略并告警 |
| **S3** | `Ctx(daemon=...)` 参数名错误 | 必须是 `guardian=`，写错会导致 systemd **启动直接崩溃** |

### 3.3 Python / HTTP / 前端

| # | 坑 | 说明 |
|---|---|---|
| **P1** | **`[hidden]` 属性靠 UA 样式表的 `display:none` 实现** | 任何显式 `display:flex/grid/block` 都会**覆盖**它。这是通用陷阱 → CSS 必须加 `[hidden] { display: none !important; }` |
| **P2** | JS 函数声明提升 | 重复定义 `showOverlay`/`hideOverlay`/`esc` 时，**旧的有 bug 版本会胜出** |
| **P3** | `status()` 返回 `ConnStatus` 对象（`__slots__`） | 不是 dict，用 `.get()` 会 `AttributeError` |
| **P4** | `ValidationError(message, detail, field)` | **不接受 `hint=` 参数**，传了会 `TypeError` |
| **P5** | `store.upsert_profile_ref(has_secret=)` | 参数名错误，真实名字是 **`has_psk`** |
| **P6** | `store.add_saved_network()` 不存在 | 真实方法是 **`upsert_saved_network()`** |
| **P7** | `ctx.store` 是 per-thread sqlite 连接 | 用完必须 `close_thread_conn()`，否则线程池会积累连接 |

### 3.4 WPA3 / SAE（重要，与直觉相反）

**SAE 握手在本机不可用。** 同一个混合 AP 实测：
- `wpa-psk` ✅ 拿到 IP
- `sae` ❌ 25 秒超时

原因：wpa_supplicant 2.9 确实带 SAE 支持，但**rtl8188fu 出厂驱动 + 内核 4.4
无法完成 PMF 帧**。

**更坑的是**：配置层回读会显示 sae「成功」—— **配置层探测会误报**。
所以默认策略是 `sae_policy=psk_first`，SAE 探测藏在设置里（用户已选择隐藏）。

---

## 4. 密码安全模型

**路径**：渲染 keyfile → 备份旧文件到快照目录 → 写 keyfiles 目录（0600 root）
→ `nmcli connection reload` → **回读校验** → `nmcli connection up`。

**已实测验证**：连接成功后扫描全机 `/proc/*/cmdline`，密码零出现。

应用 SQLite **无任何密码列**（`has_psk` 只是布尔）。有测试断言 schema 不含
`psk`/`password` 字段（`tests/test_no_secrets.py`，6 项）。

### 4.1 ★ 推公开仓库前抓到真实凭据泄漏

`backends/nmcli.py` 的 SAE 探测把**真实 WiFi 密码硬编码**成了默认值。
若直接 push 到公开仓库等于永久泄漏。

修复：改用显式占位串 `wifimgr-probe-placeholder`；测试改用 `testpass1`；
新增 `test_no_secrets.py` 把「源码不得出现真实口令字面量」变成**可执行断言**
（白名单机制，改白名单等于主动声明"这是假密码"）。

### 4.2 CRLF 陷阱

Windows 的 git 默认把 `.sh` 转成 CRLF，推到 Linux 上会报
`/bin/sh^M: bad interpreter`。`.gitattributes` 里 `* text=auto eol=lf` 是**必需**的。

---

## 5. 完整变更历史（4 个 commit）

### 5.1 `be8da9d` — 初始版本（190 项测试）

功能：扫描、连接（WPA2/WPA3 降级链）、保存/删除已保存网络、守护线程、
eMMC 审计工具、完整 README。

**同时完成了 eMMC 磨损评估**：

| 场景 | 60s 内本软件文件修改数 |
|---|---|
| 空闲（守护运行中） | **0** |
| 前端轮询打开 | 0 |
| 扫描 | 0 |
| 连接/保存/改配置 | 少量（低频人工操作） |

根文件系统在 **mmcblk0p9 = eMMC**（不是 SD 卡）。厂商驱动未暴露
`wear_leveling`/`life_time_estimation_ts`，只能靠 `/sys/block/mmcblk0/stat`
第 7 字段（写入扇区数）差分间接评估。

**真正的消耗源不是本软件**：
1. **journald 无上限，已占 673MB** → 加 `journald-limit.conf`
   （SystemMaxUse=200M），**实测 673MB → 208MB**（现216MB）
2. Docker overlay2 也在 eMMC 上（3 个容器：青龙/Portainer/CUPS）。
   README 已提示用 `logging: max-size` 限制，**未擅自改用户容器配置**

⚠️ 测量方法教训：30 秒短窗口测出过「停机时写入反而更多」的反直觉结果，
是其它进程噪声。**必须用 ≥60s 窗口 + 本软件自身文件 mtime 双重佐证**。

### 5.2 `048d6e7` — 修复删除功能 404

**现象**：用户报 `无此接口: DELETE /api/v1/networks/%E5%AF%86...`

**根因**：`httpd._match_deep()` 里的 DELETE 分支**被误缩进进了
`if method == "POST"` 内部**。代码一直存在、看起来完全正常，但只在 method 是
POST 时才可能执行 → **任何 DELETE 都必然 404**。

```python
# 修复前（错误）
if method == "POST":
    m = re.match(r"^/api/v1/networks/(.+)/connect$", path)
    if m: ... return h
    m = re.match(r"^/api/v1/networks/([^/]+)$", path)   # ← 嵌在 POST 里
    if m: ... delete_network ...return h                 # ← 永不执行

# 修复后
if method == "POST":
    ...  # 只管 connect
if method == "DELETE":        # ← 提为独立分支
    ...
```

**教训**：
- **不可达的分支不会有语法错误、也不会被 linter 报出来**。缩进错误把一段正确
  代码变成死代码，而代码审查时它看起来是对的。
- 报「无此接口」时应**立刻怀疑路由表**，而不是先怀疑 URL 编码或代理配置。
  本次的 `%E5%AF%86...` 中文编码完全是干扰项。

新增 `tests/test_delete_route.py`（12 项），起真服务器 + 真 Store，
用**用户实际报错的 URL 里的真实 profile 名**。
**已验证移除修复后 5 项失败**。

### 5.3 `0c4442a` — 拒绝删除当前活跃网络（实机事故换来的）

**事故经过**：DB 里有两条重复记录（调试残留 + 当前活跃的），
我以为在清理重复项，**把当前活跃的那条也删了** → wlan0 立刻掉线。

**恢复过程（耗时较长，值得记录）**：
1. `keyfile-snapshots/` 里的旧快照救了这个场 ★
2. 但踩了两个坑：
   - 按 `sorted()` 取最新快照会取到**自己刚失败重连时生成的坏快照**
     （`key-mgmt=none`、无 psk）。**必须校验 psk 非空 + key-mgmt 正确**
   - keyfile 里的 `ssid` 是分号转义（91 字节，见 D10），
     按明文匹配永远失败 → 改用文件名匹配
3. 最终从健康快照整份拷回 + `nmcli connection reload` + `con up` 恢复

**代码改动**：
- `Ctx.active_profile_name()`：取活跃 profile 名，**任何异常吞掉返回 None**
- `delete_network()`：与活跃名相同则报 `400 VALIDATION_FAILED`，不删任何东西
- **取不到活跃信息时放行** —— 宁可误删也不能让功能变成不可用
- 前端 confirm 文案改成如实说明「会删除系统里保存的配置（含密码）」，
  原文案「仅删除记录，不动系统里的密码」是**错的**

**实机验证**：删除活跃网络返回 400 且**未断网**。

### 5.4 `a1f73d5` — 文档

README 新增 §11.5.1「删除已保存的网络：会删掉什么」、
§11.8「SSH 使用提示」（含 PowerShell 转义踩坑表）。

---

## 6. ★ 未完成 / 待处理事项

### 6.1 守护线程仍是 `dry_run=true`（**用户已知情，尚未决定**）

守护在跑（`cycles=701`，健康），但**只探测不动作**。
建议观察一两天确认稳定后，在 `/etc/wifimgr.json` 里把 `dry_run` 改 `false`，
或用面板的守护设置。

### 6.2 `RD08_IoT` 的 autoconnect（**用户尚未回复选哪个**）

**现状**（2026-10-08 15:07 实测）：

| profile | UUID | autoconnect | priority | SSID 是否存在 |
|---|---|---|---|---|
| 密码是八个八-18319B（活跃） | `4ec333c8-...` | yes | **100** | ✅ 存在 |
| RD08_IoT | `188621c0-...` | yes | **0** | ❌ **已不存在** |

`RD08_IoT` 的 `connection.autoconnect-retries=0` 意为 **forever（无限重试）**。

**但实测它现在并没有在干扰** —— 最近 40 分钟 NetworkManager 日志里，
`188621c0` / `RD08_IoT` **一次激活尝试都没有**。原因是 priority=0 排在
priority=100 后面，NM 抢不到。

**关闭命令**：
```bash
nmcli con mod RD08_IoT connection.autoconnect no    # 关闭
nmcli con mod RD08_IoT connection.autoconnect yes   # 回滚
```

**我给出的建议（用户尚未选择）**：
倾向于**关掉，但不是因为它现在有干扰，而是消除隐患**。
`autoconnect-retries=forever` 是定时炸弹 —— 万一活跃 profile 因别的原因断开、
priority 排序变化，它就会被激活，然后对着不存在的 SSID 无限重试，
每次 25s，还会报 `The base network connection was interrupted` 打断当前连接。
**这个场景之前真实发生过。**

更彻底的做法是直接 `nmcli con del RD08_IoT`（SSID 已不存在，密码也没用了），
但保守起见建议先关 autoconnect 观察几天。

### 6.3 旧 cron 已停用未删（有意保留，可回滚）

- `/etc/cron.d/wifi-check` 加了 `# disabled-by-wifimgr` 前缀
- 旧脚本 `/usr/local/bin/wifi-check.sh` 权限收紧为 0750，**未删除**

### 6.4 Docker 日志限制（未擅自改用户配置）

3 个容器的 overlay2 在 eMMC 上。建议在各自 compose 里加：
```yaml
logging:
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"
```
**这是用户自己的服务，不要未经许可改。**

---

## 7. 开发指南（给接手的人）

### 7.1 本地编辑 → 部署的流程

```bash
# 1. 本地改代码（Windows 上编辑）
# 2. 跑测试（Windows 也可以，不需要 Linux）
cd C:\Users\zhang\WorkBuddy\2026-10-08-00-21-03\nas-wifimgr
python tests/run_tests.py

# 3. scp 上去
scp -i ~/.ssh/id_ed25519_nas wifimgr/api.py root@192.168.31.47:/tmp/api.py.new

# 4. 用 Python 脚本做「语法校验 → 备份 → 原子替换 → 回读校验」
ssh -i ~/.ssh/id_ed25519_nas root@192.168.31.47 "python3 -" < deploy_script.py

# 5. 重启
ssh -i ~/.ssh/id_ed25519_nas root@192.168.31.47 "systemctl restart wifimgr"
```

**不要写长shell 命令**（见 §8.2）。整份 `deploy/install.sh` 是幂等的，
大改动直接跑它更省事（支持 `--dry-run` 预演，会自动 `.bak-YYYYMMDD` 备份）。

### 7.2 新增测试的铁律

**每次修 bug 后，必须验证测试确实能抓到这个 bug**：

```bash
git stash push wifimgr/xxx.py    # 回退修复
python -m unittest tests.test_yyy # 必须失败
git stash pop                     # 恢复
python -m unittest tests.test_yyy # 必须全绿
```

### 7.3 ★ 两条血泪教训（务必遵守）

**教训一：mock 掉的正是最容易出错的注入路径。**

「记住网络不生效」那个bug 的成因：`NMBackend`漏实现 `set_store`，
而 `__main__.py` 用 `hasattr(backend, "set_store")` 判断注入 → 恒 False →
store 永远没被注入，**且完全静默**。

为什么测试没抓到？因为**测试全用 FakeBackend，而 FakeBackend 有 `set_store`**。
真实注入路径从来没被测过。

→ **凡是用 `hasattr` 做可选注入的地方，都必须有一条真实后端的测试。**

**教训二：静默 return 是最坏的失败方式。**

→ store为 None 时至少要打 **error 级日志**，并把状态透传给用户
（写到 `res.detail["remember_warning"]`，前端弹红色 toast），
而不是默默返回 False 让界面显示"还没有保存的网络"。

### 7.4 常见测试陷阱

- **写完测试失败时，先分清是产品有 bug 还是自己断言写错**。别急着改产品代码。
- 用 `Edit` 往测试文件里插入大段代码后**必须核对类边界** —— 插class 时
  容易把上一个方法挤到错误的类里，测试串位后报的错完全不相关。
- 断言「被拦下时X 应存在」之前，先确认 `setUp` 里真的创建了 X。
- **不要用 `except AttributeError: pass` 兜底** —— 那会让假测试静默通过。
  方法名写错就应该直接报错。
- Windows 上 `TemporaryDirectory.cleanup()` 可能抛 `WinError 32`
  （sqlite 连接还被线程持有）→ 用 `try/except OSError: pass` 兜。

---

## 8. 环境与工具（踩过的坑）

### 8.1 SSH 到 NAS：必须带 `-i`

```bash
ssh -i ~/.ssh/id_ed25519_nas -o BatchMode=yes root@192.168.31.47 "cmd"
```

本机 `~/.ssh/` 下有两个专用密钥：
- `id_ed25519_nas` → **NAS（192.168.31.47）用这个**
- `id_ed25519_router` → 路由器

默认的 `~/.ssh/id_ed25519` **不存在**，所以不带 `-i` 会回退到密码认证并
卡在交互式提示符上。

> 本次会话曾误以为「SSH 需要密码」，绕了一圈才发现一直是走公钥。
> **看到密码提示符时，先查 `~/.ssh/` 有没有专用密钥。**

### 8.2 ★ Windows PowerShell → ssh 的转义地狱

| 写法 | 结果 |
|---|---|
| 命令里含反引号 `` `$(date +%Y%m%d)` `` | PowerShell 先解析，报语法错 |
| 命令里含 `%s` / `%{http_code}` / `%VAR%` | **被安全策略拦截**（误判成 cmd 变量语法） |
| 嵌套双引号 + 转义 | 极易出错 |

**绕过办法（本次全程使用）**：把脚本写成 heredoc，管道喂给远端 `python3 -`：

```powershell
$py = @'
import json, urllib.request
print(json.load(urllib.request.urlopen("http://127.0.0.1:8791/api/v1/status", timeout=10)))
'@
$py | ssh -i "$env:USERPROFILE\.ssh\id_ed25519_nas" -o BatchMode=yes root@192.168.31.47 "python3 -"
```

同理，**`git commit -m` 的信息里也不能出现 `%s` 之类**，会被拦。

### 8.3 目标机的环境差异

| 项 | 情况 |
|---|---|
| **`sqlite3` CLI** | **没有！** 查库必须用 Python 的 `sqlite3` 模块 |
| `python3` | `/usr/bin/python3`（**Python 3.x，注意 `f-string` 兼容性**） |
| SSH 横幅 | 每次连接都打印 OpenSSH 后量子 KEX 的 WARNING，干扰脚本解析 |
| 系统字体 / locale | 远程输出中文常显示为乱码，**建议在Python 脚本里显式处理**：`x.encode("utf-8","replace").decode("utf-8","replace")` |

### 8.4 WSL 环境（**已实测可用**）

- 发行版：**Ubuntu 26.04.1 LTS**，WSL2，内核 `6.18.40.1-microsoft-standard-WSL2`
- `/mnt/c` 可访问 → 仓库路径 `/mnt/c/Users/zhang/WorkBuddy/2026-10-08-00-21-03/nas-wifimgr/`
- **测试在 WSL 里实测通过**：`python3 tests/run_tests.py` →
  `Ran 206 tests, OK (skipped=1)`

**注意 skip 数量差异**：Windows 是 `skipped=2`，WSL/Linux 是 `skipped=1`。
差的那一项是 **flock 相关用例**（`daemon.py` 里的文件锁）——
Windows 上没有 `fcntl.flock` 所以 skip，Linux 上真的跑。
**这是正常的，不是测试缺失。**

如果你在 WSL 里改代码，测试会比 Windows 多覆盖一条 flock 逻辑，
这是好事。

---

## 9. 测试体系

**206 项**，分布在 20 个文件。入口：

```bash
python tests/run_tests.py          # Windows / Linux 都可以
python -m unittest tests.test_xxx  # 单个文件
python3 -B -m wifimgr selftest     # 设备上自检
```

| 文件 | 项数 | 覆盖 |
|---|---|---|
| `test_terse.py` | 20 | nmcli 输出解析 |
| `test_nmkey.py` | 33 | keyfile 渲染 / 转义 / 原子写入 |
| `test_security.py` | 17 | CSRF / 目录穿越 |
| `test_daemon.py` | 19 | 守护线程逻辑 |
| `test_api.py` | 28 | 业务逻辑 |
| `test_http.py` | 19 | 端到端 HTTP |
| `test_iw.py` | 13 | iw 输出 / C 转义解码 |
| `test_cli.py` | 6 | CLI 组装路径 |
| `test_static.py` | 16 | CSS / JS 静态断言（无浏览器依赖） |
| `test_remember.py` | 8 | **用真实 NMBackend + 真实 Store** |
| `test_scan_phantom.py` | 4 | 无 BSSID 占位记录过滤 |
| `test_no_secrets.py` | 6 | **源码不得含真实口令字面量** |
| `test_delete_route.py` | 16 | DELETE 路由 + 活跃删除保护 |

`fixtures/` 固化了实机抓取的真实 nmcli 输出（含转义 BSSID、中文 SSID、空 SSID、
占位记录、缺字段行）。

**测试哲学**：安全不变量要有专门测试把「设计意图」变成**可执行检查**。

---

## 10. 当前实机状态（2026-10-08 15:07 快照）

```
SSID        = 密码是八个八（2.4G 那个，信号 -17 dBm）
IP          = 192.168.31.64
state= connected
profile_ref = ['密码是八个八-18319B']
saved_network = ['密码是八个八-18319B']
connect_attempt= 14 条
keyfiles     = ['RD08_IoT.nmconnection', '密码是八个八-18319B.nmconnection']
snapshots    = 8 份
guardian     = running, cycles=701, consecutive_failures=0, flapping=False
journald     = 216.0M（已从 673M 回收）
内存        ≈ 9.2 MB
```

NAS 上的备份文件（回滚用）：
```
/opt/wifimgr/wifimgr/httpd.py.bak-20261008-031107
/opt/wifimgr/wifimgr/httpd.py.bak-20261008-0318
/opt/wifimgr/wifimgr/api.py.bak-20261008-0318
/opt/wifimgr/wifimgr/static/app.js.bak-20261008-0318
```

> 注：用户在此期间把 WiFi 从 `密码是八个八wifi5`（5G）切到了
> `密码是八个八`（2.4G，BSSID `50:4F:3B:18:31:9B`）。
> 这两个是**不同的 SSID、不同 BSSID、不同密码**（8 位 vs 12 位），
> 对应不同的 profile。**改代码时不要假设当前连的是哪个。**

---

## 11. 快速排障对照表

| 症状 | 先查 |
|---|---|
| 面板打不开 | `systemctl status wifimgr`；`nginx -t`；确认 `/wifi/` 反代配置 |
| 接口报「无此接口」 | 查 `api.py` 的 `ROUTES` 和 `httpd.py` 的 `_match_deep`（**可能是分支被缩进死了**） |
| 信号强度永远为空 | `AF_NETLINK` 是否在 unit 里；`iw dev wlan0 link` 能否跑 |
| 扫描结果翻倍 | 是否带了 `ifname wlan0`（排除 `p2p0`） |
| 列表里多出连不上的记录 | 无 BSSID 占位记录（D7），按 BSSID 判空丢弃 |
| 连不上某 AP | 看 journald 的 `Activation: failed`，注意 `key-mgmt` 回读是否一致 |
| 「明明保存了但列表为空」 | `store` 是否注入成功（`hasattr` 静默失败陷阱）；`remember_warning` |
| WiFi 掉线且无法恢复 | 检查 keyfile 是否变成 `key-mgmt=none`；从 `keyfile-snapshots/` 恢复 |
| 切WiFi 后网页卡住 | 90s 超时 + 100s 看门狗是否生效；检查 `[hidden]` 的 CSS 兜底 |
| eMMC 写入异常 | `bash tools/emmc-audit.sh`，**用 ≥60s 窗口** |

---

## 12. 给接手者的建议

1. **先跑一遍测试**（206 项）确认基线是绿的，再动手。
2. **改任何 profile 相关代码前**，先把 D1–D10 读一遍，那些坑都是实测的。
3. **不要简化 `apply_profile` 的回读校验**。它看着啰嗦，但正是它让我们
   能发现「nmcli 假成功」这类问题。
4. **不要给 `NMBackend` 减方法**。上次漏一个 `set_store` 就静默坏了整条链路。
5. 新增功能记得同步更新 `README.md`（§11 是完整全新安装文档，
   用户明确要求「以后全新安装时能照着做」）。
6. 提交前确认 `test_no_secrets.py` 过了 —— **这个仓库是公开的**。

---

*文档生成时间：2026-10-08 15:07*
*对应 commit：`a1f73d5`（main 分支）*
*本次会话共 4 个 commit / 53 文件 / 9591 行 / 206 项测试*

---

## 附录：本文档的自检方式

如果你要验证这份文档是否可用：

```bash
# WSL 里
cd /mnt/c/Users/zhang/WorkBuddy/2026-10-08-00-21-03/nas-wifimgr
file HANDOVER-MEMORY.md          # 应显示 UTF-8 text
python3 tests/run_tests.py       # 应 206 项全绿（skipped=1）
git log --oneline -5             # 最后一个是 docs: 新增交接记忆文档
```

Windows PowerShell 里看中文会显示乱码，**那是控制台编码问题，
不是文件问题**。用 WSL 或任意 UTF-8 编辑器打开即正常。
