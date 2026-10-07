# WiFi Manager

海思 Hi3798 NAS（192.168.31.47）的无线网络管理面板。替代散落的 `wifi-check.sh`
与硬编码脚本，把扫描、连接、凭据保管、保活四件事收进一个服务。

* 纯 Python 标准库，无第三方依赖（目标机 ARMv7 装不了 Flask，见下文「为什么不用 Flask」）
* 面板：<http://192.168.31.47/wifi/>
* 服务：`systemctl status wifimgr`
* 目标环境：Ubuntu 20.04 rootfs / Python 3.8.10 / NetworkManager 1.22.10 / ARMv7 / eMMC

---

## 快速开始

```bash
git clone https://github.com/zhang-astronaut/nas-wifimgr.git
cd nas-wifimgr
bash deploy/install.sh --dry-run     # 先看会做什么
bash deploy/install.sh               # 实际安装
```

安装完成后面板在 `http://<盒子IP>/wifi/`。完整注意事项见
[部署文档](#十一部署文档全新安装必读)。

---

## 一、eMMC 磨损评估 ★

这台机器的根文件系统在 **eMMC** 上（`/dev/mmcblk0p9` → `/`，容量 7.3G，已用 69%）。
闪存有有限的写入寿命，所以「这个软件会不会磨损硬件」是必须回答的问题。

**结论：本软件在空闲期对 eMMC 零写入，不构成磨损风险。**

实测数据（用 `/sys/block/mmcblk0/stat` 第 7 字段「写入扇区数」差分，
而不是估算）：

| 场景 | 60 秒内本软件文件修改数 | 说明 |
|---|---|---|
| 空闲（守护运行中） | **0** | 守护只读 nmcli 状态，不写任何文件 |
| 前端轮询打开时 | 0 | `/status` `/events` 是只读查询 |
| 扫描 | 0 | 只读 |
| 连接 / 改配置 / 保存网络 | 少量 | 写 SQLite 与 keyfile，属低频人工操作 |

软件设计上刻意规避了磨损：

- **守护线程不写日志到闪存**。健康状态下 `log.debug()` 不产生 I/O；
  事件表在空闲时实测 0 行新增。
- **无高频轮询落盘**。前端 3 秒轮询只发 HTTP GET，不触发任何写操作。
- **SQLite 只在人工操作时写**（连接/保存/改配置），且有
  `prune()` 按 `event_retention_days=30` 与 `max_attempt_rows=2000` 封顶。
- **keyfile 快照有上限**（`snapshot_keep=20`），不会无限增长。
- 临时凭据文件走 `/run`（**tmpfs，不落盘**），崩溃残留由
  `systemd-tmpfiles` 定期清理。

### 真正在磨损 eMMC 的是这些（不是本软件）

审计时发现两个更值得关注的问题：

**1. journald 无上限，已占 673MB**

```
/var/log/journal  →  673 MB
/etc/systemd/journald.conf  →  未设置 SystemMaxUse
```

日志可以无限增长。这是当前最大的闪存消耗源。仓库提供了修复：

```bash
cp deploy/journald-limit.conf /etc/systemd/journald.conf.d/wifimgr-limit.conf
systemctl restart systemd-journald
journalctl --vacuum-size=200M    # 立刻回收
```

**2. Docker overlay2 也在闪存上**

3 个容器（青龙/Portainer/CUPS）的日志与可写层都落在 eMMC。
如需控制，在各容器的 compose 里加 `logging: max-size: 10m, max-file: 3`。

### 自己复测

```bash
bash tools/emmc-audit.sh              # 全面检查
bash tools/emmc-audit.sh --attrib     # 查设备是否暴露寿命属性
bash tools/emmc-audit.sh 120          # 自定义采样窗口（秒）
```

> 注：本机厂商驱动未暴露 `wear_leveling` / `life_time_estimation_ts`，
> 无法直接读剩余寿命，只能靠写入量间接评估。

---

## 二、实测得到的关键事实

这一节是整个项目的地基。**每条都在目标机上实测确认过**，不是从文档推断的。
踩过这些坑的实现基本跑不起来。

### 1. `nmcli connection load` 会「假成功」 ★最严重

```bash
$ nmcli connection load /tmp/x.nmconnection ; echo $?
0                                  # ← 看起来成功
# journalctl 里实际是：
#   settings: load: no settings plugin could load "/tmp/x.nmconnection"
#   audit: op="connections-load" ... result="fail"
```

profile 根本没创建。`/tmp` 与 0700 私有目录**都失败**。

**可行路线**：直接写入 `/etc/NetworkManager/system-connections/<name>.nmconnection`
（0600 root:root），再 `nmcli connection reload`。

> 因此本项目**所有** profile 操作都强制**回读校验**，绝不信任何返回码。

### 2. keyfile 的 `type` 必须是 `wifi`

写 `type=802-11-wireless`（NM 文档里的写法）会导致 plugin 不认，症状与坑 1
一模一样，极易误判。NM 自己落盘的也是 `type=wifi`。

### 3. keyfile 的 `bssid` 是分号分隔的十进制字节

```
bssid=80;79;59;24;49;155;      ✅ NM 回读 50:4F:3B:18:31:9B 正确
bssid=50\:4F\:3B\:18\:31\:9B    ❌ 连接必然 ssid-not-found
```

而 `ssid` 反而**明文可用**（NM 存盘时才转成 `229;175;134;...` 分号十进制）。

### 4. `nmcli -g` 多字段失败；`-t` 对 `dev show` 无效

```bash
$ nmcli -g GENERAL.STATE,GENERAL.CONNECTION dev show wlan0 ; echo $?
2                                    # 失败，无输出
$ nmcli -t -f GENERAL.STATE,... dev show wlan0
                                     # rc=0，但输出完全为空 ← 最阴险
$ nmcli -f  GENERAL.STATE,... dev show wlan0
GENERAL.STATE:      100 (connected)  # ✅
```

规则：`-t` 只用于 `con show` / `dev wifi list` / `dev status`；
`dev show` 一律 `-f` 不加 `-t`，解析 `KEY:  value`（注意 `IP4.ADDRESS[1]` 带索引）。

### 5. `p2p0` 会让扫描结果翻倍

`wlan0`(phy#0) 和 `p2p0`(phy#1) 都是 `wifi` 类型：

```bash
$ nmcli dev wifi list | wc -l                       # 22 行，每个网络重复两遍
$ nmcli dev wifi list ifname wlan0 | wc -l          # 11 行，正确的
```

所有扫描**强制带 `ifname wlan0`**，keyfile 也必须写死 `interface-name=wlan0`，
否则 NM 可能把 profile 挂到 p2p0 上。

### 6. 无 BSSID 的「占位记录」

NM 会为「有 profile 但当前扫描不到」的 SSID 吐一行占位记录：

```
wlan0:RD08_IoT::0 MHz:0:WPA1 WPA2
```

BSSID 空、频率 0、信号 0。**不可连接**，展示出来只会让用户点一个连不上的网络。
应用按 BSSID 判空丢弃它们。

注意区分：真正的隐藏网络是 **SSID 为空但 BSSID 存在**，所以用 BSSID 判定不会误伤。

### 7. WPA3/SAE 在本机**握手不可用**

| 同一个 AP（`密码是八个八`，WPA2/WPA3 混合） | 结果 |
|---|---|
| `key-mgmt=wpa-psk` | ✅ 连上，拿到 192.168.31.64 |
| `key-mgmt=sae`（带/不带 bssid 都试过） | ❌ 25s 超时 `ssid-not-found` |
| 配置层回读 `key-mgmt` | ✅ 显示 `sae` —— **配置能写进去但握手不通** |

`wpa_supplicant v2.9` 确实带 SAE（`grep -ac SAE` = 15），但 rtl8188fu 出厂驱动
（2017 年源码 v4.3.23.6）+ 内核 4.4.35_ecoo 无法完成 SAE 所需的 PMF 帧交换。

**所以：混合 WPA2/WPA3 的 AP 用 `wpa-psk` 连接即可**（实测可行），
应用默认 `sae_policy=psk_first`。**配置层探测会误报 SAE 可用**，不能只看它。

### 8. 遗留 `RD08_IoT` 指向已不存在的 SSID

```
$ nmcli -g 802-11-wireless.ssid con show RD08_IoT   →  RD08_IoT
$ nmcli dev wifi list ifname wlan0 | grep RD08     →  无匹配
```

那个 AP 现在叫 **`密码是八个八wifi5`**（BSSID 未变，仍是 `62:4F:3B:18:31:9B`）。
所以 2026-10-06 设的 `autoconnect-retries 0` 现在帮不上忙 —— NM 会一直重试一个
不存在的 SSID，每次白等 25s，还会抢在真实连接前面（报
`The base network connection was interrupted`）。

**处理**：`active_profile` 默认留空（用当前活跃的），并建议关掉它的 autoconnect：

```bash
nmcli con mod RD08_IoT connection.autoconnect no
```

### 9. 环境限制

| 项 | 说明 |
|---|---|
| `WIFI-SIGNAL` 字段 | 本驱动下**恒为空**，信号强度只能取 `iw dev wlan0 link` |
| `iw` 输出非 ASCII SSID | 用 C 风格转义 `\xe5\xaf\x86...`，需解码 |
| `strings` / `rfkill` | 未安装，本项目不依赖 |
| systemd unit | `RestrictAddressFamilies` **必须含 `AF_NETLINK`**，否则 `iw` 静默失败 |
| `StartLimitIntervalSec` | 属于 `[Unit]` 段，写在 `[Service]` 会被忽略并告警 |

---

## 二、为什么不用 Flask

ARMv7 在 PyPI **没有 manylinux wheel**。`pip install flask` 会拉入
Werkzeug / Jinja2 / **MarkupSafe** / itsdangerous / click，其中 MarkupSafe 是
C 扩展，必须现场编译 —— 要求 rootfs 里有 gcc 与 Python.h，厂商定制 rootfs
通常裁掉了编译工具链。

纯 stdlib 方案零依赖、常驻内存约 **6.5MB**（实测），Flask 约 25–35MB。
本机 931MB RAM 且已有 3 个 Docker 容器在跑，能省就省。

同理不用 Docker、不用 PHP：php7.4-fpm 已被厂商 WebUI 占用，
且 WiFi 控制需要长任务与守护进程，不适合 FPM 请求模型。

---

## 三、架构

```
LAN:192.168.31.47:80
   └─ nginx  /etc/nginx/locations.d/wifimgr.conf
        │   （目录已存在且被 default_server include，厂商 UI 完全不动）
        └─ proxy_pass http://127.0.0.1:8791/
             └─ wifimgr.service   root / Python 3.8.10 / 纯 stdlib
                  ├─ HTTP  :8791   ThreadingHTTPServer + busy 锁 + CSRF
                  ├─ Daemon 线程    退避 + settle 宽限期 + flock
                  ├─ SQLite /var/lib/wifimgr   WAL，无密码列
                  └─ Backend 可插拔   NMBackend | WpaSupplicantBackend | FakeBackend
                        └─ 唯一控制面：nmcli
```

**后端抽象**让解析逻辑能在没有 nmcli 的机器（开发用的 Windows）上被测试。
`FakeBackend` 回放的是本机抓取的真实输出（含转义 BSSID、中文 SSID、空 SSID
隐藏网络、占位记录），`tests/` 下 160 项测试全部不依赖 Linux/nmcli/root。

---

## 四、密码安全

**密码绝不进入 argv。** `nmcli con add ... wifi-sec.psk <pw>` 会把 PSK 暴露在
`/proc/<pid>/cmdline`，同机任何用户（含 nginx 的 www-data）都能读到。

本项目的路径：

```
渲染 keyfile（内存）
  → 备份同名旧文件到 /var/lib/wifimgr/keyfile-snapshots/（留 20 份）
  → 写入 keyfiles 目录（O_EXCL, 0600, root:root）
  → nmcli connection reload
  → 回读校验 ssid / key-mgmt / bssid 与预期一致（不信 rc）
  → nmcli connection up
```

已验证：连接成功后扫描全机 `/proc/*/cmdline`，密码**零出现**。

应用自己的 SQLite **没有任何密码列**（`has_psk` 只是布尔标记）。
`tests/test_security.py` 把这条从「设计意图」变成**可执行检查**：

* 走完整连接流程后扫描所有 argv，断言密码不在其中
* 断言数据库 schema 不含 psk/password/passphrase
* 断言事件落库前已脱敏（`redact()`）
* 断言源码里没有 `wifi-sec.psk` 传给子进程的写法

---

## 五、目录结构

```
/opt/wifimgr/
├── wifimgr/
│   ├── __main__.py       CLI: serve/scan/status/connect/profiles/doctor/selftest/probe-sae
│   ├── terse.py          nmcli -t 解析、dev show 解析、BSSID 编码
│   ├── nmkey.py          keyfile 渲染/转义/写入/快照/覆写删除
│   ├── nmcli 后端         扫描、四级状态判定、连接降级链、SAE 探测
│   ├── daemon.py         守护线程：退避、宽限期、抖动检测、flock
│   ├── httpd.py          ThreadingHTTPServer 加固
│   ├── api.py            业务逻辑（纯函数，可无 HTTP 直测）
│   ├── store.py          SQLite（无密码列）
│   ├── security.py       CSRF + 静态文件防穿越
│   └── static/           前端（原生 JS，手机优先）
├── tests/                160 项离线测试
├── deploy/               install.sh / rollback.sh / systemd unit / nginx 片段
└── etc/wifimgr.json      配置模板

/etc/wifimgr.json                       配置（JSONC，支持注释）
/etc/systemd/system/wifimgr.service     服务单元
/etc/nginx/locations.d/wifimgr.conf     反代片段
/var/lib/wifimgr/wifimgr.db             数据库
/var/lib/wifimgr/keyfile-snapshots/     覆盖前的 keyfile 备份
```

---

## 六、配置

`/etc/wifimgr.json`（JSONC）。优先级：内置默认 < 配置文件 < SQLite `setting` 表
（UI 改守护参数写这里，并回写 json，原子替换）。

关键项：

| 键 | 默认 | 说明 |
|---|---|---|
| `wifi.ifname` | `wlan0` | 不要填 p2p0 |
| `wifi.connect.sae_policy` | `psk_first` | 因实测 SAE 握手不通 |
| `wifi.connect.settle_sec` | `8` | 因密码错误时 nmcli 可能返回 rc=0 |
| `daemon.active_profile` | `""` | 空 = 用当前活跃的 |
| `daemon.dry_run` | **`true`** | ★首次部署保持 true 观察，确认后再关 |

---

## 七、日常运维

```bash
# 状态 / 日志
systemctl status wifimgr
journalctl -u wifimgr -f
tail -f /var/log/nginx/wifimgr.error.log

# 命令行
cd /opt/wifimgr
PYTHONPATH=/opt/wifimgr python3 -B -m wifimgr status
PYTHONPATH=/opt/wifimgr python3 -B -m wifimgr scan
PYTHONPATH=/opt/wifimgr python3 -B -m wifimgr doctor
PYTHONPATH=/opt/wifimgr python3 -B -m wifimgr connect --ssid <SSID> --ask-pass
PYTHONPATH=/opt/wifimgr python3 -B -m wifimgr selftest

# 关闭 dry-run（确认守护行为正确后）
sed -i 's/"dry_run": true/"dry_run": false/' /etc/wifimgr.json
systemctl restart wifimgr

# 处理遗留 RD08_IoT
nmcli con mod RD08_IoT connection.autoconnect no
```

SSH 别名（避免每次都被 OpenSSH 后量子 KEX 横幅刷屏）：

```bash
alias nas='ssh -i ~/.ssh/id_ed25519_nas -o BatchMode=yes -o LogLevel=ERROR root@192.168.31.47'
```

---

## 八、部署与回滚

安装脚本是幂等的，每步都有断言，覆盖前自动 `.bak-YYYYMMDD` 备份：

```bash
cd /opt/wifimgr
bash deploy/install.sh --dry-run     # 先看会做什么
bash deploy/install.sh
```

回滚：

```bash
bash /opt/wifimgr/deploy/rollback.sh          # 交互确认
bash /opt/wifimgr/deploy/rollback.sh --yes    # 直接执行
```

会还原：nginx 片段、systemd unit、旧 cron 与 `wifi-check.sh` 权限、
`RD08_IoT` 的 autoconnect。数据库默认保留。

> 旧 watchdog 只**停用**不删除：`/etc/cron.d/wifi-check` 加 `# disabled-by-wifimgr`
> 前缀，脚本本体改成 0750。回滚时去前缀 + 恢复 0755。

---

## 九、异常处理

| 场景 | 行为 |
|---|---|
| nmcli 超时 | `killpg` 杀进程组；扫描退回上次缓存并标 `stale` |
| D-Bus 超时 / NM 无响应 | 不重试（无用），退避后继续 |
| 密码错误 | 归入 `accepted_but_handshake_failed`，提示核对密码；不无限重试 |
| SAE 握手失败 | 自动降级 wpa-psk，并明确说明「驱动限制，非密码错误」 |
| AP 连接中途消失 | 识别 `ssid-not-found`，提示重新扫描，不降级 key_mgmt |
| wlan0 忙 | 全局锁排队（深度 1 + 5s 超时），返回 `BUSY` |
| rescan 限速 | 距上次 < `min_interval_sec` 返回 429 + `retry_after`，前端倒计时 |
| NM 正在 activating | settle 宽限期内**不插手**（抢进去会打断四次握手） |
| 抖动频繁 | 滑动窗口超阈值 → 暂停自动重连，防止刷死 AP |
| 磁盘只读/满 | 事件落库失败只记一次（防日志风暴）→ 仍可扫描/看状态 |
| 配置被 NM 拒 | 抛出并附**脱敏后**原文；可选 key（pmf）分级降级重试 |
| 守护抢不到 flock | 另一个实例在跑，本实例安静退出（不是错误） |

连接结果分四档，UI 用颜色区分：

| phase | 含义 |
|---|---|
| `activated` | 成功且拿到 IP |
| `accepted_but_handshake_failed` | 配置写入了但没握手成功（**橙色**，多半是密码） |
| `rejected` | NM 拒绝了配置（**红色**，是兼容问题不是密码） |
| `timeout` / `busy` | 超时或设备忙，交给守护重试 |

---

## 十、已知限制

1. **WPA3/SAE 不可用**（硬件限制，见上文事实 7）。换驱动后才可能支持。
2. **信号强度依赖 `iw`**。unit 里 `RestrictAddressFamilies` 必须含 `AF_NETLINK`，
   否则 `iw` 静默失败、信号显示为空。
3. **切 WiFi 不会失联**：`192.168.31.47` 在 **eth0** 且 eth0 是 unmanaged，
   默认路由走 eth0。NM 只重建 wlan0。已实测确认。
4. **无登录页**：只监听 127.0.0.1 + nginx，局域网内可信。CSRF 仍启用。
   若将来要暴露到更大范围，需加访问令牌（配置里预留了扩展点）。
5. **重装 rootfs 或换驱动后**：需重跑 `probe-sae` 确认 WPA3 是否可用，
   并把 `sae_policy` 调整为 `force_sae` 或恢复 `psk_first`。

---

## 十一、部署文档（全新安装必读）

### 11.1 前置条件

| 项 | 要求 | 检查命令 |
|---|---|---|
| 权限 | root | `id -u` 应为 0 |
| Python | ≥ 3.7（需 `ThreadingHTTPServer`），实测 3.8.10 | `python3 -V` |
| NetworkManager | 1.16+（1.22.10 实测） | `nmcli --version` |
| `iw` | 必需，否则信号强度显示为空 | `command -v iw` |
| init | systemd | `cat /proc/1/comm` |
| nginx | 建议（不用也能跑，直连 127.0.0.1:8791） | `nginx -v` |
| 闪存 | 无要求 | `bash tools/emmc-audit.sh` |

本机实测环境：海思 Hi3798MV100 / Ubuntu 20.04.6 / 内核 `4.4.35_ecoo` /
NM 1.22.10 / wpa_supplicant 2.9 / rtl8188fu USB WiFi / eMMC 7.3G / 931MB RAM。

### 11.2 安装步骤

```bash
# 1. 拿到代码
git clone https://github.com/zhang-astronaut/nas-wifimgr.git
cd nas-wifimgr

# 2. 干跑：只检查不改动，确认前置条件与将要做的操作
bash deploy/install.sh --dry-run

# 3. 实装（幂等，可重复执行）
bash deploy/install.sh
```

安装脚本会依次完成：前置检查 → 备份旧文件（`.bak-YYYYMMDD`）→ 停用旧 watchdog
→ 部署代码 → 环境自检 → 离线单测 → 装 systemd unit → 装 nginx 片段并
`nginx -t` 后 **reload（不 restart）** → 启动服务 → 接口断言。

任何一步断言失败都会停下并打印可读原因，**不会留下半安装状态**。

### 11.3 安装后必须手动做的事

**① 确认守护行为（重要）**

首次安装 `daemon.dry_run=true`，守护**只探测不动作**。观察一两天：

```bash
journalctl -u wifimgr -f
```

确认无误后关闭：

```bash
sed -i 's/"dry_run": true/"dry_run": false/' /etc/wifimgr.json
systemctl restart wifimgr
```

**② 处理遗留的失效 profile**

如果存在指向**已不存在的 SSID** 的 profile（例如换过 SSID 名的 AP），
它会一直重试并每次白等 25 秒，还会抢在真实连接前面：

```bash
nmcli -t -f NAME,TYPE con show                    # 列出所有 profile
nmcli con mod <失效profile名> connection.autoconnect no
```

**③ 建议：限制 journald（见上文 eMMC 评估）**

```bash
mkdir -p /etc/systemd/journald.conf.d
cp deploy/journald-limit.conf /etc/systemd/journald.conf.d/wifimgr-limit.conf
systemctl restart systemd-journald
journalctl --vacuum-size=200M
```

### 11.4 目录与文件

| 路径 | 用途 | 备份建议 |
|---|---|---|
| `/opt/wifimgr/` | 程序本体 | 可随时从 git 重建 |
| `/etc/wifimgr.json` | 配置（JSONC） | **建议备份** |
| `/etc/systemd/system/wifimgr.service` | 服务单元 | 可从 `deploy/` 重建 |
| `/etc/nginx/locations.d/wifimgr.conf` | 反代片段 | 可从 `deploy/` 重建 |
| `/etc/NetworkManager/system-connections/*.nmconnection` | **WiFi 密码**（0600 root） | ⚠️ 含密码，谨慎备份 |
| `/var/lib/wifimgr/wifimgr.db` | SQLite（**不含密码**） | 建议备份 |
| `/var/lib/wifimgr/keyfile-snapshots/` | 覆盖前的 keyfile 备份（留 20 份） | 可清理 |
| `/run/wifimgr/` | 临时凭据（tmpfs，**不落盘**） | 无需备份 |

> 数据库可随时清空重建（只存"我认识哪些网络"）。真正的凭据在 NM keyfile 里。

### 11.5 卸载与回滚

```bash
# 交互式回滚（还原 nginx/unit/旧 cron/autoconnect，数据库保留）
bash /opt/wifimgr/deploy/rollback.sh

# 静默回滚
bash /opt/wifimgr/deploy/rollback.sh --yes

# 回滚并删除程序本体（数据库仍保留）
bash /opt/wifimgr/deploy/rollback.sh --yes --purge
```

回滚会：停止服务 → 还原或移除 nginx 片段（并 `nginx -t` + reload）→
移除 unit → 恢复旧 `wifi-check.sh` 的 cron 与权限 → 恢复 profile 的 autoconnect。

若要彻底清理（**会删除已保存的网络记录**）：

```bash
rm -rf /var/lib/wifimgr        # 数据库 + 快照
rm /etc/wifimgr.json
# 各 WiFi profile 需单独决定是否删除
```

### 11.6 安全注意事项

**密码存储模型**

```
密码  →  只写入 /etc/NetworkManager/system-connections/<profile>.nmconnection
        权限 0600 root:root，是 NetworkManager 自己的标准存放位置

应用数据库  →  /var/lib/wifimgr/wifimgr.db，**无任何密码列**
              （saved_network 只记 profile_name/ssid/key_mgmt；
                profile_ref 只有一个 has_psk 布尔标记）
```

**已实测验证**：连接成功后扫描全机 `/proc/*/cmdline`，密码**零出现**。
`tests/test_security.py` 与 `tests/test_no_secrets.py` 把这条约束固化为
可执行断言（含"源码不得出现真实口令字面量"）。

**若要暴露到公网或不可信网络，必须先加访问令牌。** 当前设计假设局域网可信：

- 只监听 `127.0.0.1:8791`，由 nginx 反代
- CSRF 已启用（双提交 token + `SameSite=Strict` + Origin 校验）
- **但没有登录页** —— 局域网内任何能访问该端口的设备都能切换 WiFi

### 11.7 排障速查

| 现象 | 排查 |
|---|---|
| 面板打不开 | `systemctl status wifimgr`；`curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8791/api/v1/status` |
| 页面无样式/脚本 | `nginx -t` 后 `systemctl reload nginx`；检查 `/etc/nginx/locations.d/wifimgr.conf` 存在 |
| 扫描不到网络 | 确认 `wifi.ifname` 是 `wlan0`（不是 `p2p0`）；`nmcli dev wifi list ifname wlan0` 手动验证 |
| 信号强度空白 | `iw` 是否可用；unit 里 `RestrictAddressFamilies` 是否含 `AF_NETLINK` |
| 连接总是失败 | 看 `phase` 字段：`accepted_but_handshake_failed` 多半是密码错；`rejected` 是兼容问题 |
| 遮罩关不掉 | Ctrl+F5 强刷缓存；旧版 CSS 缺 `[hidden]{display:none!important}` 兜底 |
| 「已保存的网络」为空 | 确认连接时勾了「保存」；`journalctl -u wifimgr | grep remember` 看有无报错 |
| 守护不动作 | 是否仍是 `dry_run=true`；`curl -s http://127.0.0.1:8791/api/v1/daemon \| python3 -m json.tool` |
| 旧脚本同时在跑 | `grep -v '^#' /etc/cron.d/wifi-check` 应无输出 |

一键自检：

```bash
PYTHONPATH=/opt/wifimgr python3 -B -m wifimgr --config /etc/wifimgr.json doctor
PYTHONPATH=/opt/wifimgr python3 -B -m wifimgr selftest    # 190 项离线测试
bash /opt/wifimgr/tools/emmc-audit.sh                     # 闪存写入审计
```

### 11.8 SSH 使用提示

这台机器每次 SSH 连接都会打印 OpenSSH 后量子 KEX 的 WARNING 横幅，干扰脚本解析。
建议加别名：

```bash
# ~/.bashrc
alias nas='ssh -i ~/.ssh/id_ed25519_nas -o BatchMode=yes -o LogLevel=ERROR root@192.168.31.47'
```

**大段脚本一律 `scp` 过去再执行，不要内联**。cmd → ssh 转义的坑：
双引号内不能出现 `\"`；远端单引号内 `$()` 无需反斜杠；cmd 不展开 `$`。

### 11.9 换设备 / 重装系统后

1. 重新 clone 本仓库
2. `bash deploy/install.sh --dry-run` 确认前置条件
3. **重跑 SAE 探测**（新机器驱动可能不同）：

```bash
PYTHONPATH=. python3 -B -m wifimgr probe-sae              # 仅配置层
PYTHONPATH=. python3 -B -m wifimgr probe-sae --handshake --ssid <SSID> --password <PW>
```

若握手可用，把 `sae_policy` 改为 `force_sae` 或 `psk_first`（混合 AP 用后者）；
若仍不可用，保持 `psk_first`。

4. 按 11.3 重新设置 `dry_run=false` 与处理失效 profile
5. 建议重新执行 `tools/emmc-audit.sh` 取得新机器的写入基线
