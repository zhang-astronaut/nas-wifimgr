/* WiFi Manager 前端（原生 JS，无框架）。
 *
 * 注意：nginx 反代到 /wifi/ 前缀，服务内部路由不带前缀，所以这里用相对路径。
 * 若直连 127.0.0.1:8791 调试，需要把 PREFIX 改成 ''。
 */
(function () {
  "use strict";

  var PREFIX = "/wifi";
  var API = PREFIX + "/api/v1";

  var state = {
    csrf: null,
    caps: null,
    status: null,
    lastScan: null,
    connectTarget: null,
    scanBusy: false,
    pollTimer: null,
  };

  // ---------------- HTTP ----------------

  function getCookie(name) {
    var m = document.cookie.match(new RegExp("(?:^|; )" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=([^;]*)"));
    return m ? decodeURIComponent(m[1]) : "";
  }

  function api(method, path, body) {
    var opts = {
      method: method,
      headers: { "Accept": "application/json" },
      credentials: "same-origin",
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    if (method !== "GET" && state.csrf) {
      opts.headers["X-CSRF-Token"] = state.csrf;
    }
    return fetch(API + path, opts).then(function (resp) {
      return resp.text().then(function (txt) {
        var data = null;
        try { data = txt ? JSON.parse(txt) : null; } catch (e) { data = null; }
        if (!resp.ok) {
          var err = (data && data.error) || { message: "HTTP " + resp.status, code: "HTTP_" + resp.status };
          var e = new Error(err.message || "请求失败");
          e.code = err.code;
          e.detail = err;
          e.status = resp.status;
          throw e;
        }
        return data && data.data;
      });
    });
  }

  // ---------------- UI helpers ----------------

  function $(id) { return document.getElementById(id); }

  /* 遮罩必须「保险式」关闭：任何异常路径（含 fetch 抛错、超时、页面报错）
     都不能把用户永久困在遮罩里。除了 .hidden，同时清掉 inline style 与 class，
     并用一个递增的 token 让旧请求的回调无法再改遮罩。 */
  var overlayToken = 0;
  function showOverlay(text) {
    overlayToken++;
    $("overlayText").textContent = text || "处理中…";
    $("overlay").hidden = false;
    $("overlay").style.display = "";
    $("overlay").dataset.shownAt = String(Date.now());
    return overlayToken;
  }
  function hideOverlay(token) {
    // token 传入时表示「只关闭自己这次打开的遮罩」，避免旧请求误关新的
    if (token !== undefined && token !== overlayToken) return false;
    var el = $("overlay");
    el.hidden = true;
    el.style.display = "none";
    el.dataset.shownAt = "";
    return true;
  }

  /* fetch 超时包装。原生 fetch 没有超时，连接请求在慢 AP 上可能挂很久，
     甚至后端异常时永远不返回。没有超时用户就只能干等。 */
  function apiWithTimeout(method, path, body, timeoutMs) {
    var ctrl = (typeof AbortController !== "undefined") ? new AbortController() : null;
    var opts = {
      method: method,
      headers: { "Accept": "application/json" },
      credentials: "same-origin",
      signal: ctrl ? ctrl.signal : undefined
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    if (method !== "GET" && state.csrf) {
      opts.headers["X-CSRF-Token"] = state.csrf;
    }
    var timer = null;
    var p = fetch(API + path, opts);
    if (ctrl) {
      timer = setTimeout(function () { ctrl.abort(); }, timeoutMs || 120000);
    }
    return p.then(function (resp) {
      return resp.text().then(function (txt) {
        var data = null;
        try { data = txt ? JSON.parse(txt) : null; } catch (e) { data = null; }
        if (!resp.ok) {
          var err = (data && data.error) || { message: "HTTP " + resp.status, code: "HTTP_" + resp.status };
          var e = new Error(err.message || "请求失败");
          e.code = err.code;
          e.detail = err;
          e.status = resp.status;
          throw e;
        }
        return data && data.data;
      });
    }).catch(function (err) {
      if (err && err.name === "AbortError") {
        var te = new Error("请求超时，后端可能仍在操作。可稍后点『刷新』查看当前状态。");
        te.code = "CLIENT_TIMEOUT";
        throw te;
      }
      throw err;
    }).then(function (v) {
      if (timer) clearTimeout(timer);
      return v;
    }, function (e) {
      if (timer) clearTimeout(timer);
      throw e;
    });
  }

  function esc(s) {
    return String(s === null || s === undefined ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function toast(msg, kind) {
    var el = document.createElement("div");
    el.className = "toast" + (kind ? " " + kind : "");
    el.textContent = msg;
    $("toasts").appendChild(el);
    setTimeout(function () {
      el.style.opacity = "0";
      setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 300);
    }, kind === "err" ? 6500 : 3200);
  }

  // 信号强度条：4 格
  function barsHtml(signal) {
    // signal 是 dBm（-100..-30），来自 iw
    var level = 0;
    if (signal !== null && signal !== undefined) {
      if (signal >= -55) level = 4;
      else if (signal >= -67) level = 3;
      else if (signal >= -75) level = 2;
      else if (signal >= -85) level = 1;
    }
    var cls = ["", "weak", "mid", ""];
    var h = "";
    for (var i = 1; i <= 4; i++) {
      var on = i <= level ? " on" + (cls[i] ? " " + cls[i] : "") : "";
      h += '<i class="' + on.trim() + '" style="height:' + (5 + i * 4) + 'px"></i>';
    }
    return '<span class="bars">' + h + "</span>";
  }

  function securityBadge(sec, authKind) {
    var s = (sec || "").toLowerCase();
    if (s === "open" || s === "") {
      // 本机实测：开放网络在 WPA 过渡环境里常是同路由的隐藏 SSID，标注清楚
      return '<span class="badge open">开放</span>';
    }
    if (authKind === "mixed") {
      return '<span class="badge wpa3">WPA2/3 混合 · 用WPA2</span>';
    }
    if (s.indexOf("wpa3") >= 0 && s.indexOf("wpa2") < 0) {
      return '<span class="badge wpa3">WPA3 · 本机不支持</span>';
    }
    if (s.indexOf("wpa2") >= 0) return '<span class="badge">WPA2</span>';
    if (s.indexOf("wpa1") >= 0) return '<span class="badge">WPA1</span>';
    if (s.indexOf("wep") >= 0) return '<span class="badge">WEP</span>';
    return '<span class="badge">' + esc(sec) + "</span>";
  }

  // ---------------- 渲染 ----------------

  function renderStatus(st, guardian) {
    state.status = st;
    var chip = $("statusChip"), text = $("statusText");
    if (st.connected) {
      chip.dataset.state = "ok";
      text.textContent = (st.ssid || st.profile_name || "已连接") + " · " + (st.ip || "");
    } else {
      chip.dataset.state = st.state && st.state.indexOf("connecting") >= 0 ? "warn" : "err";
      text.textContent = st.state || "未连接";
    }

    var rows = [
      ["状态", st.state || "未知"],
      ["SSID", st.ssid || "—"],
      ["profile", st.profile_name || "—"],
      ["BSSID", st.bssid || "—"],
      ["IP", st.ip || "—"],
      ["信号", st.signal !== null && st.signal !== undefined ? st.signal + " dBm" : "—"],
      ["判定来源", st.source + "（可信度 " + Math.round((st.confidence || 0) * 100) + "%）"]
    ];
    if (guardian) {
      rows.push(["守护", guardian.running ? "运行中" : "未运行"]);
      rows.push(["循环次数", guardian.cycles]);
      if (guardian.last_ok_at) {
        rows.push(["最近成功", new Date(guardian.last_ok_at * 1000).toLocaleTimeString()]);
      }
      if (guardian.consecutive_failures) {
        rows.push(["连续失败", guardian.consecutive_failures]);
      }
      if (guardian.flapping) rows.push(["抖动", "是，已暂停自动重连"]);
    }
    $("statusBody").innerHTML = rows.map(function (r) {
      return "<dt>" + esc(r[0]) + "</dt><dd>" + esc(r[1]) + "</dd>";
    }).join("");
  }

  function renderScan(data) {
    state.lastScan = data;
    var ul = $("netList");
    if (!data.items || !data.items.length) {
      ul.innerHTML = '<li class="muted pad">未发现网络</li>';
    } else {
      ul.innerHTML = data.items.map(function (n, i) {
        var sub = [];
        sub.push(n.bssid ? n.bssid.slice(-6) : "");
        if (n.freq) sub.push(n.freq);
        if (n.signal !== null && n.signal !== undefined) sub.push(n.signal + " dBm");
        return '<li class="net" data-i="' + i + '">' +
          barsHtml(n.signal) +
          '<div class="meta"><div class="ssid">' + esc(n.display) + "</div>" +
          '<div class="sub"><span>' + esc(sub.filter(Boolean).join(" · ")) + "</span></div></div>" +
          securityBadge(n.security, n.auth_kind) +
          (n.saved ? '<span class="badge saved">已存</span>' : "") +
          (n.in_use ? '<span class="badge on">已连接</span>' : "") +
          "</li>";
      }).join("");
      Array.prototype.forEach.call(ul.querySelectorAll(".net"), function (li) {
        li.addEventListener("click", function () {
          openPassword(state.lastScan.items[Number(li.dataset.i)]);
        });
      });
    }

    var meta = "共 " + (data.items ? data.items.length : 0) + " 个网络";
    if (data.age_sec !== null && data.age_sec !== undefined) meta += " · " + data.age_sec + " 秒前扫描";
    if (data.stale) meta += " · <span class='err'>本次扫描失败，显示的是缓存结果</span>";
    $("scanMeta").innerHTML = meta;
  }

  function renderSaved(items) {
    var ul = $("savedList");
    if (!items.length) {
      ul.innerHTML = '<li class="muted pad">还没有保存的网络</li>';
      return;
    }
    ul.innerHTML = items.map(function (n) {
      var sub = [];
      sub.push(n.key_mgmt === "sae" ? "WPA3(SAE)" : n.key_mgmt === "wpa-psk" ? "WPA2" : n.key_mgmt);
      if (n.connect_count) sub.push("已连 " + n.connect_count + " 次");
      if (n.last_result && n.last_result !== "activated") sub.push("上次: " + n.last_result);
      return '<li class="net" data-p="' + esc(n.profile_name) + '">' +
        '<div class="meta"><div class="ssid">' + esc(n.ssid) + "</div>" +
        '<div class="sub">' + esc(sub.join(" · ")) + "</div></div>" +
        '<span class="btn ghost sm" data-act="conn">连接</span>' +
        '<span class="btn ghost sm" data-act="del">删除</span>' +
        "</li>";
    }).join("");
    Array.prototype.forEach.call(ul.querySelectorAll(".net"), function (li) {
      var name = li.dataset.p;
      var conn = li.querySelector('[data-act="conn"]');
      var del = li.querySelector('[data-act="del"]');
      if (conn) conn.addEventListener("click", function (e) { e.stopPropagation(); reconnect(name); });
      if (del) del.addEventListener("click", function (e) { e.stopPropagation(); removeNetwork(name); });
    });
  }

  function renderDaemon(d) {
    var c = d.config || {}, r = d.runtime || {};
    $("daemonBody").innerHTML =
      '<div class="row"><input type="checkbox" id="dEnabled"' + (c.enabled ? " checked" : "") + ">" +
      "<span>启用守护保活</span></div>" +
      '<div class="grid2">' +
      '<div class="field"><label>检测间隔（秒）</label><input type="number" id="dInterval" min="5" value="' + (c.interval_sec || 60) + '"></div>' +
      '<div class="field"><label>最大重试次数</label><input type="number" id="dRetries" min="0" value="' + (c.max_retries || 0) + '"></div>' +
      '<div class="field"><label>退避基数（秒）</label><input type="number" id="dBase" min="1" value="' + ((c.backoff || {}).base_sec || 5) + '"></div>' +
      '<div class="field"><label>退避上限（秒）</label><input type="number" id="dCap" min="1" value="' + ((c.backoff || {}).cap_sec || 300) + '"></div>' +
      '<div class="field"><label>抖动比例</label><input type="number" id="dJitter" min="0" max="1" step="0.05" value="' + ((c.backoff || {}).jitter || 0.2) + '"></div>' +
      '<div class="field"><label>宽限期（秒）</label><input type="number" id="dSettle" min="0" value="' + (c.settle_grace_sec || 20) + '"></div>' +
      "</div>" +
      '<label class="row"><input type="checkbox" id="dDry"' + (c.dry_run ? " checked" : "") + ">" +
      "<span>dry-run（只探测不动作）</span></label>" +
      '<p class="muted small">运行中：' + (r.running ? "是" : "否") +
      " · 循环 " + (r.cycles || 0) + " 次" +
      " · 锁 " + (r.lock_held ? "已持有" : "未持有") +
      (r.next_check_in !== undefined && r.next_check_in !== null ? " · 下次检查 " + r.next_check_in + "s 后" : "") +
      "</p>";
  }

  function renderEvents(items) {
    var ul = $("eventList");
    if (!items.length) { ul.innerHTML = '<li class="muted pad">暂无</li>'; return; }
    ul.innerHTML = items.slice(0, 20).map(function (e) {
      return "<li><span class='lvl " + esc(e.level) + "'>" + esc(e.level) + "</span>" +
        "<span class='ev-time'>" + new Date(e.ts * 1000).toLocaleTimeString() + "</span>" +
        "<span>" + esc(e.source) + " · " + esc(e.message) + "</span></li>";
    }).join("");
  }

  function renderDoctor(checks) {
    $("doctorList").innerHTML = checks.map(function (c) {
      return "<li><span class='" + (c.ok ? "ok" : "no") + "'>" + (c.ok ? "✓" : "✗") + "</span>" +
        "<span><b>" + esc(c.name) + "</b> — " + esc(c.detail || "") + "</span></li>";
    }).join("");
  }

  // ---------------- 动作 ----------------

  function openPassword(net) {
    state.connectTarget = net;
    $("pwdTitle").textContent = "连接到 " + net.display;
    $("pwdSSID").textContent = (net.bssid || "") + (net.hidden ? " · 隐藏网络" : "");
    $("pwdErr").hidden = true;
    $("pwdInput").value = "";
    $("pwdRemember").checked = true;
    $("pwdLockBssid").checked = false;
    $("pwdModal").hidden = false;
    $("pwdModal").style.display = "";
    setTimeout(function () { $("pwdInput").focus(); }, 30);
  }

  function closePassword() {
    state.connectTarget = null;
    var el = $("pwdModal");
    el.hidden = true;
    el.style.display = "none";
  }

  function submitPassword(ev) {
    ev.preventDefault();
    var net = state.connectTarget;
    if (!net) return;
    var pw = $("pwdInput").value;
    var errEl = $("pwdErr");

    // 开放网络不需要密码
    var needPw = net.auth_kind !== "open" && net.security !== "open";
    if (needPw && !pw) {
      errEl.textContent = "该网络是加密的，请输入密码";
      errEl.hidden = false;
      return;
    }

    var payload = {
      ssid: net.ssid,
      bssid: net.bssid,
      password: needPw ? pw : null,
      auth_kind: net.auth_kind,
      remember: $("pwdRemember").checked,
      bssid_lock: $("pwdLockBssid").checked,
      // 实测：本机 SAE 握手必失败，混合 AP 一律用 WPA2
      sae_policy: "psk_first",
    };

    closePassword();
    var myToken = showOverlay("正在切换到 " + net.display + " …");
    $("btnScan").disabled = true;

    // 连接在慢 AP 上可达 60s+（command_timeout_sec 60 + settle 8），
    // 客户端再给 90s 余量；超时后遮罩必须自动收起。
    var remember = $("pwdRemember").checked;
    apiWithTimeout("POST", "/connect", payload, 90000).then(function (d) {
      hideOverlay(myToken);
      toast("已连接到 " + (d.result.ssid || net.ssid), "ok");
      // 后端在勾选「保存」时会把网络写进 saved_network，
      // 这里必须刷新列表，否则用户看不到刚保存的网络。
      loadSaved();
      refreshStatus(); scan();
      // 后端保存失败时会带回 warning，明确告诉用户，别让列表默默为空。
      var rw = d.result && d.result.detail && d.result.detail.remember_warning;
      if (rw) toast(rw, "err");
      else if (remember) {
        toast("已保存，可在「已保存的网络」里一键切换。", "ok");
      }
    }).catch(function (e) {
      hideOverlay(myToken);
      var msg = e.message || "连接失败";
      if (e.code === "CLIENT_TIMEOUT") {
        msg = "连接请求超时。后端可能仍在尝试，请点『刷新』看当前状态。";
      } else if (e.code === "accepted_but_handshake_failed" ||
          (e.detail && e.detail.result && e.detail.result.phase === "accepted_but_handshake_failed")) {
        var detail = (e.detail && e.detail.result) || {};
        msg = (detail.message || msg) + " 建议：核对密码；WPA3 网络本机驱动无法握手，请改用 WPA2 的 SSID。";
      }
      toast(msg, "err");
      refreshStatus();
    }).then(function () {
      $("btnScan").disabled = false;
    });
  }

  function reconnect(profileName) {
    var myToken = showOverlay("正在重连 " + profileName + " …");
    apiWithTimeout("POST", "/networks/" + encodeURIComponent(profileName) + "/connect", {}, 90000)
      .then(function () {
        hideOverlay(myToken);
        toast("已连接", "ok");
        refreshStatus();
      }).catch(function (e) {
        hideOverlay(myToken);
        toast((e.detail && e.detail.result && e.detail.result.message) || e.message, "err");
      });
  }

  function removeNetwork(profileName) {
    if (!confirm("删除已保存的 " + profileName + "？（仅删除记录，不动系统里的密码）")) return;
    api("DELETE", "/networks/" + encodeURIComponent(profileName), {}).then(function () {
      toast("已删除", "ok");
      loadSaved();
    }).catch(function (e) { toast(e.message, "err"); });
  }

  function saveDaemon() {
    var payload = {
      enabled: $("dEnabled").checked,
      interval_sec: Number($("dInterval").value) || 60,
      max_retries: Number($("dRetries").value) || 0,
      settle_grace_sec: Number($("dSettle").value) || 20,
      dry_run: $("dDry").checked,
      backoff: {
        base_sec: Number($("dBase").value) || 5,
        cap_sec: Number($("dCap").value) || 300,
        jitter: Number($("dJitter").value) || 0
      }
    };
    api("PUT", "/daemon", payload).then(function () {
      toast("守护配置已保存", "ok");
      loadDaemon();
    }).catch(function (e) { toast(e.message, "err"); });
  }

  // ---------------- 加载 ----------------

  function refreshStatus() {
    return api("GET", "/status").then(function (d) {
      renderStatus(d.status, d.guardian);
    }).catch(function (e) {
      $("statusChip").dataset.state = "err";
      $("statusText").textContent = "服务不可达";
    });
  }

  function scan() {
    if (state.scanBusy) return Promise.resolve();
    state.scanBusy = true;
    return api("POST", "/scan", {}).then(function (d) {
      renderScan(d);
    }).catch(function (e) {
      if (e.code === "RATE_LIMITED") {
        var wait = (e.detail && e.detail.detail && e.detail.detail.retry_after) || 5;
        $("scanMeta").innerHTML = "扫描过于频繁，" + wait + " 秒后可重试";
        setTimeout(scan, (wait + 1) * 1000);
      } else {
        toast(e.message, "err");
      }
    }).then(function () { state.scanBusy = false; });
  }

  function loadSaved() {
    return api("GET", "/networks").then(function (d) { renderSaved(d.items || []); })
      .catch(function () {});
  }
  function loadDaemon() {
    return api("GET", "/daemon").then(function (d) { renderDaemon(d); }).catch(function () {});
  }
  function loadEvents() {
    return api("GET", "/events?limit=20").then(function (d) { renderEvents(d.items || []); })
      .catch(function () {});
  }
  function runDoctor() {
    return api("GET", "/doctor").then(function (d) { renderDoctor(d.checks || []); })
      .catch(function (e) { toast(e.message, "err"); });
  }

  function poll() {
    clearInterval(state.pollTimer);
    state.pollTimer = setInterval(function () {
      if ($("overlay").hidden) { refreshStatus(); loadEvents(); }
    }, 3000);

    // 兜底看门狗：任何原因导致遮罩没被收起（例如回调被吞、JS 异常），
    // 最多 100 秒后强制收起并提示，绝不让用户被永久困住。
    setInterval(function () {
      var el = $("overlay");
      if (el.hidden || !el.dataset.shownAt) return;
      var age = Date.now() - Number(el.dataset.shownAt);
      if (age > 100000) {
        hideOverlay();
        toast("操作耗时过长，已解除遮罩。请点『刷新』确认当前状态。", "err");
        $("btnScan").disabled = false;
      }
    }, 5000);
  }

  function boot() {
    api("GET", "/session").then(function (d) {
      state.csrf = d.csrf || getCookie("wifimgr_csrf");
      if (state.caps === null) {
        api("GET", "/capabilities").then(function (c) { state.caps = c; }).catch(function () {});
      }
      refreshStatus();
      scan();
      loadSaved();
      loadDaemon();
      loadEvents();
      poll();
    }).catch(function (e) {
      $("statusChip").dataset.state = "err";
      $("statusText").textContent = "无法连接服务：" + (e.message || e);
    });
  }

  // ---------------- 绑定 ----------------

  document.addEventListener("DOMContentLoaded", function () {
    $("btnScan").addEventListener("click", scan);
    $("btnRefreshStatus").addEventListener("click", refreshStatus);
    $("btnSaveDaemon").addEventListener("click", saveDaemon);
    $("btnDoctor").addEventListener("click", runDoctor);
    $("pwdForm").addEventListener("submit", submitPassword);
    Array.prototype.forEach.call(document.querySelectorAll("[data-close]"), function (el) {
      el.addEventListener("click", closePassword);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key !== "Escape") return;
      if (!$("pwdModal").hidden) { closePassword(); return; }
      // 遮罩是纯提示层，Esc 直接解除（后端操作会继续跑完）
      if (!$("overlay").hidden) {
        hideOverlay();
        $("btnScan").disabled = false;
        toast("已解除遮罩，后端操作仍在继续。点『刷新』查看结果。");
      }
    });
    boot();
  });
})();
