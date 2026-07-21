const form = document.querySelector("#configForm");
const message = document.querySelector("#message");
const statusText = document.querySelector("#statusText");
const statsText = document.querySelector("#statsText");
const jobIdText = document.querySelector("#jobIdText");
const logBox = document.querySelector("#logBox");
const startBtn = document.querySelector("#startBtn");
const stopBtn = document.querySelector("#stopBtn");
const refreshAccountsBtn = document.querySelector("#refreshAccountsBtn");
const checkHealthBtn = document.querySelector("#checkHealthBtn");
const importGrok2apiBtn = document.querySelector("#importGrok2apiBtn");
const importSub2apiBtn = document.querySelector("#importSub2apiBtn");
const probeSub2apiBtn = document.querySelector("#probeSub2apiBtn");
const deleteSub2apiRemoteBtn = document.querySelector("#deleteSub2apiRemoteBtn");
const importCpaBtn = document.querySelector("#importCpaBtn");
const exportAccountsBtn = document.querySelector("#exportAccountsBtn");
const deleteAccountsBtn = document.querySelector("#deleteAccountsBtn");
const cfGlobalTestBtn = document.querySelector("#cfGlobalTestBtn");
const cfGlobalZonesBtn = document.querySelector("#cfGlobalZonesBtn");
const cfGlobalEmailDnsBtn = document.querySelector("#cfGlobalEmailDnsBtn");
const cfGlobalStatus = document.querySelector("#cfGlobalStatus");
const webhookRefreshBtn = document.querySelector("#webhookRefreshBtn");
const webhookSelfTestBtn = document.querySelector("#webhookSelfTestBtn");
const webhookClearBtn = document.querySelector("#webhookClearBtn");
const webhookCopyUrlBtn = document.querySelector("#webhookCopyUrlBtn");
const webhookCopyCurlBtn = document.querySelector("#webhookCopyCurlBtn");
const cfDeployWorkerBtn = document.querySelector("#cfDeployWorkerBtn");
const cfSetupCatchAllBtn = document.querySelector("#cfSetupCatchAllBtn");
const webhookChecks = document.querySelector("#webhookChecks");
const webhookSuggestedUrl = document.querySelector("#webhookSuggestedUrl");
const webhookFullUrl = document.querySelector("#webhookFullUrl");
const webhookPanelDetail = document.querySelector("#webhookPanelDetail");
const webhookActionStatus = document.querySelector("#webhookActionStatus");
let webhookPanelCache = null;

function setWebhookActionStatus(text, tone = "") {
  if (!webhookActionStatus) return;
  webhookActionStatus.textContent = text || "";
  webhookActionStatus.style.color =
    tone === "error" ? "var(--danger, #fb7185)" : tone === "ok" ? "var(--accent, #6ee7b7)" : "";
}
const exportFmtNative = document.querySelector("#exportFmtNative");
const exportFmtGrok2api = document.querySelector("#exportFmtGrok2api");
const exportFmtSub2api = document.querySelector("#exportFmtSub2api");
const exportFmtCpa = document.querySelector("#exportFmtCpa");
const dashboardStatusText = document.querySelector("#dashboardStatusText");
const dashboardRunNote = document.querySelector("#dashboardRunNote");
const dashboardTotalAccounts = document.querySelector("#dashboardTotalAccounts");
const dashboardRefreshAccounts = document.querySelector("#dashboardRefreshAccounts");
const dashboardHealthyAccounts = document.querySelector("#dashboardHealthyAccounts");
const dashboardNeedActionAccounts = document.querySelector("#dashboardNeedActionAccounts");
const dashboardPipeline = document.querySelector("#dashboardPipeline");
const dashboardHealthMix = document.querySelector("#dashboardHealthMix");
const dashboardPushMix = document.querySelector("#dashboardPushMix");
const dashboardSources = document.querySelector("#dashboardSources");
const warAlerts = document.querySelector("#warAlerts");
const warFailMix = document.querySelector("#warFailMix");
const warDomainHeat = document.querySelector("#warDomainHeat");
const warFailFeed = document.querySelector("#warFailFeed");
const warRuntimeChips = document.querySelector("#warRuntimeChips");
const warRecentLogs = document.querySelector("#warRecentLogs");
const warProgressText = document.querySelector("#warProgressText");
const warProgressSub = document.querySelector("#warProgressSub");
const warRateChart = document.querySelector("#warRateChart");
const warStackChart = document.querySelector("#warStackChart");
const warRateChartMeta = document.querySelector("#warRateChartMeta");
const warStackChartMeta = document.querySelector("#warStackChartMeta");
const warStackLegend = document.querySelector("#warStackLegend");
const warInventorySub = document.querySelector("#warInventorySub");
const warSolverState = document.querySelector("#warSolverState");
const warSolverSub = document.querySelector("#warSolverSub");
const warSolverTile = document.querySelector("#warSolverTile");
const warDomainAvailable = document.querySelector("#warDomainAvailable");
const warDomainSub = document.querySelector("#warDomainSub");
const warDomainTile = document.querySelector("#warDomainTile");
const warDomainPin = document.querySelector("#warDomainPin");
const warThroughputText = document.querySelector("#warThroughputText");
const warEtaText = document.querySelector("#warEtaText");
const warGeneratedAt = document.querySelector("#warGeneratedAt");
const warRefreshBtn = document.querySelector("#warRefreshBtn");
const warStopBtn = document.querySelector("#warStopBtn");
const warResetDomainsBtn = document.querySelector("#warResetDomainsBtn");
const warEconBlurb = document.querySelector("#warEconBlurb");
const warEconGrid = document.querySelector("#warEconGrid");
const warApStatus = document.querySelector("#warApStatus");
const warApActions = document.querySelector("#warApActions");
const warAutopilotToggle = document.querySelector("#warAutopilotToggle");
const warAutopilotOnceBtn = document.querySelector("#warAutopilotOnceBtn");
const presetRow = document.querySelector("#presetRow");
const selectPageAccounts = document.querySelector("#selectPageAccounts");
const accountPageSize = document.querySelector("#accountPageSize");
const accountSearchInput = document.querySelector("#accountSearchInput");
const accountPushFilter = document.querySelector("#accountPushFilter");
const accountColumnOptions = document.querySelector("#accountColumnOptions");
const accountPagination = document.querySelector("#accountPagination");
const accountsHead = document.querySelector("#accountsHead");
const accountsBody = document.querySelector("#accountsBody");
const accountsSummary = document.querySelector("#accountsSummary");
const tabButtons = Array.from(document.querySelectorAll("[data-tab-target]"));
const tabPanels = Array.from(document.querySelectorAll("[data-tab-panel]"));

const ACCOUNT_TABLE_PREFS_KEY = "grok-reg.accounts.table";
const ACCOUNT_TABLE_PREFS_VERSION = 4;
const ACCOUNT_COLUMNS = [
  { key: "select", label: "选择", locked: true },
  { key: "created", label: "创建时间", className: "time-column", sortable: true, sortType: "time" },
  { key: "email", label: "邮箱", className: "email-column", sortable: true, sortType: "string" },
  { key: "sso", label: "SSO 摘要", className: "token-column", sortable: true, sortType: "string" },
  { key: "refresh", label: "Refresh Token", className: "token-column", sortable: true, sortType: "string" },
  { key: "source", label: "来源文件", className: "source-column", sortable: true, sortType: "string" },
  { key: "index", label: "序号", sortable: true, sortType: "number" },
  { key: "password", label: "密码", sortable: true, sortType: "string" },
  { key: "health", label: "健康状态", className: "status-column", sortable: true, sortType: "string" },
  { key: "grok2api", label: "grok2api", className: "status-column", sortable: true, sortType: "string" },
  { key: "sub2api", label: "sub2api", className: "status-column", sortable: true, sortType: "string" },
  { key: "cpa", label: "CPA", className: "status-column", sortable: true, sortType: "string" },
];
const STATUS_COLUMN_KEYS = new Set(["health", "grok2api", "sub2api", "cpa"]);
const DEFAULT_ACCOUNT_TABLE_PREFS = {
  visibleColumns: ACCOUNT_COLUMNS.map((column) => column.key),
  pageSize: 20,
  sortKey: "created",
  sortDir: "desc",
  version: ACCOUNT_TABLE_PREFS_VERSION,
};

let currentJobId = null;
let logOffset = 0;
let pollTimer = null;
/** 防止 setInterval 与 in-flight poll 重叠：同一 offset 被多次 append 导致日志刷屏 */
let pollInFlight = false;
let accounts = [];
let accountPage = 1;
let accountSearchQuery = "";
let accountPushFilterValue = "all";
let accountTablePrefs = loadAccountTablePrefs();
let accountSortKey = accountTablePrefs.sortKey || "created";
let accountSortDir = accountTablePrefs.sortDir === "asc" ? "asc" : "desc";
let selectedAccountIdsSet = new Set();
let accountHealthStatus = {};
let accountPushStatus = {};
let accountGrok2apiPushStatus = {};
let accountCpaPushStatus = {};
let pushingToSub2api = false;
let pushingToGrok2api = false;
let pushingToCpa = false;
let warRoomTimer = null;
let warRoomSnapshot = null;

const FAIL_REASON_LABELS = {
  domain_rejected: "域名拒收",
  otp_missing: "验证码缺失",
  create_code: "发码失败",
  turnstile: "Turnstile",
  blocked: "账号封禁",
  rate_limited: "限流 429",
  session_lost: "会话丢失",
  network: "网络/超时",
  email_provider: "邮箱服务",
  other: "其他",
};

const FAIL_REASON_COLORS = {
  domain_rejected: "#fb7185",
  otp_missing: "#fb923c",
  create_code: "#fbbf24",
  turnstile: "#7dd3fc",
  blocked: "#f43f5e",
  rate_limited: "#c084fc",
  session_lost: "#38bdf8",
  network: "#34d399",
  email_provider: "#67e8f9",
  other: "#94a3b8",
};

function setMessage(text) {
  message.textContent = text || "";
}

function activateTab(name) {
  tabButtons.forEach((button) => {
    const active = button.dataset.tabTarget === name;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  tabPanels.forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.tabPanel === name);
  });
  if (name === "accounts" || name === "dashboard") {
    loadAccounts().catch((error) => setMessage(error.message));
  }
  if (name === "dashboard") {
    startWarRoomPolling();
    loadWarRoom().catch((error) => setMessage(error.message));
  } else {
    stopWarRoomPolling();
  }
}

const CONFIG_GROUP_PREF_KEY = "grok-reg.config.group";
const configSubnavButtons = Array.from(document.querySelectorAll("[data-config-group].config-subnav-btn"));
const configSections = Array.from(document.querySelectorAll("#configForm .config-section[data-config-group]"));

function activateConfigGroup(group) {
  const name = ["task", "mail", "push", "notify"].includes(group) ? group : "task";
  configSubnavButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.configGroup === name);
  });
  configSections.forEach((section) => {
    section.hidden = section.dataset.configGroup !== name;
  });
  try {
    localStorage.setItem(CONFIG_GROUP_PREF_KEY, name);
  } catch (e) {}
  if (name === "mail") {
    loadWebhookPanel({ silent: true }).catch(() => {});
  }
}

function restoreConfigGroup() {
  let group = "task";
  try {
    group = localStorage.getItem(CONFIG_GROUP_PREF_KEY) || "task";
  } catch (e) {
    group = "task";
  }
  activateConfigGroup(group);
}

function formPayload() {
  const data = {};
  new FormData(form).forEach((value, key) => {
    data[key] = value;
  });
  data.enable_nsfw = form.elements.enable_nsfw.checked;
  data.grok2api_auto_add_local = form.elements.grok2api_auto_add_local.checked;
  data.grok2api_auto_add_remote = form.elements.grok2api_auto_add_remote.checked;
  data.sub2api_auto_import_remote = form.elements.sub2api_auto_import_remote.checked;
  data.cpa_auto_push_remote = form.elements.cpa_auto_push_remote.checked;
  if (form.elements.turnstile_solver_enabled) {
    data.turnstile_solver_enabled = form.elements.turnstile_solver_enabled.checked;
  }
  if (form.elements.turnstile_solver_fallback_click) {
    data.turnstile_solver_fallback_click = form.elements.turnstile_solver_fallback_click.checked;
  }
  if (form.elements.turnstile_solver_use_proxy) {
    data.turnstile_solver_use_proxy = form.elements.turnstile_solver_use_proxy.checked;
  }
  if (form.elements.turnstile_patch_api) {
    data.turnstile_patch_api = form.elements.turnstile_patch_api.checked;
  }
  if (form.elements.turnstile_force_execute) {
    data.turnstile_force_execute = form.elements.turnstile_force_execute.checked;
  }
  if (form.elements.enable_sub_domains) {
    data.enable_sub_domains = form.elements.enable_sub_domains.checked;
  }
  if (form.elements.random_sub_domain_level) {
    data.random_sub_domain_level = form.elements.random_sub_domain_level.checked;
  }
  if (form.elements.enable_mail_domain_runtime_control) {
    data.enable_mail_domain_runtime_control = form.elements.enable_mail_domain_runtime_control.checked;
  }
  if (form.elements.mail_domain_pinpoint_burst) {
    data.mail_domain_pinpoint_burst = form.elements.mail_domain_pinpoint_burst.checked;
  }
  if (form.elements.mail_domain_prefer_low_failure) {
    data.mail_domain_prefer_low_failure = form.elements.mail_domain_prefer_low_failure.checked;
  }
  if (form.elements.enable_mail_domain_grouping) {
    data.enable_mail_domain_grouping = form.elements.enable_mail_domain_grouping.checked;
  }
  if (form.elements.sub2api_auto_import_remote) {
    data.sub2api_auto_import_remote = form.elements.sub2api_auto_import_remote.checked;
  }
  if (form.elements.sub2api_auto_probe) {
    data.sub2api_auto_probe = form.elements.sub2api_auto_probe.checked;
  }
  if (form.elements.email_webhook_enabled) {
    data.email_webhook_enabled = form.elements.email_webhook_enabled.checked;
  }
  if (form.elements.cf_email_worker_force) {
    data.cf_email_worker_force = form.elements.cf_email_worker_force.checked;
  }
  if (form.elements.notify_enabled) {
    data.notify_enabled = form.elements.notify_enabled.checked;
  }
  if (form.elements.notify_cooldown_sec) {
    data.notify_cooldown_sec = Number(form.elements.notify_cooldown_sec.value || 180);
  }
  if (form.elements.notify_milestone_success) {
    data.notify_milestone_success = String(form.elements.notify_milestone_success.value || "")
      .split(/[,，\s]+/)
      .map((x) => Number(x))
      .filter((n) => Number.isFinite(n) && n > 0);
  }
  // 手动分组：textarea 每行一组
  if (form.elements.mail_domain_groups_text) {
    const lines = String(form.elements.mail_domain_groups_text.value || "")
      .split(/\r?\n/)
      .map((x) => x.trim())
      .filter(Boolean);
    data.mail_domain_groups = lines;
  }
  data.register_count = Number(data.register_count || 1);
  data.register_threads = Number(data.register_threads || 1);
  data.thread_start_interval = Number(data.thread_start_interval || 2);
  data.account_interval_seconds = Number(data.account_interval_seconds || 12);
  data.account_interval_jitter_seconds = Number(data.account_interval_jitter_seconds || 8);
  data.stop_on_consecutive_blocks = Number(data.stop_on_consecutive_blocks || 3);
  data.sub2api_concurrency = Number(data.sub2api_concurrency || 3);
  data.sub2api_priority = Number(data.sub2api_priority || 50);
  data.sub2api_init_gap_seconds = Number(data.sub2api_init_gap_seconds || 8);
  data.cpa_push_workers = Number(data.cpa_push_workers || 3);
  data.turnstile_solver_timeout = Number(data.turnstile_solver_timeout || 120);
  data.turnstile_wait_seconds = Number(data.turnstile_wait_seconds || 120);
  data.sub_domain_level = Number(data.sub_domain_level || 1);
  data.mail_domain_fail_threshold = Number(data.mail_domain_fail_threshold || 3);
  data.mail_domain_fail_cooldown_sec = Number(data.mail_domain_fail_cooldown_sec || 600);
  data.mail_domain_group_count = Number(data.mail_domain_group_count || 2);
  return data;
}

function applyConfig(config) {
  for (const [key, value] of Object.entries(config)) {
    const field = form.elements[key];
    if (!field) continue;
    if (field.type === "checkbox") {
      field.checked = Boolean(value);
    } else if (key === "notify_milestone_success" && Array.isArray(value)) {
      field.value = value.join(",");
    } else if (key === "notify_events") {
      continue;
    } else {
      // select 若 value 不在 options 里，浏览器会悄悄落回第一项（原先是 duckmail）
      if (field.tagName === "SELECT" && value != null && value !== "") {
        const wanted = String(value);
        const ok = Array.from(field.options || []).some((opt) => opt.value === wanted);
        if (!ok) {
          console.warn(`[config] ${key}=${wanted} 不在选项中，保持当前值`);
          continue;
        }
      }
      field.value = value ?? "";
    }
  }
  if (form.elements.mail_domain_groups_text) {
    const groups = Array.isArray(config.mail_domain_groups) ? config.mail_domain_groups : [];
    form.elements.mail_domain_groups_text.value = groups.filter(Boolean).join("\n");
  }
  if (form.elements.notify_milestone_success && Array.isArray(config.notify_milestone_success)) {
    form.elements.notify_milestone_success.value = config.notify_milestone_success.join(",");
  }
  const paths = [
    config.cloudflare_path_domains,
    config.cloudflare_path_accounts,
    config.cloudflare_path_token,
    config.cloudflare_path_messages,
  ].filter(Boolean);
  if (paths.length === 4 && form.elements.cloudflare_paths) {
    form.elements.cloudflare_paths.value = paths.join(",");
  }
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    ...options,
  });
  // 会话过期 / 未登录 → 跳转登录页
  if (response.status === 401 && !String(url).includes("/api/auth/")) {
    const next = `${location.pathname}${location.search || ""}` || "/";
    location.replace(`/login?next=${encodeURIComponent(next)}`);
    throw new Error("未登录或会话已过期");
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    let detail = payload.detail || payload.message || `HTTP ${response.status}`;
    if (Array.isArray(detail)) {
      detail = detail
        .map((item) => (typeof item === "string" ? item : item.msg || JSON.stringify(item)))
        .join("; ");
    } else if (detail && typeof detail === "object") {
      detail = detail.msg || JSON.stringify(detail);
    }
    throw new Error(detail);
  }
  return payload;
}

async function logout() {
  try {
    await requestJson("/api/auth/logout", { method: "POST", body: "{}" });
  } catch (e) {
    /* ignore */
  }
  location.replace("/login");
}

function selectedExportFormats() {
  const formats = [];
  if (exportFmtNative && exportFmtNative.checked) formats.push("native");
  if (exportFmtGrok2api && exportFmtGrok2api.checked) formats.push("grok2api");
  if (exportFmtSub2api && exportFmtSub2api.checked) formats.push("sub2api");
  if (exportFmtCpa && exportFmtCpa.checked) formats.push("cpa");
  return formats;
}

function parseFilenameFromDisposition(headerValue) {
  const raw = String(headerValue || "");
  const star = raw.match(/filename\*=UTF-8''([^;]+)/i);
  if (star) {
    try {
      return decodeURIComponent(star[1].trim().replace(/"/g, ""));
    } catch (e) {
      /* ignore */
    }
  }
  const plain = raw.match(/filename="?([^";]+)"?/i);
  return plain ? plain[1].trim() : "export_accounts.zip";
}

async function exportSelectedAccounts() {
  const accountIds = selectedAccountIds();
  if (!accountIds.length) {
    setMessage("请先勾选要导出的账号");
    return;
  }
  const formats = selectedExportFormats();
  if (!formats.length) {
    setMessage("请至少勾选一种导出格式");
    return;
  }
  if (exportAccountsBtn) {
    exportAccountsBtn.disabled = true;
    exportAccountsBtn.textContent = "导出中…";
  }
  try {
    const response = await fetch("/api/accounts/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...formPayload(), account_ids: accountIds, formats }),
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail || `HTTP ${response.status}`);
    }
    const blob = await response.blob();
    const filename = parseFilenameFromDisposition(
      response.headers.get("Content-Disposition")
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setMessage(
      `已导出 ${accountIds.length} 个账号（${formats.join(" + ")}）→ ${filename}`
    );
  } catch (error) {
    setMessage(`导出失败：${error.message}`);
  } finally {
    if (exportAccountsBtn) {
      exportAccountsBtn.disabled = false;
      exportAccountsBtn.textContent = "导出选中";
    }
  }
}

async function loadConfig() {
  const config = await requestJson("/api/config");
  applyConfig(config);
}

async function saveConfig() {
  const config = await requestJson("/api/config", {
    method: "PUT",
    body: JSON.stringify(formPayload()),
  });
  applyConfig(config);
  setMessage("配置已保存");
}

const JOB_ID_STORAGE_KEY = "grok-reg.currentJobId";

function rememberJobId(jobId) {
  currentJobId = jobId || null;
  try {
    if (currentJobId) localStorage.setItem(JOB_ID_STORAGE_KEY, currentJobId);
    else localStorage.removeItem(JOB_ID_STORAGE_KEY);
  } catch (e) {
    /* ignore */
  }
  if (jobIdText) jobIdText.textContent = currentJobId || "-";
}

function restoreRememberedJobId() {
  try {
    return localStorage.getItem(JOB_ID_STORAGE_KEY) || null;
  } catch (e) {
    return null;
  }
}

async function startJob() {
  const payload = formPayload();
  const provider = String(payload.email_provider || "").trim();
  if (!provider) {
    setMessage("请先选择邮箱服务商（email_provider）再启动");
    return;
  }
  setMessage(`正在启动… 邮箱服务商=${provider}`);
  const job = await requestJson("/api/jobs/start", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  // 换 job / 清屏：进行中的 poll 看到 jobId/offset 变化会丢弃结果
  rememberJobId(job.job_id);
  logOffset = 0;
  logBox.textContent = "";
  if (job.already_running) {
    setMessage("已有任务在运行，已恢复跟踪");
  } else {
    setMessage("任务已启动");
  }
  startPolling();
}

function isActiveJobStatus(status) {
  if (!status) return false;
  const name = String(status.status || "").toLowerCase();
  if (["interrupted", "stopped", "completed", "failed", "idle"].includes(name)) return false;
  if (status.from_disk) return false;
  // stopping 仍算活跃：线程在收尾，禁止重复启动，并继续轮询
  if (Boolean(status.running) || Boolean(status.stop_requested)) return true;
  return ["pending", "running", "stopping"].includes(name);
}

async function stopJob() {
  // 优先当前 id；失败则停服务端 active
  const id = currentJobId;
  try {
    let result;
    if (id) {
      try {
        result = await requestJson(`/api/jobs/${id}/stop`, { method: "POST" });
      } catch (error) {
        // 404：尝试无 id 的 stop（停当前 active / 清僵尸）
        result = await requestJson(`/api/jobs/stop`, { method: "POST" });
      }
    } else {
      result = await requestJson(`/api/jobs/stop`, { method: "POST" });
    }
    if (result.job_id) rememberJobId(result.job_id);
    statusText.textContent = result.status || "stopping";
    // 协作式停止：可能仍在收尾，继续轮询直到真正 stopped
    const stillActive = isActiveJobStatus(result) || result.status === "stopping" || result.stop_requested;
    startBtn.disabled = stillActive;
    stopBtn.disabled = true;
    setMessage(
      result.message ||
        (stillActive
          ? "已请求停止，等待当前步骤结束（验证码/过盾/网络请求完成后才会真正停下）"
          : "任务已停止")
    );
    if (stillActive) {
      startPolling();
    } else if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    renderDashboard();
    loadWarRoom({ silent: true }).catch(() => {});
  } catch (error) {
    // 最终失败也清前端状态，避免卡在 running
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    statusText.textContent = "stopped";
    startBtn.disabled = false;
    stopBtn.disabled = true;
    rememberJobId(null);
    setMessage(`停止任务: ${error.message}`);
    renderDashboard();
  }
}

async function pollJob() {
  if (!currentJobId) return;
  // setInterval 不会等上一次 async 结束；重叠时两个请求用同一 logOffset，
  // 会把同一段日志 append 多遍（用户看到整段流程刷屏）。
  if (pollInFlight) return;
  pollInFlight = true;
  // 全程用快照：中途 start/restore 换 job 或重置 offset 时丢弃本轮结果
  const jobId = currentJobId;
  const requestedOffset = logOffset;
  try {
    let status;
    try {
      status = await requestJson(`/api/jobs/${jobId}`);
    } catch (error) {
      if (String(error.message || "").includes("404") || String(error.message || "").includes("不存在")) {
        if (currentJobId !== jobId) return;
        const current = await requestJson("/api/jobs/current").catch(() => null);
        if (current && current.has_job && current.job_id) {
          rememberJobId(current.job_id);
          status = current;
        } else {
          if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
          }
          statusText.textContent = "idle";
          startBtn.disabled = false;
          stopBtn.disabled = true;
          rememberJobId(null);
          return;
        }
      } else {
        throw error;
      }
    }
    if (currentJobId !== jobId) return;

    statusText.textContent = status.status;
    statsText.textContent = `成功 ${status.success_count || 0} / 失败 ${status.fail_count || 0}`;
    const trulyRunning = isActiveJobStatus(status);
    const stopping = status.status === "stopping" || Boolean(status.stop_requested);
    startBtn.disabled = trulyRunning;
    // 停止中只允许点一次；结束后放开启动、禁用停止
    stopBtn.disabled = !trulyRunning || stopping;

    if (currentJobId === jobId && logOffset === requestedOffset) {
      const logs = await requestJson(`/api/jobs/${jobId}/logs?offset=${requestedOffset}`);
      // 再次校验：避免 restore/start 已清屏后把旧片段 append 回来
      if (
        logs.lines &&
        logs.lines.length &&
        currentJobId === jobId &&
        logOffset === requestedOffset
      ) {
        logBox.textContent += `${logs.lines.join("\n")}\n`;
        logBox.scrollTop = logBox.scrollHeight;
        logOffset =
          typeof logs.next_offset === "number"
            ? logs.next_offset
            : requestedOffset + logs.lines.length;
      }
    }

    if (currentJobId !== jobId) return;
    if (!trulyRunning && pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
      loadAccounts().catch((error) => setMessage(error.message));
    }
    loadWarRoom({ silent: true }).catch(() => renderDashboard());
  } finally {
    pollInFlight = false;
  }
}

async function restoreCurrentJob({ silent = false } = {}) {
  // 与 pollJob 互斥，避免恢复全量日志时 in-flight poll 再 append 一段。
  // 注意：释放 pollInFlight 后再 startPolling/pollJob，且不要用 finally 统一清——
  // 否则会把刚启动的 poll 的 inFlight 标志误清掉。
  while (pollInFlight) {
    await new Promise((r) => setTimeout(r, 50));
  }
  pollInFlight = true;
  let handoffToPoll = false;
  try {
    // 1) localStorage 记住的 job
    let jobId = restoreRememberedJobId();
    // 2) 服务端当前/最近任务
    try {
      const current = await requestJson("/api/jobs/current");
      if (current && current.has_job && current.job_id) {
        jobId = current.job_id;
        rememberJobId(jobId);
        statusText.textContent = current.status || "-";
        statsText.textContent = `成功 ${current.success_count || 0} / 失败 ${current.fail_count || 0}`;
        const running = isActiveJobStatus(current);
        const stopping = current.status === "stopping" || Boolean(current.stop_requested);
        startBtn.disabled = running;
        stopBtn.disabled = !running || stopping;
        // 拉全量日志
        logOffset = 0;
        logBox.textContent = "";
        const logs = await requestJson(`/api/jobs/${jobId}/logs?offset=0`);
        if (logs.lines && logs.lines.length && currentJobId === jobId) {
          logBox.textContent = `${logs.lines.join("\n")}\n`;
          logBox.scrollTop = logBox.scrollHeight;
          logOffset = logs.next_offset;
        }
        if (running) {
          if (!silent) {
            setMessage(
              stopping
                ? "已恢复停止中的任务（等待当前步骤结束）"
                : "已恢复运行中的注册任务"
            );
          }
          handoffToPoll = true;
          pollInFlight = false;
          startPolling();
        } else if (!silent) {
          setMessage("已恢复最近一次任务记录（已结束）");
        }
        renderDashboard();
        return true;
      }
    } catch (error) {
      if (!silent) setMessage(`恢复任务失败: ${error.message}`);
    }
    // 没有任务
    if (!jobId) {
      startBtn.disabled = false;
      stopBtn.disabled = true;
      return false;
    }
    // 仅有本地 jobId：尝试拉取
    try {
      rememberJobId(jobId);
      logOffset = 0;
      logBox.textContent = "";
      handoffToPoll = true;
      pollInFlight = false;
      await pollJob();
      const running = ["pending", "running", "stopping"].includes(statusText.textContent);
      if (running) startPolling();
      return true;
    } catch (error) {
      rememberJobId(null);
      return false;
    }
  } finally {
    if (!handoffToPoll) pollInFlight = false;
  }
}

function loadAccountTablePrefs() {
  try {
    const saved = JSON.parse(localStorage.getItem(ACCOUNT_TABLE_PREFS_KEY) || "{}");
    const allowedColumns = new Set(ACCOUNT_COLUMNS.map((column) => column.key));
    const visibleColumns = Array.isArray(saved.visibleColumns)
      ? saved.visibleColumns
          .map((key) => (key === "line" ? "index" : key))
          .filter((key) => allowedColumns.has(key))
      : DEFAULT_ACCOUNT_TABLE_PREFS.visibleColumns.slice();
    if (Number(saved.version || 1) < 2 && !visibleColumns.includes("health")) {
      visibleColumns.push("health");
    }
    if (Number(saved.version || 1) < 3 && !visibleColumns.includes("cpa")) {
      visibleColumns.push("cpa");
    }
    if (Number(saved.version || 1) < 4 && !visibleColumns.includes("created")) {
      const emailIdx = visibleColumns.indexOf("email");
      if (emailIdx >= 0) visibleColumns.splice(emailIdx, 0, "created");
      else visibleColumns.push("created");
    }
    const pageSize = [10, 20, 50, 100].includes(Number(saved.pageSize))
      ? Number(saved.pageSize)
      : DEFAULT_ACCOUNT_TABLE_PREFS.pageSize;
    const sortKey = allowedColumns.has(saved.sortKey) && saved.sortKey !== "select"
      ? saved.sortKey
      : DEFAULT_ACCOUNT_TABLE_PREFS.sortKey;
    const sortDir = saved.sortDir === "asc" ? "asc" : "desc";
    return {
      visibleColumns: visibleColumns.includes("select") ? visibleColumns : ["select", ...visibleColumns],
      pageSize,
      sortKey,
      sortDir,
      version: ACCOUNT_TABLE_PREFS_VERSION,
    };
  } catch (error) {
    return { ...DEFAULT_ACCOUNT_TABLE_PREFS };
  }
}

function saveAccountTablePrefs() {
  accountTablePrefs.sortKey = accountSortKey;
  accountTablePrefs.sortDir = accountSortDir;
  accountTablePrefs.version = ACCOUNT_TABLE_PREFS_VERSION;
  localStorage.setItem(ACCOUNT_TABLE_PREFS_KEY, JSON.stringify(accountTablePrefs));
}

function visibleAccountColumns() {
  const visible = new Set(accountTablePrefs.visibleColumns);
  return ACCOUNT_COLUMNS.filter((column) => column.locked || visible.has(column.key));
}

function accountIsPushed(account, channel) {
  const status = String(account[`${channel}_status`] || "").toLowerCase();
  const text = String(account[`${channel}_status_text`] || "");
  if (channel === "sub2api") {
    const live = accountPushStatus[account.id];
    if (live) {
      // 探测失败也算「已入库」，但筛选「已推送」只认真正通过
      return live === "已推送" || (String(live).includes("已推送") && !String(live).includes("探测失败"));
    }
    // probe_failed 已入库但未通过探测，不算「已推送」
    if (status === "probe_failed" || text.includes("探测失败")) return false;
  }
  if (channel === "grok2api") {
    const live = accountGrok2apiPushStatus[account.id];
    if (live) return live === "已推送" || String(live).includes("已推送");
  }
  if (channel === "cpa") {
    const live = accountCpaPushStatus[account.id];
    if (live) return live === "已推送" || String(live).includes("已推送");
  }
  return status === "pushed" || text === "已推送";
}

function accountIsSub2apiProbeFailed(account) {
  // 只认正式状态 probe_failed（新号探测失败后写入）。
  // 历史号默认 pushed=探测成功。操作中 live「探测中/删除远端中」仍留在该筛选下，
  // 避免一点击列表变空；过滤器本身不要被代码改掉。
  const status = String(account.sub2api_status || "").toLowerCase();
  const live = String(accountPushStatus[account.id] || "");
  if (live === "探测中" || live === "删除远端中") {
    return (
      status === "probe_failed" ||
      Boolean(account.sub2api_probe_error) ||
      String(account.sub2api_status_text || "").includes("探测失败")
    );
  }
  if (status === "probe_failed") return true;
  const text = String(account.sub2api_status_text || "");
  return text.includes("已入库·探测失败") || text.includes("探测失败");
}

function accountHasPushFailure(account) {
  for (const channel of ["grok2api", "sub2api", "cpa"]) {
    const status = String(account[`${channel}_status`] || "").toLowerCase();
    const live = String(
      (channel === "sub2api" && accountPushStatus[account.id]) ||
        (channel === "grok2api" && accountGrok2apiPushStatus[account.id]) ||
        (channel === "cpa" && accountCpaPushStatus[account.id]) ||
        ""
    );
    const text = String(account[`${channel}_status_text`] || "");
    // 推送本身失败；sub2api 探测失败单独筛，也算进「推送失败」方便处理
    if (status === "failed") return true;
    if (channel === "sub2api" && status === "probe_failed") return true;
    if (live.startsWith("失败")) return true;
    if (text.startsWith("失败") || text === "推送失败") return true;
    if (channel === "sub2api" && (text.includes("探测失败") || live.includes("探测失败"))) return true;
  }
  return false;
}

function formatAccountCreatedAt(value) {
  const raw = String(value || "").trim();
  if (!raw) return "—";
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(raw)) {
    return raw.replace("T", " ").slice(0, 19);
  }
  return raw;
}

function accountSortValue(account, key) {
  if (key === "created") return String(account.created_at || "");
  if (key === "email") return String(account.email || "").toLowerCase();
  if (key === "sso") return String(account.sso_preview || "").toLowerCase();
  if (key === "refresh") {
    return account.has_refresh_token
      ? `1:${String(account.refresh_token_preview || "").toLowerCase()}`
      : "0:";
  }
  if (key === "source") return String(account.source_file || "").toLowerCase();
  if (key === "index") return Number(account.line_no || 0);
  if (key === "password") return account.password ? "1" : "0";
  if (key === "health") {
    return String(accountHealthStatus[account.id] || account.health_status_text || account.health_status || "").toLowerCase();
  }
  if (key === "grok2api") {
    return String(
      accountGrok2apiPushStatus[account.id] ||
        account.grok2api_status_text ||
        account.grok2api_status ||
        ""
    ).toLowerCase();
  }
  if (key === "sub2api") {
    return String(
      accountPushStatus[account.id] || account.sub2api_status_text || account.sub2api_status || ""
    ).toLowerCase();
  }
  if (key === "cpa") {
    return String(
      accountCpaPushStatus[account.id] || account.cpa_status_text || account.cpa_status || ""
    ).toLowerCase();
  }
  return "";
}

function compareAccountSort(a, b, key, dir) {
  const col = ACCOUNT_COLUMNS.find((c) => c.key === key);
  const type = (col && col.sortType) || "string";
  const av = accountSortValue(a, key);
  const bv = accountSortValue(b, key);
  let cmp = 0;
  if (type === "number") {
    cmp = Number(av || 0) - Number(bv || 0);
  } else if (type === "time") {
    cmp = String(av || "").localeCompare(String(bv || ""));
  } else {
    cmp = String(av || "").localeCompare(String(bv || ""), "zh-CN", { numeric: true, sensitivity: "base" });
  }
  if (cmp === 0) {
    const t = String(a.created_at || "").localeCompare(String(b.created_at || ""));
    if (t !== 0) cmp = t;
    else cmp = Number(b.line_no || 0) - Number(a.line_no || 0);
  }
  return dir === "asc" ? cmp : -cmp;
}

function setAccountSort(key) {
  if (!key || key === "select") return;
  if (accountSortKey === key) {
    accountSortDir = accountSortDir === "asc" ? "desc" : "asc";
  } else {
    accountSortKey = key;
    accountSortDir = key === "created" || key === "index" ? "desc" : "asc";
  }
  saveAccountTablePrefs();
  accountPage = 1;
  renderAccounts();
}

function filteredAccounts() {
  const q = String(accountSearchQuery || "").trim().toLowerCase();
  const filter = accountPushFilterValue || "all";
  const list = accounts.filter((account) => {
    if (q) {
      const hay = [
        account.email,
        account.source_file,
        account.created_at,
        account.sso_preview,
        account.grok2api_status_text,
        account.sub2api_status_text,
        account.cpa_status_text,
        account.health_status_text,
        accountGrok2apiPushStatus[account.id],
        accountPushStatus[account.id],
        accountCpaPushStatus[account.id],
      ]
        .map((x) => String(x || "").toLowerCase())
        .join(" ");
      if (!hay.includes(q)) return false;
    }
    if (filter === "all") return true;
    if (filter === "any_pushed") {
      return (
        accountIsPushed(account, "grok2api") ||
        accountIsPushed(account, "sub2api") ||
        accountIsPushed(account, "cpa")
      );
    }
    if (filter === "none_pushed") {
      return (
        !accountIsPushed(account, "grok2api") &&
        !accountIsPushed(account, "sub2api") &&
        !accountIsPushed(account, "cpa")
      );
    }
    if (filter === "grok2api_pushed") return accountIsPushed(account, "grok2api");
    if (filter === "sub2api_pushed") return accountIsPushed(account, "sub2api");
    if (filter === "sub2api_probe_failed") return accountIsSub2apiProbeFailed(account);
    if (filter === "cpa_pushed") return accountIsPushed(account, "cpa");
    if (filter === "failed") return accountHasPushFailure(account);
    return true;
  });
  const key = accountSortKey || "created";
  const dir = accountSortDir === "asc" ? "asc" : "desc";
  return list.slice().sort((a, b) => compareAccountSort(a, b, key, dir));
}

function accountTotalPages() {
  return Math.max(1, Math.ceil(filteredAccounts().length / accountTablePrefs.pageSize));
}

function currentPageAccounts() {
  const list = filteredAccounts();
  const start = (accountPage - 1) * accountTablePrefs.pageSize;
  return list.slice(start, start + accountTablePrefs.pageSize);
}

function clampAccountPage() {
  accountPage = Math.min(Math.max(1, accountPage), accountTotalPages());
}

function selectedAccountIds() {
  const visible = new Set(filteredAccounts().map((a) => a.id));
  return Array.from(selectedAccountIdsSet).filter(
    (id) => accounts.some((account) => account.id === id) && (visible.has(id) || true)
  );
}

function renderAccountColumns() {
  if (!accountColumnOptions) return;
  accountColumnOptions.innerHTML = "";
  for (const column of ACCOUNT_COLUMNS.filter((item) => !item.locked)) {
    const label = document.createElement("label");
    label.className = "check compact";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.setAttribute("data-column-toggle", column.key);
    checkbox.checked = accountTablePrefs.visibleColumns.includes(column.key);
    label.appendChild(checkbox);
    label.append(document.createTextNode(column.label));
    accountColumnOptions.appendChild(label);
  }
}

function renderAccountsHead() {
  if (!accountsHead) return;
  const row = document.createElement("tr");
  for (const column of visibleAccountColumns()) {
    const cell = document.createElement("th");
    if (column.className) cell.className = column.className;
    if (column.sortable) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "th-sort";
      if (accountSortKey === column.key) {
        btn.classList.add("active");
        btn.dataset.dir = accountSortDir;
      }
      const label = document.createElement("span");
      label.textContent = column.label;
      const mark = document.createElement("i");
      mark.className = "sort-mark";
      mark.textContent =
        accountSortKey === column.key ? (accountSortDir === "asc" ? "↑" : "↓") : "↕";
      btn.append(label, mark);
      btn.title = "点击排序";
      btn.addEventListener("click", () => setAccountSort(column.key));
      cell.appendChild(btn);
    } else {
      cell.textContent = column.label;
    }
    row.appendChild(cell);
  }
  accountsHead.innerHTML = "";
  accountsHead.appendChild(row);
}

function accountCellValue(account, key, rowNumber) {
  const refreshStatus = account.has_refresh_token
    ? `已保存 ${account.refresh_token_preview || ""}`.trim()
    : "缺少";
  const persistedGrok2apiStatus = account.grok2api_status_text || (account.grok2api_status === "pushed" ? "已推送" : "未推送");
  const grok2apiStatus = accountGrok2apiPushStatus[account.id] || persistedGrok2apiStatus;
  const persistedSub2apiStatus = account.sub2api_status_text || (account.sub2api_status === "pushed" ? "已推送" : "未推送");
  const sub2apiStatus = accountPushStatus[account.id] || persistedSub2apiStatus;
  const persistedCpaStatus = account.cpa_status_text || (account.cpa_status === "pushed" ? "已推送" : "未推送");
  const cpaStatus = accountCpaPushStatus[account.id] || persistedCpaStatus;
  const persistedHealthStatus = account.health_status_text || "未检查";
  const healthStatus = accountHealthStatus[account.id] || persistedHealthStatus;
  const values = {
    created: formatAccountCreatedAt(account.created_at),
    email: account.email,
    sso: account.sso_preview || "",
    refresh: refreshStatus,
    source: account.source_file || "",
    index: key === "index" ? Number(account.line_no || rowNumber) : rowNumber,
    password: account.password ? "已保存" : "-",
    health: healthStatus,
    grok2api: grok2apiStatus,
    sub2api: sub2apiStatus,
    cpa: cpaStatus,
  };
  return values[key] ?? "";
}

function summarizeFailureStatus(text) {
  const lower = String(text || "").toLowerCase();
  if (lower.includes("user account is blocked") || lower.includes("account is blocked")) {
    return "失败：账号已封禁";
  }
  if (lower.includes("revoked")) return "失败：令牌已撤销";
  if (lower.includes("invalid_grant")) return "失败：令牌无效";
  if (lower.includes("缺少 refresh") || lower.includes("缺少refresh")) return "失败：缺少 Refresh";
  if (lower.includes("retry_with_sso_failed")) return "失败：SSO 重试失败";
  if (lower.includes("http 401") || lower.includes("unauthorized")) return "失败：HTTP 401";
  if (lower.includes("http 403") || lower.includes("forbidden")) return "失败：HTTP 403";
  if (lower.includes("http 404")) return "失败：HTTP 404";
  if (lower.includes("http 429")) return "失败：请求过多";
  if (lower.includes("http 502") || lower.includes("http 503") || lower.includes("http 504")) {
    return "失败：服务异常";
  }
  if (lower.includes("http 400")) return "失败：HTTP 400";
  if (lower.includes("timeout") || lower.includes("超时")) return "失败：超时";
  return "失败";
}

function formatAccountStatusDisplay(value) {
  const text = String(value ?? "").trim();
  if (!text) return { display: "", title: "", tone: "" };
  if (text === "已推送" || text === "可用") return { display: text, title: "", tone: "ok" };
  if (text === "推送中" || text === "检查中" || text === "探测中" || text === "删除远端中") {
    return { display: text, title: "", tone: "running" };
  }
  if (text === "已入库·探测失败" || text.includes("探测失败")) {
    return { display: text.includes("已入库") ? "已入库·探测失败" : "探测失败", title: text, tone: "failed" };
  }
  if (text === "失效" || text === "资料不完整") return { display: text, title: "", tone: "failed" };
  if (text.startsWith("失败") || text === "推送失败") {
    return { display: summarizeFailureStatus(text), title: text, tone: "failed" };
  }
  if (text.length > 24) return { display: `${text.slice(0, 22)}…`, title: text, tone: "" };
  return { display: text, title: "", tone: "" };
}

function dashboardMetricValue(element, value) {
  if (!element) return;
  element.textContent = String(value);
}

function isFailedStatus(account, prefix) {
  const status = String(account[`${prefix}_status`] || "").toLowerCase();
  const text = String(account[`${prefix}_status_text`] || "");
  return status === "failed" || text.startsWith("失败");
}

function accountDashboardStats() {
  const total = accounts.length;
  const refresh = accounts.filter((account) => account.has_refresh_token).length;
  const healthy = accounts.filter((account) => account.health_status === "healthy" || account.health_status_text === "可用").length;
  const unhealthy = accounts.filter((account) => account.health_status === "unhealthy" || account.health_status_text === "失效").length;
  const incomplete = accounts.filter((account) => account.health_status === "incomplete" || account.health_status_text === "资料不完整").length;
  const untested = Math.max(0, total - healthy - unhealthy - incomplete);
  const grok2api = accounts.filter((account) => account.grok2api_status === "pushed" || account.grok2api_status_text === "已推送").length;
  const sub2api = accounts.filter((account) => account.sub2api_status === "pushed" || account.sub2api_status_text === "已推送").length;
  const needAction = accounts.filter((account) => {
    return (
      !account.has_refresh_token ||
      account.health_status === "unhealthy" ||
      account.health_status === "incomplete" ||
      account.health_status_text === "失效" ||
      account.health_status_text === "资料不完整" ||
      isFailedStatus(account, "grok2api") ||
      isFailedStatus(account, "sub2api")
    );
  }).length;
  return {
    total,
    refresh,
    healthy,
    unhealthy,
    incomplete,
    untested,
    grok2api,
    sub2api,
    needAction,
  };
}

function percentText(value, total) {
  if (!total) return "0%";
  return `${Math.round((value / total) * 100)}%`;
}

function renderMixRow(parent, label, value, total, tone = "") {
  const row = document.createElement("div");
  row.className = `mix-row ${tone}`.trim();
  const meta = document.createElement("div");
  meta.className = "mix-meta";
  const title = document.createElement("span");
  title.textContent = label;
  const count = document.createElement("strong");
  count.textContent = `${value} / ${total}`;
  meta.append(title, count);
  const track = document.createElement("div");
  track.className = "mix-track";
  const bar = document.createElement("span");
  bar.style.width = percentText(value, total);
  track.appendChild(bar);
  row.append(meta, track);
  parent.appendChild(row);
}

function formatDuration(sec) {
  const n = Number(sec);
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 60) return `${Math.round(n)}s`;
  if (n < 3600) return `${Math.floor(n / 60)}m ${Math.round(n % 60)}s`;
  const h = Math.floor(n / 3600);
  const m = Math.floor((n % 3600) / 60);
  return `${h}h ${m}m`;
}

function chartEmpty(el, text) {
  if (!el) return;
  el.innerHTML = "";
  const p = document.createElement("p");
  p.className = "dashboard-empty chart-empty";
  p.textContent = text;
  el.appendChild(p);
}

function renderSuccessRateChart(timeline) {
  if (!warRateChart) return;
  const points = Array.isArray(timeline) ? timeline : [];
  if (!points.length) {
    chartEmpty(warRateChart, "暂无注册事件，跑任务后显示成功率曲线");
    if (warRateChartMeta) warRateChartMeta.textContent = "0 事件";
    return;
  }
  const w = 560;
  const h = 200;
  const padL = 36;
  const padR = 12;
  const padT = 16;
  const padB = 28;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;
  const n = points.length;
  const xs = points.map((_, i) => padL + (n === 1 ? plotW / 2 : (i / (n - 1)) * plotW));
  const ys = points.map((p) => {
    const rate = Math.max(0, Math.min(100, Number(p.success_rate) || 0));
    return padT + plotH * (1 - rate / 100);
  });
  const line = xs.map((x, i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${ys[i].toFixed(1)}`).join(" ");
  const area = `${line} L${xs[n - 1].toFixed(1)},${(padT + plotH).toFixed(1)} L${xs[0].toFixed(1)},${(padT + plotH).toFixed(1)} Z`;
  const last = points[n - 1];
  const gridY = [0, 25, 50, 75, 100]
    .map((v) => {
      const y = padT + plotH * (1 - v / 100);
      return `<line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" class="chart-grid"/>
        <text x="${padL - 6}" y="${y + 3}" class="chart-axis" text-anchor="end">${v}</text>`;
    })
    .join("");
  const dots = xs
    .map((x, i) => {
      const kind = points[i].kind === "success" ? "ok" : "bad";
      return `<circle cx="${x.toFixed(1)}" cy="${ys[i].toFixed(1)}" r="3.2" class="chart-dot ${kind}"><title>${points[i].t} · ${points[i].success_rate}% · ${points[i].kind}</title></circle>`;
    })
    .join("");
  const labelIdx = [0, Math.floor((n - 1) / 2), n - 1].filter((v, i, a) => a.indexOf(v) === i);
  const xLabels = labelIdx
    .map((i) => {
      const label = String(points[i].t || "").slice(0, 8);
      return `<text x="${xs[i].toFixed(1)}" y="${h - 8}" class="chart-axis" text-anchor="middle">${label}</text>`;
    })
    .join("");

  warRateChart.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="chart-svg">
      ${gridY}
      <path d="${area}" class="chart-area"/>
      <path d="${line}" class="chart-line"/>
      ${dots}
      ${xLabels}
    </svg>`;
  if (warRateChartMeta) {
    warRateChartMeta.textContent = `${n} 事件 · 当前 ${last.success_rate}% · ✓${last.cum_success} / ✗${last.cum_fail}`;
  }
}

function renderFailStackChart(stack, reasonKeys) {
  if (!warStackChart) return;
  const rows = Array.isArray(stack) ? stack : [];
  const keys = Array.isArray(reasonKeys) && reasonKeys.length
    ? reasonKeys
    : Array.from(
        new Set(
          rows.flatMap((r) => Object.keys(r).filter((k) => k !== "bucket" && k !== "total"))
        )
      );
  if (!rows.length || !keys.length) {
    chartEmpty(warStackChart, "暂无失败堆叠数据");
    if (warStackChartMeta) warStackChartMeta.textContent = "0 桶";
    if (warStackLegend) warStackLegend.innerHTML = "";
    return;
  }
  const w = 560;
  const h = 200;
  const padL = 28;
  const padR = 12;
  const padT = 12;
  const padB = 28;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;
  const maxTotal = Math.max(1, ...rows.map((r) => Number(r.total) || 0));
  const gap = 4;
  const barW = Math.max(8, (plotW - gap * Math.max(0, rows.length - 1)) / rows.length);
  const bars = rows
    .map((row, i) => {
      const x = padL + i * (barW + gap);
      let y = padT + plotH;
      const segs = [];
      for (const key of keys) {
        const count = Number(row[key] || 0);
        if (!count) continue;
        const segH = (count / maxTotal) * plotH;
        y -= segH;
        const color = FAIL_REASON_COLORS[key] || FAIL_REASON_COLORS.other;
        segs.push(
          `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${Math.max(1, segH).toFixed(1)}" fill="${color}" rx="2"><title>${row.bucket} · ${FAIL_REASON_LABELS[key] || key}: ${count}</title></rect>`
        );
      }
      const label = String(row.bucket || "").slice(0, 5);
      const showLabel = rows.length <= 12 || i % Math.ceil(rows.length / 6) === 0 || i === rows.length - 1;
      const text = showLabel
        ? `<text x="${(x + barW / 2).toFixed(1)}" y="${h - 8}" class="chart-axis" text-anchor="middle">${label}</text>`
        : "";
      return segs.join("") + text;
    })
    .join("");
  const grid = [0, 0.5, 1]
    .map((f) => {
      const y = padT + plotH * (1 - f);
      const val = Math.round(maxTotal * f);
      return `<line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" class="chart-grid"/>
        <text x="${padL - 4}" y="${y + 3}" class="chart-axis" text-anchor="end">${val}</text>`;
    })
    .join("");

  warStackChart.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="chart-svg">
      ${grid}
      ${bars}
    </svg>`;
  if (warStackChartMeta) {
    const totalFails = rows.reduce((s, r) => s + (Number(r.total) || 0), 0);
    warStackChartMeta.textContent = `${rows.length} 桶 · ${totalFails} 次失败`;
  }
  if (warStackLegend) {
    warStackLegend.innerHTML = "";
    for (const key of keys) {
      const item = document.createElement("span");
      item.className = "legend-item";
      const sw = document.createElement("i");
      sw.style.background = FAIL_REASON_COLORS[key] || FAIL_REASON_COLORS.other;
      const lab = document.createElement("em");
      lab.textContent = FAIL_REASON_LABELS[key] || key;
      item.append(sw, lab);
      warStackLegend.appendChild(item);
    }
  }
}

function renderWarCharts(data) {
  const charts = (data && data.charts) || (data && data.failures && data.failures.charts) || {};
  renderSuccessRateChart(charts.timeline || []);
  renderFailStackChart(charts.fail_stack || [], charts.reason_keys || []);
}

function renderEconomics(econ) {
  if (!warEconGrid) return;
  const e = econ || {};
  if (warEconBlurb) warEconBlurb.textContent = e.blurb || "产能数据收集中";
  const cells = [
    ["秒/成功", e.sec_per_success != null ? `${e.sec_per_success}s` : "—"],
    ["尝试/成功", e.attempts_per_success != null ? String(e.attempts_per_success) : "—"],
    ["邮箱已耗~", e.mail_spent_est != null ? String(e.mail_spent_est) : "—"],
    ["再要 N 个", e.terminal ? "—" : (e.remain != null ? String(e.remain) : "—")],
    ["再耗邮箱~", e.terminal ? "—" : (e.est_more_mail != null ? String(e.est_more_mail) : "—")],
    ["ETA", e.terminal ? "已结束" : (e.eta_more_sec != null ? formatDuration(e.eta_more_sec) : "—")],
    ["Solver 失败信号", e.solver_fail_hits != null ? String(e.solver_fail_hits) : "—"],
    ["产能/min", e.rate_per_min != null ? String(e.rate_per_min) : "—"],
  ];
  warEconGrid.innerHTML = "";
  for (const [k, v] of cells) {
    const cell = document.createElement("div");
    cell.className = "econ-cell";
    cell.innerHTML = `<span>${k}</span><strong>${v}</strong>`;
    warEconGrid.appendChild(cell);
  }
}

function renderAutopilot(ap) {
  const data = ap || {};
  if (warAutopilotToggle) {
    warAutopilotToggle.checked = Boolean(data.enabled);
  }
  if (warApStatus) {
    warApStatus.textContent = data.enabled ? "已开启 · 运行中自动应用" : "关闭 · 仅展示建议";
  }
  if (!warApActions) return;
  warApActions.innerHTML = "";
  const pending = data.pending_actions || [];
  const last = data.last_actions || [];
  if (!pending.length && !last.length) {
    const empty = document.createElement("p");
    empty.className = "dashboard-empty";
    empty.textContent = "暂无建议动作（有失败信号后出现）";
    warApActions.appendChild(empty);
    return;
  }
  if (pending.length) {
    const title = document.createElement("div");
    title.className = "ap-group-title";
    title.textContent = "待执行 / 建议";
    warApActions.appendChild(title);
    for (const act of pending) {
      const row = document.createElement("div");
      row.className = "ap-item";
      const main = act.type === "set"
        ? `${act.key} → ${JSON.stringify(act.value)}`
        : act.type || "action";
      row.innerHTML = `<strong>${main}</strong><span>${act.reason || ""}</span>`;
      warApActions.appendChild(row);
    }
  }
  if (last.length) {
    const title = document.createElement("div");
    title.className = "ap-group-title";
    title.textContent = "最近已应用";
    warApActions.appendChild(title);
    for (const act of last.slice(-6).reverse()) {
      const row = document.createElement("div");
      row.className = "ap-item applied";
      const main = act.type === "set"
        ? `${act.key} → ${JSON.stringify(act.value)}`
        : act.type || "action";
      row.innerHTML = `<strong>${main}</strong><span>${act.reason || ""}</span>`;
      warApActions.appendChild(row);
    }
  }
}

function renderPresets(list) {
  if (!presetRow) return;
  const presets = Array.isArray(list) ? list : [];
  if (!presets.length) {
    presetRow.innerHTML = `<p class="dashboard-empty">菜谱加载中…</p>`;
    return;
  }
  presetRow.innerHTML = "";
  for (const p of presets) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "preset-chip";
    btn.dataset.presetId = p.id;
    btn.innerHTML = `<strong>${p.name}</strong><span>${p.blurb || ""}</span>`;
    btn.addEventListener("click", () => {
      applyPreset(p.id).catch((error) => setMessage(error.message));
    });
    presetRow.appendChild(btn);
  }
}

async function loadPresets() {
  const data = await requestJson("/api/ops/presets");
  renderPresets(data.presets || []);
}

async function applyPreset(presetId) {
  const data = await requestJson(`/api/ops/presets/${presetId}/apply`, { method: "POST" });
  if (data.config) applyConfig(data.config);
  setMessage(`已应用菜谱：${(data.preset && data.preset.name) || presetId}`);
  loadWarRoom({ silent: true }).catch(() => {});
}

async function setAutopilotEnabled(enabled) {
  await requestJson("/api/ops/autopilot", {
    method: "POST",
    body: JSON.stringify({ enabled: Boolean(enabled) }),
  });
  setMessage(enabled ? "Auto Pilot 已开启" : "Auto Pilot 已关闭");
  await loadWarRoom({ silent: true });
}

async function runAutopilotOnce() {
  const data = await requestJson("/api/ops/autopilot/evaluate", {
    method: "POST",
    body: JSON.stringify({ apply: true }),
  });
  const n = (((data.applied || {}).applied) || []).length;
  setMessage(n ? `Auto Pilot 已应用 ${n} 项` : "评估完成：无需调整或信号不足");
  if (data.applied && data.applied.settings) {
    applyConfig(data.applied.settings);
  }
  await loadWarRoom({ silent: true });
}

function startWarRoomPolling() {
  if (warRoomTimer) clearInterval(warRoomTimer);
  // 看板指标不需要 2–3s 刷新；Solver 健康检查另有服务端缓存。
  // 任务进度仍由 job polling（~1.2s）负责。
  warRoomTimer = setInterval(() => {
    loadWarRoom({ silent: true }).catch(() => {});
  }, 10000);
}

function stopWarRoomPolling() {
  if (warRoomTimer) {
    clearInterval(warRoomTimer);
    warRoomTimer = null;
  }
}

async function loadWarRoom({ silent = false } = {}) {
  const data = await requestJson("/api/ops/war-room");
  warRoomSnapshot = data;
  renderWarRoom(data);
  if (!silent && data.job && data.job.job_id && data.job.running) {
    rememberJobId(data.job.job_id);
  }
  return data;
}

function renderWarRoom(data) {
  if (!data || !data.ok) return;
  const job = data.job || {};
  const inv = data.inventory || {};
  const thr = data.throughput || {};
  const solver = data.solver || {};
  const domains = data.domains || {};
  const failures = data.failures || {};
  const runtime = data.runtime || {};

  const success = Number(job.success_count || 0);
  const fail = Number(job.fail_count || 0);
  const target = Number(job.register_count || runtime.register_count || 0);
  const running = isActiveJobStatus(job);
  const stopping = job.status === "stopping" || Boolean(job.stop_requested);

  if (dashboardStatusText) {
    dashboardStatusText.textContent = job.status || statusText.textContent || "idle";
    dashboardStatusText.classList.toggle("is-running", running);
  }
  if (dashboardRunNote) {
    dashboardRunNote.textContent = `成功 ${success} / 失败 ${fail}${target ? ` · 目标 ${target}` : ""}`;
  }
  if (statusText && job.status) statusText.textContent = job.status;
  if (statsText) statsText.textContent = `成功 ${success} / 失败 ${fail}`;
  // 停止中禁用再次点击；真正结束后也禁用
  if (warStopBtn) warStopBtn.disabled = !running || stopping;

  if (warProgressText) warProgressText.textContent = `${success}/${target || "—"}`;
  if (warProgressSub) {
    const rate = thr.success_rate != null ? `${thr.success_rate}%` : "—";
    const elapsed = thr.elapsed_sec != null ? formatDuration(thr.elapsed_sec) : "—";
    warProgressSub.textContent = thr.terminal
      ? `成功率 ${rate} · 总耗时 ${elapsed}`
      : `成功率 ${rate} · 已运行 ${elapsed}`;
  }
  const progressBar = document.querySelector("#warProgressBar");
  if (progressBar) {
    const pct = target > 0 ? Math.min(100, Math.round((success / target) * 100)) : 0;
    progressBar.style.setProperty("--metric-pct", `${pct}%`);
  }
  if (warThroughputText) {
    warThroughputText.textContent =
      thr.rate_per_min != null ? `产能 ${thr.rate_per_min}/min` : "产能 —";
  }
  if (warEtaText) {
    if (thr.terminal) {
      warEtaText.textContent = "已结束";
    } else {
      warEtaText.textContent = thr.eta_sec != null ? `ETA ${formatDuration(thr.eta_sec)}` : "ETA —";
    }
  }

  dashboardMetricValue(dashboardTotalAccounts, inv.total || 0);
  dashboardMetricValue(dashboardRefreshAccounts, inv.refresh || 0);
  dashboardMetricValue(dashboardHealthyAccounts, inv.healthy || 0);
  dashboardMetricValue(dashboardNeedActionAccounts, inv.need_action || 0);
  if (warInventorySub) {
    warInventorySub.textContent = `Refresh ${inv.refresh || 0} · 需处理 ${inv.need_action || 0}`;
  }

  if (warSolverState) {
    if (!solver.enabled) warSolverState.textContent = "关";
    else warSolverState.textContent = solver.reachable ? "在线" : "离线";
  }
  if (warSolverSub) {
    const lat = solver.latency_ms != null ? `${solver.latency_ms}ms` : "—";
    warSolverSub.textContent = solver.enabled
      ? `${solver.reachable ? "可达" : "不可达"} · ${lat}`
      : "已禁用";
  }
  if (warSolverTile) {
    warSolverTile.classList.toggle("metric-ok", Boolean(solver.enabled && solver.reachable));
    warSolverTile.classList.toggle("metric-alert", Boolean(solver.enabled && !solver.reachable));
  }

  if (warDomainAvailable) warDomainAvailable.textContent = String(domains.available_count ?? 0);
  if (warDomainSub) {
    warDomainSub.textContent = `冷却 ${domains.cooldown_count || 0} · 禁用 ${domains.disabled_count || 0}`;
  }
  if (warDomainTile) {
    const avail = Number(domains.available_count || 0);
    const total = Number(domains.total_count || 0);
    warDomainTile.classList.toggle("metric-alert", total > 0 && avail === 0);
    warDomainTile.classList.toggle("metric-ok", avail > 0);
  }
  if (warDomainPin) {
    warDomainPin.textContent = domains.pinpoint_domain
      ? `黄金矿工: ${domains.pinpoint_domain}`
      : domains.grouping
        ? "分组调度开启"
        : "";
  }
  if (warGeneratedAt) warGeneratedAt.textContent = data.generated_at || "";

  if (warAlerts) {
    warAlerts.innerHTML = "";
    for (const alert of data.alerts || []) {
      const el = document.createElement("div");
      el.className = `alert-chip level-${alert.level || "info"}`;
      el.textContent = alert.text || "";
      warAlerts.appendChild(el);
    }
    if (!(data.alerts || []).length) {
      const el = document.createElement("div");
      el.className = "alert-chip level-ok";
      el.textContent = "态势正常";
      warAlerts.appendChild(el);
    }
  }

  if (dashboardPipeline) {
    dashboardPipeline.innerHTML = "";
    const total = Number(inv.total || 0);
    const flow = [
      ["注册账号", total, "账号池总量"],
      ["Refresh Token", inv.refresh || 0, "可推送 sub2api"],
      ["健康可用", inv.healthy || 0, "最近检查通过"],
      ["grok2api", inv.grok2api || 0, "远端已入池"],
      ["sub2api", inv.sub2api || 0, "远端已导入"],
    ];
    for (const [label, value, caption] of flow) {
      const step = document.createElement("div");
      step.className = "flow-step";
      step.style.setProperty("--flow-percent", percentText(value, total));
      const name = document.createElement("span");
      name.textContent = label;
      const number = document.createElement("strong");
      number.textContent = String(value);
      const note = document.createElement("small");
      note.textContent = `${caption} · ${percentText(value, total)}`;
      const line = document.createElement("i");
      step.append(name, number, note, line);
      dashboardPipeline.appendChild(step);
    }
  }

  if (warFailMix) {
    warFailMix.innerHTML = "";
    const reasons = failures.reasons || [];
    if (!reasons.length) {
      const empty = document.createElement("p");
      empty.className = "dashboard-empty";
      empty.textContent = "暂无失败信号（运行任务后根据日志归因）";
      warFailMix.appendChild(empty);
    } else {
      const totalFail = reasons.reduce((s, r) => s + Number(r.count || 0), 0);
      for (const row of reasons) {
        const label = FAIL_REASON_LABELS[row.reason] || row.reason;
        renderMixRow(warFailMix, label, row.count, totalFail, "bad");
      }
    }
  }

  if (dashboardHealthMix) {
    dashboardHealthMix.innerHTML = "";
    const total = Number(inv.total || 0);
    renderMixRow(dashboardHealthMix, "可用", inv.healthy || 0, total, "ok");
    renderMixRow(dashboardHealthMix, "未检查", inv.untested || 0, total);
    renderMixRow(dashboardHealthMix, "资料不完整", inv.incomplete || 0, total, "warn");
    renderMixRow(dashboardHealthMix, "失效", inv.unhealthy || 0, total, "bad");
  }

  if (dashboardPushMix) {
    dashboardPushMix.innerHTML = "";
    const total = Number(inv.total || 0);
    renderMixRow(dashboardPushMix, "grok2api 已推送", inv.grok2api || 0, total, "ok");
    renderMixRow(dashboardPushMix, "sub2api 已推送", inv.sub2api || 0, total, "ok");
    renderMixRow(dashboardPushMix, "CPA 已推送", inv.cpa || 0, total, "ok");
    renderMixRow(dashboardPushMix, "Refresh Token 覆盖", inv.refresh || 0, total);
  }

  if (warDomainHeat) {
    warDomainHeat.innerHTML = "";
    const rows = domains.domains || [];
    if (!rows.length) {
      const empty = document.createElement("p");
      empty.className = "dashboard-empty";
      empty.textContent = domains.ok === false
        ? `域名池读取失败: ${domains.error || "unknown"}`
        : "未配置 mail_domains / defaultDomains，或池为空";
      warDomainHeat.appendChild(empty);
    } else {
      for (const d of rows) {
        const card = document.createElement("button");
        card.type = "button";
        card.className = "domain-chip";
        if (d.is_disabled) card.classList.add("is-disabled");
        else if ((d.cooldown_remaining_sec || 0) > 0) card.classList.add("is-cool");
        else if (d.is_available) card.classList.add("is-ok");
        else card.classList.add("is-bad");
        const title = document.createElement("strong");
        title.textContent = d.domain || "—";
        const meta = document.createElement("span");
        const cool = Number(d.cooldown_remaining_sec || 0);
        meta.textContent = cool > 0
          ? `冷却 ${formatDuration(cool)} · 成功 ${d.success_count || 0}`
          : `✓${d.success_count || 0}  ✗${d.fail_count || 0}  pick ${d.pick_count || 0}`;
        card.append(title, meta);
        card.title = "点击清除该域计数/冷却";
        card.addEventListener("click", () => {
          clearWarDomain(d.domain).catch((error) => setMessage(error.message));
        });
        warDomainHeat.appendChild(card);
      }
    }
  }

  if (warFailFeed) {
    warFailFeed.innerHTML = "";
    const items = failures.recent_fails || [];
    if (!items.length) {
      const empty = document.createElement("p");
      empty.className = "dashboard-empty";
      empty.textContent = "暂无失败条目";
      warFailFeed.appendChild(empty);
    } else {
      for (const item of items.slice().reverse()) {
        const row = document.createElement("div");
        row.className = "fail-item";
        const tag = document.createElement("span");
        tag.className = "fail-tag";
        tag.textContent = FAIL_REASON_LABELS[item.reason] || item.reason || "other";
        const line = document.createElement("code");
        line.textContent = item.line || "";
        row.append(tag, line);
        warFailFeed.appendChild(row);
      }
    }
  }

  if (warRuntimeChips) {
    warRuntimeChips.innerHTML = "";
    const chips = [
      ["模式", runtime.signup_mode || "—"],
      ["邮箱", runtime.email_provider || "—"],
      ["并发", String(runtime.register_threads ?? "—")],
      ["代理", runtime.proxy_configured ? "已配" : "直连"],
      ["Solver", runtime.turnstile_solver_enabled ? "开" : "关"],
      ["Job", job.job_id ? String(job.job_id).slice(0, 8) : "—"],
    ];
    for (const [k, v] of chips) {
      const chip = document.createElement("div");
      chip.className = "runtime-chip";
      chip.innerHTML = `<span>${k}</span><strong>${v}</strong>`;
      warRuntimeChips.appendChild(chip);
    }
  }

  if (dashboardSources) {
    dashboardSources.innerHTML = "";
    const sources = inv.sources || [];
    if (!sources.length) {
      const empty = document.createElement("p");
      empty.className = "dashboard-empty";
      empty.textContent = "暂无账号批次";
      dashboardSources.appendChild(empty);
    } else {
      for (const src of sources) {
        const item = document.createElement("div");
        item.className = "source-item";
        const name = document.createElement("span");
        name.textContent = src.source || "未知";
        const value = document.createElement("strong");
        value.textContent = `${src.count || 0} 个`;
        item.append(name, value);
        dashboardSources.appendChild(item);
      }
    }
  }

  if (warRecentLogs) {
    const lines = data.recent_logs || [];
    warRecentLogs.textContent = lines.length ? lines.join("\n") : "暂无任务日志";
    warRecentLogs.scrollTop = warRecentLogs.scrollHeight;
  }

  renderWarCharts(data);
  renderEconomics(data.economics);
  renderAutopilot(data.autopilot);
  if (data.presets && data.presets.length && presetRow && !presetRow.dataset.ready) {
    renderPresets(data.presets);
    presetRow.dataset.ready = "1";
  }
}

function renderDashboard() {
  if (warRoomSnapshot) {
    renderWarRoom(warRoomSnapshot);
    return;
  }
  if (!dashboardTotalAccounts) return;
  const stats = accountDashboardStats();
  dashboardMetricValue(dashboardTotalAccounts, stats.total);
  dashboardMetricValue(dashboardRefreshAccounts, stats.refresh);
  dashboardMetricValue(dashboardHealthyAccounts, stats.healthy);
  dashboardMetricValue(dashboardNeedActionAccounts, stats.needAction);
  if (dashboardStatusText) dashboardStatusText.textContent = statusText.textContent || "就绪";
  if (dashboardRunNote) dashboardRunNote.textContent = statsText.textContent || "成功 0 / 失败 0";
  if (warInventorySub) {
    warInventorySub.textContent = `Refresh ${stats.refresh} · 需处理 ${stats.needAction}`;
  }
}

async function clearWarDomain(domain) {
  if (!domain) return;
  await requestJson("/api/mail-domain-pool/clear-domain", {
    method: "POST",
    body: JSON.stringify({ domain }),
  });
  setMessage(`已清除域名计数: ${domain}`);
  await loadWarRoom();
}

async function resetWarDomains() {
  await requestJson("/api/mail-domain-pool/reset", { method: "POST" });
  setMessage("域名池运行时状态已重置");
  await loadWarRoom();
}

function syncSelectPageAccounts() {
  if (!selectPageAccounts) return;
  const pageAccounts = currentPageAccounts();
  const selectedCount = pageAccounts.filter((account) => selectedAccountIdsSet.has(account.id)).length;
  selectPageAccounts.checked = pageAccounts.length > 0 && selectedCount === pageAccounts.length;
  selectPageAccounts.indeterminate = selectedCount > 0 && selectedCount < pageAccounts.length;
  selectPageAccounts.disabled = pageAccounts.length === 0;
}

function renderPagination() {
  if (!accountPagination) return;
  accountPagination.innerHTML = "";
  const totalPages = accountTotalPages();
  const filtered = filteredAccounts();
  const start = filtered.length ? (accountPage - 1) * accountTablePrefs.pageSize + 1 : 0;
  const end = Math.min(filtered.length, accountPage * accountTablePrefs.pageSize);
  const summary = document.createElement("span");
  summary.className = "pagination-summary";
  summary.textContent = `${start}-${end} / ${filtered.length}`;
  accountPagination.appendChild(summary);

  const prevButton = document.createElement("button");
  prevButton.type = "button";
  prevButton.className = "page-button";
  prevButton.textContent = "上一页";
  prevButton.disabled = accountPage <= 1;
  prevButton.addEventListener("click", () => {
    accountPage -= 1;
    renderAccounts();
  });
  accountPagination.appendChild(prevButton);

  const pageText = document.createElement("span");
  pageText.className = "page-current";
  pageText.textContent = `${accountPage} / ${totalPages}`;
  accountPagination.appendChild(pageText);

  const nextButton = document.createElement("button");
  nextButton.type = "button";
  nextButton.className = "page-button";
  nextButton.textContent = "下一页";
  nextButton.disabled = accountPage >= totalPages;
  nextButton.addEventListener("click", () => {
    accountPage += 1;
    renderAccounts();
  });
  accountPagination.appendChild(nextButton);
}

function renderAccounts() {
  if (!accountsBody) return;
  selectedAccountIdsSet = new Set(selectedAccountIds());
  clampAccountPage();
  renderAccountsHead();
  renderAccountColumns();
  accountsBody.innerHTML = "";
  const filtered = filteredAccounts();
  const filterHint =
    filtered.length !== accounts.length
      ? `，筛选后 ${filtered.length} 个`
      : "";
  accountsSummary.textContent = `共 ${accounts.length} 个账号${filterHint}，已选择 ${selectedAccountIdsSet.size} 个`;
  if (accountPageSize) accountPageSize.value = String(accountTablePrefs.pageSize);
  if (accountSearchInput && accountSearchInput.value !== accountSearchQuery) {
    accountSearchInput.value = accountSearchQuery;
  }
  if (accountPushFilter) accountPushFilter.value = accountPushFilterValue;
  if (!filtered.length) {
    const row = document.createElement("tr");
    const emptyText = accounts.length
      ? "没有匹配的账号，试试清空搜索/筛选"
      : "暂无账号，注册成功后会出现在这里";
    row.innerHTML = `<td colspan="${visibleAccountColumns().length}" class="empty">${emptyText}</td>`;
    accountsBody.appendChild(row);
    syncSelectPageAccounts();
    renderPagination();
    return;
  }
  const pageAccounts = currentPageAccounts();
  for (const [pageIndex, account] of pageAccounts.entries()) {
    const rowNumber = (accountPage - 1) * accountTablePrefs.pageSize + pageIndex + 1;
    const row = document.createElement("tr");
    for (const column of visibleAccountColumns()) {
      const cell = document.createElement("td");
      if (column.key === "select") {
        const checkbox = document.createElement("input");
        checkbox.className = "account-check";
        checkbox.type = "checkbox";
        checkbox.value = account.id;
        checkbox.checked = selectedAccountIdsSet.has(account.id);
        checkbox.title = account.has_refresh_token
          ? ""
          : "可推送到 grok2api；缺少 Refresh Token 时不能推送到 sub2api 或 CPA";
        checkbox.addEventListener("change", () => {
          if (checkbox.checked) selectedAccountIdsSet.add(account.id);
          else selectedAccountIdsSet.delete(account.id);
          accountsSummary.textContent = `共 ${accounts.length} 个账号${filterHint}，已选择 ${selectedAccountIdsSet.size} 个`;
          syncSelectPageAccounts();
        });
        cell.appendChild(checkbox);
        row.appendChild(cell);
        continue;
      }
      const value = accountCellValue(account, column.key, rowNumber);
      const rawText = String(value ?? "");
      if (STATUS_COLUMN_KEYS.has(column.key)) {
        const formatted = formatAccountStatusDisplay(rawText);
        cell.textContent = formatted.display;
        if (formatted.title) cell.title = formatted.title;
        if (
          rawText.startsWith("失败") ||
          rawText.includes("失败") ||
          rawText.includes("探测失败")
        ) {
          cell.classList.add("status-failed");
        } else if (rawText === "已推送" || rawText === "可用") {
          cell.classList.add("status-ok");
        }
        if (column.key === "sub2api" && account.sub2api_probe_error) {
          cell.title = `${formatted.title || rawText}\n${account.sub2api_probe_error}`.trim();
        } else if (column.key === "sub2api" && account.sub2api_remote_id) {
          cell.title = `${formatted.title || rawText}\nremote id: ${account.sub2api_remote_id}`.trim();
        }
      } else {
        cell.textContent = rawText;
        if (column.key === "created" && account.created_at) {
          // batch = 任务启动文件名时间（同批相同）；account = 每个号注册成功时写入
          const src = account.created_at_source === "account" ? "账号成功时间" : "任务批次时间";
          cell.title = `${account.created_at}（${src}）`;
        }
      }
      if (column.className) cell.className = `${cell.className} ${column.className}`.trim();
      row.appendChild(cell);
    }
    accountsBody.appendChild(row);
  }
  syncSelectPageAccounts();
  renderPagination();
}

async function loadAccounts() {
  const payload = await requestJson("/api/accounts");
  accounts = payload.accounts || [];
  renderDashboard();
  renderAccounts();
}

async function deleteSelectedAccounts() {
  const accountIds = selectedAccountIds();
  if (!accountIds.length) {
    setMessage("请选择账号再删除");
    return;
  }
  if (!window.confirm(`确定删除选中的 ${accountIds.length} 个账号吗？此操作不可恢复。`)) return;

  deleteAccountsBtn.disabled = true;
  deleteAccountsBtn.textContent = `删除中 ${accountIds.length} 个...`;
  setMessage(`正在删除 ${accountIds.length} 个账号`);
  try {
    const result = await requestJson("/api/accounts", {
      method: "DELETE",
      body: JSON.stringify({ account_ids: accountIds }),
    });
    accountIds.forEach((id) => {
      selectedAccountIdsSet.delete(id);
      delete accountHealthStatus[id];
      delete accountPushStatus[id];
      delete accountGrok2apiPushStatus[id];
      delete accountCpaPushStatus[id];
    });
    accounts = result.accounts || [];
    setMessage(result.message || `已删除 ${result.deleted || 0} 个账号`);
  } catch (error) {
    setMessage(`删除账号失败：${error.message}`);
  } finally {
    deleteAccountsBtn.disabled = false;
    deleteAccountsBtn.textContent = "删除选中";
    renderDashboard();
    renderAccounts();
  }
}

async function checkSelectedAccountHealth() {
  const accountIds = selectedAccountIds();
  if (!accountIds.length) {
    setMessage("请选择账号再做健康检查");
    return;
  }
  checkHealthBtn.disabled = true;
  checkHealthBtn.textContent = `检查中 ${accountIds.length} 个...`;
  accountIds.forEach((id) => {
    accountHealthStatus[id] = "检查中";
  });
  renderAccounts();
  setMessage(`开始健康检查：${accountIds.length} 个账号`);
  try {
    const result = await requestJson("/api/accounts/check-health", {
      method: "POST",
      body: JSON.stringify({ ...formPayload(), account_ids: accountIds }),
    });
    if (Array.isArray(result.accounts)) {
      const returned = new Map(result.accounts.map((account) => [account.id, account]));
      accounts = accounts.map((account) => returned.get(account.id) || account);
      accountIds.forEach((id) => {
        const account = returned.get(id);
        accountHealthStatus[id] = account?.health_status_text || "未检查";
      });
    }
    setMessage(result.message || `健康检查完成：可用 ${result.healthy || 0} 个，异常 ${result.failed || 0} 个`);
  } catch (error) {
    accountIds.forEach((id) => {
      accountHealthStatus[id] = `失败：${error.message}`;
    });
    setMessage(`健康检查失败：${error.message}`);
  } finally {
    checkHealthBtn.disabled = false;
    checkHealthBtn.textContent = "健康检查";
    renderAccounts();
  }
}

async function importSelectedToSub2api() {
  const accountIds = selectedAccountIds().filter((id) => {
    const account = accounts.find((item) => item.id === id);
    return account?.has_refresh_token;
  });
  if (!accountIds.length) {
    setMessage("请选择带 Refresh Token 的账号再推送");
    return;
  }
  pushingToSub2api = true;
  importSub2apiBtn.disabled = true;
  importSub2apiBtn.textContent = `推送中 ${accountIds.length} 个...`;
  accountIds.forEach((id) => {
    accountPushStatus[id] = "推送中";
  });
  renderAccounts();
  setMessage(`开始推送到 sub2api：${accountIds.length} 个账号`);
  const payload = { ...formPayload(), account_ids: accountIds };
  try {
    const result = await requestJson("/api/accounts/import/sub2api", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (Array.isArray(result.accounts)) {
      const returned = new Map(result.accounts.map((account) => [account.id, account]));
      accounts = accounts.map((account) => returned.get(account.id) || account);
      accountIds.forEach((id) => {
        const account = returned.get(id);
        accountPushStatus[id] = account?.sub2api_status_text || (account?.sub2api_status === "pushed" ? "已推送" : "未推送");
      });
    } else {
      accountIds.forEach((id) => {
        accountPushStatus[id] = result.status === "partial_failed" ? "失败：请刷新查看详情" : "已推送";
      });
    }
    setMessage(`${result.message || `已推送到 sub2api：${result.total} 个账号`}。${result.warning || ""}`);
  } catch (error) {
    accountIds.forEach((id) => {
      accountPushStatus[id] = `失败：${error.message}`;
    });
    setMessage(`推送 sub2api 失败：${error.message}`);
  } finally {
    pushingToSub2api = false;
    importSub2apiBtn.disabled = false;
    importSub2apiBtn.textContent = "推送到 sub2api";
    renderAccounts();
  }
}

async function probeSelectedOnSub2api() {
  const accountIds = selectedAccountIds();
  if (!accountIds.length) {
    setMessage("请选择要重新探测的账号（可先用筛选「sub2api 探测失败」）");
    return;
  }
  // 不改过滤条件；「探测中」仍算在「探测失败」筛选内，列表不会被滤空
  if (probeSub2apiBtn) {
    probeSub2apiBtn.disabled = true;
    probeSub2apiBtn.textContent = `探测中 ${accountIds.length} 个...`;
  }
  accountIds.forEach((id) => {
    accountPushStatus[id] = "探测中";
  });
  renderAccounts();
  setMessage(`开始 sub2api 重新探测：${accountIds.length} 个账号（请稍候，每号约数秒～二十秒）`);
  try {
    const result = await requestJson("/api/accounts/sub2api/probe", {
      method: "POST",
      body: JSON.stringify({ ...formPayload(), account_ids: accountIds }),
    });
    if (Array.isArray(result.accounts)) {
      const returned = new Map(result.accounts.map((account) => [account.id, account]));
      accounts = accounts.map((account) => returned.get(account.id) || account);
      accountIds.forEach((id) => {
        const account = returned.get(id);
        if (account) {
          accountPushStatus[id] =
            account.sub2api_status_text ||
            (account.sub2api_status === "pushed"
              ? "已推送"
              : account.sub2api_status === "probe_failed"
                ? "已入库·探测失败"
                : "未推送");
        } else {
          delete accountPushStatus[id];
        }
      });
    } else {
      accountIds.forEach((id) => {
        delete accountPushStatus[id];
      });
    }
    setMessage(result.message || "sub2api 重新探测完成");
  } catch (error) {
    accountIds.forEach((id) => {
      accountPushStatus[id] = `失败：${error.message}`;
    });
    setMessage(`sub2api 重新探测失败：${error.message}`);
  } finally {
    if (probeSub2apiBtn) {
      probeSub2apiBtn.disabled = false;
      probeSub2apiBtn.textContent = "重新探测 sub2api";
    }
    renderAccounts();
  }
}

async function deleteSelectedSub2apiRemote() {
  const accountIds = selectedAccountIds();
  if (!accountIds.length) {
    setMessage("请选择要删除远端的账号");
    return;
  }
  if (
    !window.confirm(
      `确认删除选中 ${accountIds.length} 个账号在 sub2api 上的远端记录？\n（只删远端，本地账号文件保留；状态会改回未推送）`
    )
  ) {
    return;
  }
  // 不改过滤条件；删除过程中状态「删除远端中」仍留在「探测失败」筛选内
  if (deleteSub2apiRemoteBtn) {
    deleteSub2apiRemoteBtn.disabled = true;
    deleteSub2apiRemoteBtn.textContent = `删除远端中 ${accountIds.length}...`;
  }
  accountIds.forEach((id) => {
    accountPushStatus[id] = "删除远端中";
  });
  renderAccounts();
  setMessage(`正在删除 sub2api 远端：${accountIds.length} 个账号…`);
  try {
    const result = await requestJson("/api/accounts/sub2api/delete-remote", {
      method: "POST",
      body: JSON.stringify({ ...formPayload(), account_ids: accountIds }),
    });
    if (Array.isArray(result.accounts)) {
      const returned = new Map(result.accounts.map((account) => [account.id, account]));
      accounts = accounts.map((account) => returned.get(account.id) || account);
      accountIds.forEach((id) => {
        const account = returned.get(id);
        if (account) accountPushStatus[id] = account.sub2api_status_text || "未推送";
        else delete accountPushStatus[id];
      });
    } else {
      accountIds.forEach((id) => {
        delete accountPushStatus[id];
      });
    }
    setMessage(result.message || "已删除 sub2api 远端账号");
  } catch (error) {
    accountIds.forEach((id) => {
      accountPushStatus[id] = `失败：${error.message}`;
    });
    setMessage(`删除 sub2api 远端失败：${error.message}`);
  } finally {
    if (deleteSub2apiRemoteBtn) {
      deleteSub2apiRemoteBtn.disabled = false;
      deleteSub2apiRemoteBtn.textContent = "删除远端 sub2api";
    }
    renderAccounts();
  }
}

async function importSelectedToGrok2api() {
  const accountIds = selectedAccountIds();
  if (!accountIds.length) {
    setMessage("请选择账号再推送到 grok2api");
    return;
  }
  pushingToGrok2api = true;
  importGrok2apiBtn.disabled = true;
  importGrok2apiBtn.textContent = `推送中 ${accountIds.length} 个...`;
  accountIds.forEach((id) => {
    accountGrok2apiPushStatus[id] = "推送中";
  });
  renderAccounts();
  setMessage(`开始推送到 grok2api：${accountIds.length} 个账号`);
  const payload = { ...formPayload(), account_ids: accountIds };
  try {
    const result = await requestJson("/api/accounts/import/grok2api", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (Array.isArray(result.accounts)) {
      const returned = new Map(result.accounts.map((account) => [account.id, account]));
      accounts = accounts.map((account) => returned.get(account.id) || account);
      accountIds.forEach((id) => {
        const account = returned.get(id);
        accountGrok2apiPushStatus[id] = account?.grok2api_status_text || (account?.grok2api_status === "pushed" ? "已推送" : "未推送");
      });
    } else {
      accountIds.forEach((id) => {
        accountGrok2apiPushStatus[id] = result.status === "partial_failed" ? "失败：请刷新查看详情" : "已推送";
      });
    }
    setMessage(`${result.message || `已推送到 grok2api：${result.total} 个账号`}。${result.warning || ""}`);
  } catch (error) {
    accountIds.forEach((id) => {
      accountGrok2apiPushStatus[id] = `失败：${error.message}`;
    });
    setMessage(`推送 grok2api 失败：${error.message}`);
  } finally {
    pushingToGrok2api = false;
    importGrok2apiBtn.disabled = false;
    importGrok2apiBtn.textContent = "推送到 grok2api";
    renderAccounts();
  }
}

async function importSelectedToCpa() {
  const accountIds = selectedAccountIds();
  if (!accountIds.length) {
    setMessage("请选择账号再推送到 CPA");
    return;
  }
  pushingToCpa = true;
  importCpaBtn.disabled = true;
  importCpaBtn.textContent = `推送中 ${accountIds.length} 个...`;
  accountIds.forEach((id) => {
    accountCpaPushStatus[id] = "推送中";
  });
  renderAccounts();
  setMessage(`开始推送到 CPA：${accountIds.length} 个账号`);
  try {
    const result = await requestJson("/api/accounts/import/cpa", {
      method: "POST",
      body: JSON.stringify({ ...formPayload(), account_ids: accountIds }),
    });
    if (Array.isArray(result.accounts)) {
      const returned = new Map(result.accounts.map((account) => [account.id, account]));
      accounts = accounts.map((account) => returned.get(account.id) || account);
      accountIds.forEach((id) => {
        const account = returned.get(id);
        accountCpaPushStatus[id] = account?.cpa_status_text || (account?.cpa_status === "pushed" ? "已推送" : "未推送");
      });
    } else {
      accountIds.forEach((id) => {
        accountCpaPushStatus[id] = result.status === "partial_failed" ? "失败：请刷新查看详情" : "已推送";
      });
    }
    setMessage(`${result.message || `已推送到 CPA：${result.total} 个账号`}。${result.warning || ""}`);
  } catch (error) {
    accountIds.forEach((id) => {
      accountCpaPushStatus[id] = `失败：${error.message}`;
    });
    setMessage(`推送 CPA 失败：${error.message}`);
  } finally {
    pushingToCpa = false;
    importCpaBtn.disabled = false;
    importCpaBtn.textContent = "推送到 CPA";
    renderAccounts();
  }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => {
    // 重叠轮询直接跳过（pollInFlight）；不要在这里强制 await 以免卡死 interval
    pollJob().catch((error) => setMessage(error.message));
  }, 1200);
  pollJob().catch((error) => setMessage(error.message));
}

function setCfGlobalStatus(text) {
  if (cfGlobalStatus) cfGlobalStatus.textContent = text || "";
}

function mailDomainsFromForm() {
  const data = formPayload();
  return String(data.mail_domains || data.defaultDomains || "").trim();
}

async function testCfGlobalAuth() {
  setCfGlobalStatus("正在测试 Cloudflare 全局鉴权…");
  setMessage("正在测试 Cloudflare 全局鉴权…");
  try {
    // 先保存，避免只改了表单没落盘
    await saveConfig().catch(() => {});
    const result = await requestJson("/api/cloudflare/global/test", {
      method: "POST",
      body: JSON.stringify(formPayload()),
    });
    const accounts = Array.isArray(result.accounts) ? result.accounts : [];
    const names = accounts
      .slice(0, 3)
      .map((a) => a.name || a.id)
      .filter(Boolean)
      .join("、");
    const msg =
      result.message ||
      `鉴权成功${names ? `（账户: ${names}${accounts.length > 3 ? "…" : ""}）` : ""}`;
    setCfGlobalStatus(msg);
    setMessage(msg);
  } catch (error) {
    setCfGlobalStatus(`鉴权失败：${error.message}`);
    setMessage(`Cloudflare 全局鉴权失败：${error.message}`);
  }
}

async function ensureCfGlobalZones() {
  const domains = mailDomainsFromForm();
  if (!domains) {
    setMessage("请先填写 mail_domains / defaultDomains");
    return;
  }
  if (!window.confirm(`把以下域名查询/托管到 Cloudflare？\n\n${domains}`)) return;
  setCfGlobalStatus("正在查询/托管域名…");
  setMessage("正在查询/托管域名到 Cloudflare…");
  try {
    await saveConfig().catch(() => {});
    const result = await requestJson("/api/cloudflare/global/zones", {
      method: "POST",
      body: JSON.stringify({ ...formPayload(), domains }),
    });
    const items = Array.isArray(result.items) ? result.items : [];
    const lines = items.map((it) => {
      const ns = (it.name_servers || []).slice(0, 2).join(", ");
      return `${it.domain}: ${it.msg || it.status}${ns ? ` | NS ${ns}` : ""}`;
    });
    const summary = `域名托管结果：成功 ${result.total || 0} / 失败 ${result.failed || 0}`;
    setCfGlobalStatus(summary + (lines.length ? `。${lines.slice(0, 4).join("；")}` : ""));
    setMessage(summary);
  } catch (error) {
    setCfGlobalStatus(`域名托管失败：${error.message}`);
    setMessage(`域名托管失败：${error.message}`);
  }
}

async function ensureCfGlobalEmailDns() {
  const domains = mailDomainsFromForm();
  if (!domains) {
    setMessage("请先填写 mail_domains / defaultDomains");
    return;
  }
  if (!window.confirm(`为以下域名补齐 Email Routing MX/SPF？\n\n${domains}`)) return;
  setCfGlobalStatus("正在补齐邮件 MX/SPF…");
  setMessage("正在补齐 Cloudflare Email Routing DNS…");
  try {
    await saveConfig().catch(() => {});
    const result = await requestJson("/api/cloudflare/global/email-dns", {
      method: "POST",
      body: JSON.stringify({ ...formPayload(), domains }),
    });
    const items = Array.isArray(result.items) ? result.items : [];
    const lines = items.map((it) => `${it.domain}: ${it.msg || (it.ok ? "ok" : "fail")}`);
    const summary = `邮件 DNS：成功 ${result.total || 0} / 失败 ${result.failed || 0}`;
    setCfGlobalStatus(summary + (lines.length ? `。${lines.slice(0, 4).join("；")}` : ""));
    setMessage(summary);
  } catch (error) {
    setCfGlobalStatus(`邮件 DNS 失败：${error.message}`);
    setMessage(`邮件 DNS 失败：${error.message}`);
  }
}

document.querySelector("#saveBtn").addEventListener("click", () => {
  saveConfig().catch((error) => setMessage(error.message));
});

if (cfGlobalTestBtn) {
  cfGlobalTestBtn.addEventListener("click", () => {
    testCfGlobalAuth().catch((error) => setMessage(error.message));
  });
}
if (cfGlobalZonesBtn) {
  cfGlobalZonesBtn.addEventListener("click", () => {
    ensureCfGlobalZones().catch((error) => setMessage(error.message));
  });
}
if (cfGlobalEmailDnsBtn) {
  cfGlobalEmailDnsBtn.addEventListener("click", () => {
    ensureCfGlobalEmailDns().catch((error) => setMessage(error.message));
  });
}

async function deployCfEmailWorker() {
  const data = formPayload();
  const workerName = String(data.cf_email_worker_name || "openai-cpa-email").trim() || "openai-cpa-email";
  const secret = String(data.email_webhook_secret || "").trim();
  // 已保存的密钥会显示为 ********，后端 merge_sensitive 会还原，不能当“未填写”
  if (!secret) {
    const msg = "请先填写 Webhook Secret 并保存配置";
    setWebhookActionStatus(msg, "error");
    setMessage(msg);
    return;
  }
  if (!String(data.cf_api_email || "").trim()) {
    const msg = "请先填写 Cloudflare 全局鉴权：CF 登录账号";
    setWebhookActionStatus(msg, "error");
    setMessage(msg);
    return;
  }
  if (!String(data.cf_api_key || "").trim()) {
    const msg = "请先填写 Cloudflare 全局鉴权：Global API Key";
    setWebhookActionStatus(msg, "error");
    setMessage(msg);
    return;
  }
  const force = Boolean(data.cf_email_worker_force);
  const tip = force
    ? `强制覆盖部署 Worker「${workerName}」并写入 webhook 变量？\n\n点「取消」可中止。`
    : `部署 Worker「${workerName}」？\n（已存在则跳过覆盖；要更新 URL/Secret 请勾选「强制覆盖」）\n\n点「取消」可中止。`;
  // 部分环境 confirm 被拦时直接继续，避免“点了没反应”
  let confirmed = true;
  try {
    confirmed = window.confirm(tip);
  } catch (e) {
    confirmed = true;
  }
  if (!confirmed) {
    setWebhookActionStatus("已取消部署", "");
    setMessage("已取消部署 Worker");
    return;
  }
  setWebhookActionStatus(`正在部署 Worker ${workerName}…`, "");
  setMessage(`正在部署 Worker ${workerName}…`);
  if (cfDeployWorkerBtn) {
    cfDeployWorkerBtn.disabled = true;
    cfDeployWorkerBtn.textContent = "部署中…";
  }
  try {
    // 掩码密钥不要用当前表单覆盖服务端真实值：保存前若 secret/key 是 ******，先恢复占位逻辑由 merge_sensitive 处理
    await saveConfig().catch((e) => {
      // 保存失败不阻断部署（服务端仍可用已存配置）
      console.warn("saveConfig before deploy failed", e);
    });
    const webhookUrl =
      (webhookSuggestedUrl && webhookSuggestedUrl.value) ||
      (webhookPanelCache && webhookPanelCache.webhook && webhookPanelCache.webhook.suggested_base) ||
      window.location.origin;
    const result = await requestJson("/api/cloudflare/global/deploy-email-worker", {
      method: "POST",
      body: JSON.stringify({
        ...formPayload(),
        worker_name: workerName,
        webhook_url: webhookUrl,
        // 掩码时不要传空 secret 覆盖；显式省略让服务端用已存配置
        webhook_secret: secret === "********" ? undefined : secret,
        force,
      }),
    });
    const msg = result.message || (result.skipped ? "Worker 已存在，已跳过" : "Worker 部署成功");
    setWebhookActionStatus(msg, result.ok === false ? "error" : "ok");
    setMessage(msg);
    setCfGlobalStatus(msg);
    await loadWebhookPanel({ silent: true }).catch(() => {});
  } catch (error) {
    const msg = `部署 Worker 失败：${error.message}`;
    setWebhookActionStatus(msg, "error");
    setMessage(msg);
  } finally {
    if (cfDeployWorkerBtn) {
      cfDeployWorkerBtn.disabled = false;
      cfDeployWorkerBtn.textContent = "一键部署 Worker";
    }
  }
}

async function setupCfCatchAll() {
  const data = formPayload();
  const domains = mailDomainsFromForm();
  const workerName = String(data.cf_email_worker_name || "openai-cpa-email").trim() || "openai-cpa-email";
  if (!domains) {
    const msg = "请先填写 mail_domains（邮件主域池）";
    setWebhookActionStatus(msg, "error");
    setMessage(msg);
    return;
  }
  if (!String(data.cf_api_email || "").trim()) {
    const msg = "请先填写 Cloudflare 全局鉴权：CF 登录账号";
    setWebhookActionStatus(msg, "error");
    setMessage(msg);
    return;
  }
  if (!String(data.cf_api_key || "").trim()) {
    const msg = "请先填写 Cloudflare 全局鉴权：Global API Key";
    setWebhookActionStatus(msg, "error");
    setMessage(msg);
    return;
  }
  let confirmed = true;
  try {
    confirmed = window.confirm(
      `把以下域名的 Email Routing catch-all 指到 Worker「${workerName}」？\n\n${domains}\n\n要求：域名 NS 已生效（active），且 Worker 已部署。\n点「取消」可中止。`
    );
  } catch (e) {
    confirmed = true;
  }
  if (!confirmed) {
    setWebhookActionStatus("已取消绑定 catch-all", "");
    setMessage("已取消绑定 catch-all");
    return;
  }
  setWebhookActionStatus(`正在绑定 catch-all → ${workerName}…`, "");
  setMessage(`正在绑定 catch-all → ${workerName}…`);
  if (cfSetupCatchAllBtn) {
    cfSetupCatchAllBtn.disabled = true;
    cfSetupCatchAllBtn.textContent = "绑定中…";
  }
  try {
    await saveConfig().catch((e) => console.warn("saveConfig before catch-all failed", e));
    const result = await requestJson("/api/cloudflare/global/setup-catch-all", {
      method: "POST",
      body: JSON.stringify({
        ...formPayload(),
        domains,
        worker_name: workerName,
      }),
    });
    const items = Array.isArray(result.items) ? result.items : [];
    const lines = items.map((it) => `${it.domain}: ${it.msg || (it.ok ? "ok" : "fail")}`);
    const summary = `Catch-all：成功 ${result.total || 0} / 失败 ${result.failed || 0}（Worker=${result.worker_name || workerName}）`;
    const detail = summary + (lines.length ? `。${lines.slice(0, 6).join("；")}` : "");
    setWebhookActionStatus(detail, result.ok ? "ok" : "error");
    setMessage(summary);
    setCfGlobalStatus(detail);
  } catch (error) {
    const msg = `绑定 catch-all 失败：${error.message}`;
    setWebhookActionStatus(msg, "error");
    setMessage(msg);
  } finally {
    if (cfSetupCatchAllBtn) {
      cfSetupCatchAllBtn.disabled = false;
      cfSetupCatchAllBtn.textContent = "绑定 Catch-all → Worker";
    }
  }
}

// 事件绑定放到 DOMContent 已解析后；用事件委托兜底，避免 querySelector 失败时“点了没反应”
function bindCfWorkerActions() {
  const deployBtn = document.querySelector("#cfDeployWorkerBtn");
  const catchBtn = document.querySelector("#cfSetupCatchAllBtn");
  if (deployBtn && !deployBtn.dataset.bound) {
    deployBtn.dataset.bound = "1";
    deployBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      deployCfEmailWorker().catch((error) => {
        setWebhookActionStatus(error.message, "error");
        setMessage(error.message);
      });
    });
  }
  if (catchBtn && !catchBtn.dataset.bound) {
    catchBtn.dataset.bound = "1";
    catchBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      setupCfCatchAll().catch((error) => {
        setWebhookActionStatus(error.message, "error");
        setMessage(error.message);
      });
    });
  }
}
bindCfWorkerActions();
// 若配置区后渲染，再绑一次
document.addEventListener("DOMContentLoaded", bindCfWorkerActions);

function renderWebhookPanel(data) {
  webhookPanelCache = data || null;
  if (!data) return;
  if (webhookSuggestedUrl) {
    webhookSuggestedUrl.value = (data.webhook && data.webhook.suggested_base) || "";
  }
  if (webhookFullUrl) {
    webhookFullUrl.value = (data.webhook && data.webhook.suggested_full_url) || "";
  }
  if (webhookChecks) {
    const checks = Array.isArray(data.checks) ? data.checks : [];
    const parts = checks.map((c) => `${c.ok ? "✓" : "✗"} ${c.label}: ${c.detail || ""}`);
    const stats = data.stats || {};
    parts.push(
      `收件池: ${stats.mails || 0} 封 / ${stats.addresses || 0} 地址` +
        (data.ready ? " · 配置项齐全" : " · 配置未就绪")
    );
    webhookChecks.textContent = parts.join(" ｜ ");
  }
  if (webhookPanelDetail) {
    const stats = data.stats || {};
    const recent = Array.isArray(stats.recent) ? stats.recent : [];
    const lines = [];
    lines.push(`provider=${data.provider || "—"}  webhook=${data.enabled ? "on" : "off"}  secret=${data.secret_configured ? "已配置" : "未配置"}`);
    lines.push(`mail_domains=${data.mail_domains || "—"}`);
    lines.push(`Worker 建议:`);
    lines.push(`  EMAIL_WEBHOOK_URL=${(data.worker_env && data.worker_env.EMAIL_WEBHOOK_URL) || ""}`);
    lines.push(`  EMAIL_WEBHOOK_SECRET=${(data.worker_env && data.worker_env.EMAIL_WEBHOOK_SECRET) || ""}`);
    lines.push(`Header: ${(data.webhook && data.webhook.header) || "X-Webhook-Secret"}`);
    if (recent.length) {
      lines.push("最近收件:");
      recent.slice(0, 8).forEach((m) => {
        const ts = m.last_ts ? new Date(Number(m.last_ts) * 1000).toLocaleString() : "—";
        lines.push(`  · ${m.to}  x${m.count || 1}  ${ts}`);
        if (m.raw_preview) lines.push(`    ${String(m.raw_preview).replace(/\s+/g, " ").slice(0, 100)}`);
      });
    } else {
      lines.push("最近收件: （空）可用「本机模拟推送测试」写入一封");
    }
    webhookPanelDetail.textContent = lines.join("\n");
  }
}

async function loadWebhookPanel({ silent = false } = {}) {
  try {
    const data = await requestJson("/api/webhook/email/panel");
    renderWebhookPanel(data);
    if (!silent) setMessage(data.ready ? "webhook 联调状态已刷新（配置项齐全）" : "webhook 联调状态已刷新（仍有未完成项）");
    return data;
  } catch (error) {
    if (webhookChecks) webhookChecks.textContent = `加载失败：${error.message}`;
    if (!silent) setMessage(`加载 webhook 面板失败：${error.message}`);
    throw error;
  }
}

async function selfTestWebhook() {
  setMessage("正在本机模拟 Worker 推送…");
  try {
    await saveConfig().catch(() => {});
    const result = await requestJson("/api/webhook/email/self-test", {
      method: "POST",
      body: JSON.stringify({}),
    });
    await loadWebhookPanel({ silent: true });
    if (result.extract_ok) {
      setMessage(
        `模拟推送成功：${result.to_addr} 提取到 ${result.extracted_code}（与预期 ${result.expected_code} 一致）`
      );
    } else {
      setMessage(
        `已写入收件池，但验码提取异常：got=${result.extracted_code || "空"} expected=${result.expected_code}`
      );
    }
  } catch (error) {
    setMessage(`模拟推送失败：${error.message}`);
  }
}

async function clearWebhookPool() {
  if (!window.confirm("确认清空本机 webhook 收件池？")) return;
  try {
    await requestJson("/api/webhook/email/clear", { method: "POST", body: "{}" });
    await loadWebhookPanel({ silent: true });
    setMessage("webhook 收件池已清空");
  } catch (error) {
    setMessage(`清空失败：${error.message}`);
  }
}

async function copyText(text, okMsg) {
  const value = String(text || "");
  if (!value) {
    setMessage("没有可复制的内容");
    return;
  }
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(value);
    } else {
      const ta = document.createElement("textarea");
      ta.value = value;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    setMessage(okMsg || "已复制");
  } catch (error) {
    setMessage(`复制失败：${error.message}`);
  }
}

function buildWebhookCurlExample() {
  const data = webhookPanelCache;
  const url =
    (data && data.webhook && data.webhook.suggested_full_url) ||
    `${window.location.origin}/api/webhook/email`;
  const body =
    (data && data.webhook && data.webhook.body_example) || {
      message_id: "test-001",
      to_addr: "probe@your-domain.com",
      raw_content: "SpaceXAI confirmation code: ABC-DEF",
    };
  return [
    `curl -X POST '${url}' \\`,
    `  -H 'Content-Type: application/json' \\`,
    `  -H 'X-Webhook-Secret: <你的 EMAIL_WEBHOOK_SECRET>' \\`,
    `  -d '${JSON.stringify(body)}'`,
  ].join("\n");
}

if (webhookRefreshBtn) {
  webhookRefreshBtn.addEventListener("click", () => {
    loadWebhookPanel().catch(() => {});
  });
}
if (webhookSelfTestBtn) {
  webhookSelfTestBtn.addEventListener("click", () => {
    selfTestWebhook().catch((error) => setMessage(error.message));
  });
}
if (webhookClearBtn) {
  webhookClearBtn.addEventListener("click", () => {
    clearWebhookPool().catch((error) => setMessage(error.message));
  });
}
if (webhookCopyUrlBtn) {
  webhookCopyUrlBtn.addEventListener("click", () => {
    const url =
      (webhookFullUrl && webhookFullUrl.value) ||
      (webhookPanelCache && webhookPanelCache.webhook && webhookPanelCache.webhook.suggested_full_url) ||
      "";
    copyText(url, "已复制 Webhook 完整 URL");
  });
}
if (webhookCopyCurlBtn) {
  webhookCopyCurlBtn.addEventListener("click", () => {
    copyText(buildWebhookCurlExample(), "已复制 curl 示例（请把 Secret 换成真实值）");
  });
}

startBtn.addEventListener("click", () => {
  startJob().catch((error) => setMessage(error.message));
});

stopBtn.addEventListener("click", () => {
  stopJob().catch((error) => setMessage(error.message));
});

refreshAccountsBtn.addEventListener("click", () => {
  loadAccounts().catch((error) => setMessage(error.message));
});

checkHealthBtn.addEventListener("click", () => {
  checkSelectedAccountHealth().catch((error) => setMessage(error.message));
});

if (exportAccountsBtn) {
  exportAccountsBtn.addEventListener("click", () => {
    exportSelectedAccounts().catch((error) => setMessage(error.message));
  });
}

selectPageAccounts.addEventListener("change", () => {
  for (const account of currentPageAccounts()) {
    if (selectPageAccounts.checked) selectedAccountIdsSet.add(account.id);
    else selectedAccountIdsSet.delete(account.id);
  }
  renderAccounts();
});

accountPageSize.addEventListener("change", () => {
  accountTablePrefs.pageSize = Number(accountPageSize.value) || DEFAULT_ACCOUNT_TABLE_PREFS.pageSize;
  accountPage = 1;
  saveAccountTablePrefs();
  renderAccounts();
});

if (accountSearchInput) {
  let searchTimer = null;
  accountSearchInput.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      accountSearchQuery = accountSearchInput.value || "";
      accountPage = 1;
      renderAccounts();
    }, 180);
  });
}
if (accountPushFilter) {
  accountPushFilter.addEventListener("change", () => {
    accountPushFilterValue = accountPushFilter.value || "all";
    accountPage = 1;
    renderAccounts();
  });
}

accountColumnOptions.addEventListener("change", (event) => {
  const checkbox = event.target.closest("[data-column-toggle]");
  if (!checkbox) return;
  const visible = new Set(accountTablePrefs.visibleColumns);
  if (checkbox.checked) visible.add(checkbox.dataset.columnToggle);
  else visible.delete(checkbox.dataset.columnToggle);
  visible.add("select");
  accountTablePrefs.visibleColumns = ACCOUNT_COLUMNS
    .map((column) => column.key)
    .filter((key) => visible.has(key));
  accountTablePrefs.version = ACCOUNT_TABLE_PREFS_VERSION;
  saveAccountTablePrefs();
  renderAccounts();
});

importSub2apiBtn.addEventListener("click", () => {
  importSelectedToSub2api().catch((error) => setMessage(error.message));
});

if (probeSub2apiBtn) {
  probeSub2apiBtn.addEventListener("click", () => {
    probeSelectedOnSub2api().catch((error) => setMessage(error.message));
  });
}

if (deleteSub2apiRemoteBtn) {
  deleteSub2apiRemoteBtn.addEventListener("click", () => {
    deleteSelectedSub2apiRemote().catch((error) => setMessage(error.message));
  });
}

importGrok2apiBtn.addEventListener("click", () => {
  importSelectedToGrok2api().catch((error) => setMessage(error.message));
});

importCpaBtn.addEventListener("click", () => {
  importSelectedToCpa().catch((error) => setMessage(error.message));
});

deleteAccountsBtn.addEventListener("click", () => {
  deleteSelectedAccounts().catch((error) => setMessage(error.message));
});

tabButtons.forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.tabTarget));
});

configSubnavButtons.forEach((button) => {
  button.addEventListener("click", () => activateConfigGroup(button.dataset.configGroup));
});
restoreConfigGroup();

if (warRefreshBtn) {
  warRefreshBtn.addEventListener("click", () => {
    loadWarRoom().catch((error) => setMessage(error.message));
  });
}
if (warStopBtn) {
  warStopBtn.addEventListener("click", () => {
    stopJob().catch((error) => setMessage(error.message));
  });
}
if (warResetDomainsBtn) {
  warResetDomainsBtn.addEventListener("click", () => {
    resetWarDomains().catch((error) => setMessage(error.message));
  });
}
if (warAutopilotToggle) {
  warAutopilotToggle.addEventListener("change", () => {
    setAutopilotEnabled(warAutopilotToggle.checked).catch((error) => setMessage(error.message));
  });
}
if (warAutopilotOnceBtn) {
  warAutopilotOnceBtn.addEventListener("click", () => {
    runAutopilotOnce().catch((error) => setMessage(error.message));
  });
}

const notifyTestBtn = document.querySelector("#notifyTestBtn");
const notifyStatusText = document.querySelector("#notifyStatusText");
if (notifyTestBtn) {
  notifyTestBtn.addEventListener("click", () => {
    (async () => {
      notifyTestBtn.disabled = true;
      try {
        await saveConfig().catch(() => {});
        const result = await requestJson("/api/notify/test", { method: "POST" });
        if (notifyStatusText) {
          notifyStatusText.textContent = result.ok
            ? `已发送（${result.latency_ms || "?"}ms）`
            : "发送失败";
        }
        setMessage("Telegram 测试消息已发送");
      } catch (error) {
        if (notifyStatusText) notifyStatusText.textContent = error.message;
        setMessage(`通知测试失败：${error.message}`);
      } finally {
        notifyTestBtn.disabled = false;
      }
    })();
  });
}

const logoutBtn = document.querySelector("#logoutBtn");
if (logoutBtn) {
  logoutBtn.addEventListener("click", () => {
    logout().catch(() => location.replace("/login"));
  });
}

loadConfig().catch((error) => setMessage(error.message));
loadPresets().catch(() => {});
loadAccounts().catch((error) => setMessage(error.message));
startWarRoomPolling();
loadWarRoom({ silent: true }).catch(() => {});
restoreCurrentJob().catch((error) => setMessage(error.message));
