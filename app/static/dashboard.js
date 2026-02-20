function esc(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function byId(id) {
  return document.getElementById(id);
}

function setMini(id, text) {
  const element = byId(id);
  if (element) element.textContent = text;
}

function setNavState(stateId, detailId, label, tone = "neutral", detail = "") {
  const state = byId(stateId);
  if (state) {
    state.textContent = label;
    state.className = `nav-state ${tone}`;
  }

  const detailEl = byId(detailId);
  if (detailEl) {
    detailEl.textContent = detail;
  }
}

function short(value, max = 34) {
  const str = String(value || "");
  return str.length > max ? `${str.slice(0, max - 3)}...` : str;
}

async function fetchJson(url) {
  const response = await fetch(url, { credentials: "same-origin" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function setError(targetId, message) {
  const element = byId(targetId);
  if (!element) return;
  element.innerHTML = `<div class="error-box">${esc(message)}</div>`;
}

function syncTone(status) {
  if (["synced", "repos_synced"].includes(status)) return "ok";
  if (["dirty", "ahead", "behind", "repos_unsynced", "not_git_repo"].includes(status)) return "warn";
  if (["diverged", "missing"].includes(status)) return "bad";
  return "neutral";
}

const SCAN_INTERVAL_MS = 5000;
let notifyTargetsState = null;
let memorySaveState = null;
let memorySaveFeedback = "";

function formatShortTime(isoValue) {
  if (!isoValue) return "-";
  const date = new Date(isoValue);
  if (Number.isNaN(date.getTime())) return String(isoValue);
  return date.toISOString().replace("T", " ").replace(".000Z", "Z");
}

function renderNotifyMeta(notify) {
  const status = String(notify?.status || "unknown");
  const target = String(notify?.target_label || notify?.target || "-");
  const tone = status === "sent"
    ? "ok"
    : ["no_target", "signal_channel_disabled", "missing_signal_account"].includes(status)
      ? "warn"
      : "bad";
  return `<span class="sync-badge ${tone}">notify ${esc(status)}</span><span class="sync-meta">target ${esc(target)}</span>`;
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function notifyOptions() {
  return Array.isArray(notifyTargetsState?.options) ? notifyTargetsState.options : [];
}

function defaultTargetValue() {
  return String(notifyTargetsState?.default_target || "");
}

function defaultTargetLabel() {
  const options = notifyOptions();
  const match = options.find((option) => option.value === defaultTargetValue()) || options[0];
  return match?.label || "Hauptkontakt";
}

function setRepoDefaultTargetNote() {
  const note = byId("repoHookerDefaultTarget");
  if (!note) return;
  note.textContent = `Default: ${defaultTargetLabel()}`;
}

function setButtonFlash(button, text) {
  if (!button) return;
  const original = button.dataset.originalText || button.textContent || "Test";
  button.dataset.originalText = original;
  button.textContent = text;
  window.setTimeout(() => {
    button.textContent = button.dataset.originalText || "Test";
  }, 1700);
}

function autosaveMode() {
  return String(memorySaveState?.mode || "never");
}

function autosaveOptionsHtml(selectedMode) {
  const options = Array.isArray(memorySaveState?.options) ? memorySaveState.options : [
    { value: "never", label: "Nie" },
    { value: "daily_23", label: "1x täglich (23:00)" },
  ];
  return options
    .map((option) => {
      const value = String(option?.value || "never");
      const label = String(option?.label || value);
      const selected = value === selectedMode ? " selected" : "";
      return `<option value="${esc(value)}"${selected}>${esc(label)}</option>`;
    })
    .join("");
}

function setMemorySaveFeedback(message) {
  memorySaveFeedback = String(message || "");
  if (!memorySaveFeedback) return;
  window.setTimeout(() => {
    memorySaveFeedback = "";
  }, 5000);
}

function applyMemorySaveConfig(data) {
  if (!data || typeof data !== "object") return;
  memorySaveState = data;
}

function bindMemorySaveControls() {
  const saveBtn = byId("memorySaveNowBtn");
  const modeSelect = byId("memoryAutosaveSelect");

  if (modeSelect && modeSelect.dataset.bound !== "1") {
    modeSelect.dataset.bound = "1";
    modeSelect.addEventListener("change", async () => {
      try {
        const updated = await postJson("/api/memory-save-config", { mode: modeSelect.value });
        applyMemorySaveConfig(updated);
        setMemorySaveFeedback(updated.mode === "daily_23" ? "Auto 23:00 aktiv" : "Auto aus");
        renderSyncStatus(await fetchJson("/api/workspaces-sync"));
      } catch {
        setMemorySaveFeedback("Auto-Update fehlgeschlagen");
      }
    });
  }

  if (saveBtn && saveBtn.dataset.bound !== "1") {
    saveBtn.dataset.bound = "1";
    saveBtn.addEventListener("click", async () => {
      saveBtn.disabled = true;
      try {
        const result = await postJson("/api/memory-save", { reason: "manual" });
        if (result.config) applyMemorySaveConfig(result.config);
        setMemorySaveFeedback(result.ok ? "Saved + pushed" : `Save failed: ${result.status || "error"}`);

        const [syncData] = await Promise.all([
          fetchJson("/api/workspaces-sync"),
          refreshHookerPanels(),
        ]);
        renderSyncStatus(syncData);
      } catch {
        setMemorySaveFeedback("Save fehlgeschlagen");
      } finally {
        saveBtn.disabled = false;
      }
    });
  }
}

async function runTestNotification(button, payload) {
  if (!button) return;
  button.disabled = true;
  try {
    const result = await postJson("/api/notify-targets/test", payload);
    setButtonFlash(button, result.sent ? "Sent" : "Failed");
  } catch {
    setButtonFlash(button, "Error");
  } finally {
    button.disabled = false;
  }
}

async function refreshHookerPanels() {
  const [repoHookerData, memoryHookerData] = await Promise.all([
    fetchJson("/api/repo-hooker"),
    fetchJson("/api/memory-hooker"),
  ]);
  renderRepoHooker(repoHookerData);
  renderMemoryHooker(memoryHookerData);
}

function renderMemoryTargetSelect(selectedValue) {
  const select = byId("memoryHookerTargetSelect");
  if (!select) return;

  const options = notifyOptions();
  if (!options.length) {
    select.innerHTML = "<option value=''>No target</option>";
    select.disabled = true;
    return;
  }

  select.disabled = false;
  select.innerHTML = options
    .map((option) => {
      const value = String(option?.value || "");
      const label = String(option?.label || option?.value || "target");
      return `<option value="${esc(value)}">${esc(label)}</option>`;
    })
    .join("");

  if (selectedValue && options.some((option) => option.value === selectedValue)) {
    select.value = selectedValue;
  } else if (defaultTargetValue()) {
    select.value = defaultTargetValue();
  }

  if (select.dataset.bound !== "1") {
    select.dataset.bound = "1";
    select.addEventListener("change", async () => {
      try {
        notifyTargetsState = await postJson("/api/notify-targets", { memory_target: select.value });
        applyNotifyTargets(notifyTargetsState);
        await refreshHookerPanels();
      } catch {
        // keep old value on transient failures
      }
    });
  }
}

function bindMemoryTestButton() {
  const button = byId("memoryHookerTestBtn");
  const select = byId("memoryHookerTargetSelect");
  if (!button || !select || button.dataset.bound === "1") return;

  button.dataset.bound = "1";
  button.addEventListener("click", async () => {
    const target = String(select.value || defaultTargetValue() || "");
    await runTestNotification(button, {
      target,
      scope: "memory",
      repo: "memory",
    });
  });
}

function bindRepoDefaultTestButton() {
  const button = byId("repoHookerDefaultTestBtn");
  if (!button || button.dataset.bound === "1") return;

  button.dataset.bound = "1";
  button.addEventListener("click", async () => {
    const target = defaultTargetValue();
    await runTestNotification(button, {
      target,
      scope: "repo-default",
      repo: "repo-default",
    });
  });
}

function repoTargetOptionsHtml(targetValue, isDefault) {
  const options = notifyOptions();
  const rows = [];
  rows.push(`<option value="__default__"${isDefault ? " selected" : ""}>Default (${esc(defaultTargetLabel())})</option>`);
  for (const option of options) {
    const value = String(option?.value || "");
    const label = String(option?.label || option?.value || "target");
    const selected = !isDefault && value === targetValue;
    rows.push(`<option value="${esc(value)}"${selected ? " selected" : ""}>${esc(label)}</option>`);
  }
  return rows.join("");
}

function bindRepoHookerControls(container) {
  if (!container) return;

  const selects = Array.from(container.querySelectorAll(".repo-target-select"));
  for (const select of selects) {
    if (select.dataset.bound === "1") continue;
    select.dataset.bound = "1";
    select.addEventListener("change", async () => {
      const repoPath = String(select.dataset.repoPath || "");
      if (!repoPath) return;
      try {
        notifyTargetsState = await postJson("/api/notify-targets/repo", {
          repo_path: repoPath,
          target: select.value,
        });
        applyNotifyTargets(notifyTargetsState);
        await refreshHookerPanels();
      } catch {
        // keep old value on transient failures
      }
    });
  }

  const buttons = Array.from(container.querySelectorAll(".repo-test-btn"));
  for (const button of buttons) {
    if (button.dataset.bound === "1") continue;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      const row = button.closest("tr");
      const select = row ? row.querySelector(".repo-target-select") : null;
      let target = select ? String(select.value || "") : "";
      if (target === "__default__") {
        target = defaultTargetValue();
      }

      await runTestNotification(button, {
        target,
        scope: "repo",
        repo: String(button.dataset.repoName || "repo"),
        branch: String(button.dataset.repoBranch || ""),
      });
    });
  }
}

function applyNotifyTargets(data) {
  if (!data || typeof data !== "object") return;
  notifyTargetsState = data;
  setRepoDefaultTargetNote();
  renderMemoryTargetSelect(data.memory_target);
  bindRepoDefaultTestButton();
  bindMemoryTestButton();
}

function renderSyncStatus(data) {
  const target = byId("syncStatus");
  if (!target) return;

  const dirty = Number(data.dirty_count || 0);
  const ahead = Number(data.ahead || 0);
  const behind = Number(data.behind || 0);

  let label = "Unknown";
  let cls = "sync-badge";
  if (data.status === "synced") {
    label = "Synced";
    cls += " ok";
  } else if (data.status === "repos_synced") {
    label = "Repos Synced";
    cls += " ok";
  } else if (data.status === "repos_unsynced") {
    label = "Repos Unsynced";
    cls += " warn";
  } else if (data.status === "dirty") {
    label = "Dirty";
    cls += " warn";
  } else if (data.status === "ahead") {
    label = "Ahead";
    cls += " warn";
  } else if (data.status === "behind") {
    label = "Behind";
    cls += " warn";
  } else if (data.status === "diverged") {
    label = "Diverged";
    cls += " bad";
  } else if (data.status === "not_git_repo") {
    label = "Not Git Repo";
    cls += " warn";
  } else if (data.status === "missing") {
    label = "Missing";
    cls += " bad";
  } else {
    label = "No Upstream";
  }

  const syncDetail = ["repos_synced", "repos_unsynced"].includes(data.status)
    ? `${dirty} unsynced repos`
    : `ahead ${ahead} / behind ${behind} / dirty ${dirty}`;
  const tone = syncTone(data.status);

  const dirtyFiles = (data.dirty_files || [])
    .slice(0, 3)
    .map((file) => `<code title="${esc(file)}">${esc(short(file, 42))}</code>`)
    .join(" ");

  const mode = autosaveMode();
  const modeHint = mode === "daily_23" ? "Auto 23:00" : "Auto aus";
  const feedback = memorySaveFeedback || modeHint;

  target.innerHTML = `
    <span class="${cls}">${esc(label)}</span>
    ${data.path ? `<span class="sync-meta">${esc(short(data.path, 56))}</span>` : ""}
    <span class="sync-meta">${esc(data.branch || "-")}${data.upstream ? ` -> ${esc(data.upstream)}` : ""}</span>
    <span class="sync-meta">${esc(syncDetail)}</span>
    ${dirtyFiles ? `<span class="sync-files">${dirtyFiles}</span>` : ""}
    <span class="memory-save-controls">
      <select id="memoryAutosaveSelect" class="memory-autosave-select" aria-label="Memory autosave mode">
        ${autosaveOptionsHtml(mode)}
      </select>
      <button id="memorySaveNowBtn" type="button" class="btn-secondary btn-mini">Save</button>
      <span id="memorySaveFeedback" class="sync-meta">${esc(feedback)}</span>
    </span>
  `;

  const shortSummary = `${label} | ${data.branch || "-"} | dirty ${dirty}`;
  setMini("memorySummaryMini", shortSummary);
  setNavState("navMemoryState", "navMemoryDetail", label, tone, short(syncDetail, 24));

  const badge = byId("memoryStatusBadge");
  if (badge) {
    badge.textContent = label;
    badge.className = `status-pill ${tone}`;
  }

  bindMemorySaveControls();
}

function renderSystem(data) {
  const target = byId("systemStatusResources");
  const pill = byId("systemHealthPill");
  if (!target || !pill) return;

  const cpu = Number(data.cpu_percent || 0);
  const mem = Number(data.memory?.percent || 0);
  const disk = Number(data.disk_root?.percent || 0);

  setMini("systemStatusSummaryMini", `CPU ${cpu.toFixed(0)}% MEM ${mem.toFixed(0)}% DISK ${disk.toFixed(0)}%`);
  pill.textContent = data.clawq?.running ? "healthy" : "degraded";
  pill.className = data.clawq?.running ? "pill ok" : "pill warn";
  setNavState(
    "navStatusState",
    "navStatusDetail",
    data.clawq?.running ? "Running" : "Stopped",
    data.clawq?.running ? "ok" : "bad",
    `CPU ${cpu.toFixed(0)}%`
  );

  const meter = (label, value, tone) => `
    <div class="metric metric-meter">
      <span class="k">${esc(label)}</span>
      <strong>${esc(value.toFixed(1))}%</strong>
      <div class="meter"><span class="meter-fill ${tone}" style="width:${Math.max(0, Math.min(100, value))}%"></span></div>
    </div>`;

  target.innerHTML = `
    ${meter("CPU", cpu, "tone-a")}
    ${meter("Memory", mem, "tone-b")}
    ${meter("Disk", disk, "tone-c")}
    <div class="metric"><span class="k">Uptime</span><strong>${esc(data.app_uptime_seconds)}s</strong></div>
    <div class="metric"><span class="k">ClawQ</span><strong>${esc(data.clawq.message)}</strong></div>
    <div class="metric"><span class="k">Timestamp</span><strong>${esc(data.timestamp)}</strong></div>
  `;
}

function renderUsage(data) {
  const target = byId("systemStatusUsage");
  if (!target) return;
  const stats = data.stats || {};
  const totalSessions = Number(stats.total_sessions || 0);
  const totalMessages = Number(stats.total_messages || 0);
  const profiles = Object.keys(data.profiles || {}).length;
  const creds = Object.keys(data.credentials || {}).length;

  const spark = (stats.daily_activity || [])
    .slice(-5)
    .map((row) => `<span class="spark" style="height:${8 + Math.min(30, Number(row.messageCount || 0) / 80)}px"></span>`)
    .join("");

  target.innerHTML = `
    <div class="metric-grid">
      <div class="metric"><span class="k">Sessions</span><strong>${totalSessions}</strong></div>
      <div class="metric"><span class="k">Messages</span><strong>${totalMessages}</strong></div>
      <div class="metric"><span class="k">Profiles</span><strong>${profiles}</strong></div>
      <div class="metric"><span class="k">Credentials</span><strong>${creds}</strong></div>
    </div>
    <div class="sparkline-wrap"><span class="k">Recent activity</span><div class="sparkline">${spark || ""}</div></div>
  `;
}

function renderSettings(data) {
  const target = byId("systemStatusSettings");
  if (!target) return;
  target.innerHTML = `
    <ul class="kv-list">
      <li><span>Cookie secure</span><strong>${data.cookie_secure ? "true" : "false"}</strong></li>
      <li><span>Password env</span><strong>${data.password_env_set ? "set" : "missing"}</strong></li>
      <li><span>Secret env</span><strong>${data.cookie_secret_env_set ? "set" : "derived"}</strong></li>
      <li><span>README exists</span><strong>${data.readme_exists ? "yes" : "no"}</strong></li>
    </ul>
  `;
}

function renderStt(data) {
  const target = byId("systemStatusStt");
  if (!target) return;
  const models = data.models || [];
  const items = models
    .slice(0, 6)
    .map((model) => {
      const label = model.provider || model.command || model.type || "unknown";
      const detail = model.model || model.endpoint || "";
      return `<li><span>${esc(short(label, 18))}</span><code title="${esc(detail)}">${esc(short(detail, 26))}</code></li>`;
    })
    .join("");

  target.innerHTML = `
    <div class="metric-grid">
      <div class="metric"><span class="k">Active</span><strong>${data.active ? "yes" : "no"}</strong></div>
      <div class="metric"><span class="k">Models</span><strong>${models.length}</strong></div>
    </div>
    <ul class="compact-list compact-two">${items || "<li>No models configured</li>"}</ul>
  `;
}

function getWorkspaceFromJob(job) {
  const sessionTarget = String(job.sessionTarget || "");
  if (sessionTarget.startsWith("agent:")) {
    const parts = sessionTarget.split(":");
    if (parts.length > 1 && parts[1]) return parts[1];
  }
  if (job.agentId) return String(job.agentId);
  return "global";
}

function renderCrons(data) {
  const target = byId("cronContent");
  if (!target) return;
  const jobs = data.jobs || [];
  setMini("cronSummaryMini", `${jobs.length} jobs`);

  const rows = jobs
    .slice()
    .sort((a, b) => {
      const aKind = (a.schedule?.kind || "").toLowerCase();
      const bKind = (b.schedule?.kind || "").toLowerCase();
      const aOrder = aKind === "cron" ? 0 : 1;
      const bOrder = bKind === "cron" ? 0 : 1;
      if (aOrder !== bOrder) return aOrder - bOrder;
      return getWorkspaceFromJob(a).localeCompare(getWorkspaceFromJob(b)) || String(a.name || a.id || "").localeCompare(String(b.name || b.id || ""));
    })
    .map((job, index) => {
      const workspace = getWorkspaceFromJob(job);
      const enabled = job.enabled !== false;
      const name = job.name || job.id || "unnamed";
      const schedule = job.schedule?.expr || job.schedule?.kind || "n/a";
      const kind = (job.schedule?.kind || "").toLowerCase() === "cron" ? "repeat" : "once";
      const detailId = `cron-detail-${index}`;
      const detailText = String(job.payload?.message || job.payload?.text || "").trim();
      const detail = detailText || JSON.stringify(job.payload || {}, null, 2);
      return `
        <tr class="cron-row" data-detail-id="${esc(detailId)}" tabindex="0" role="button" aria-expanded="false">
          <td title="${esc(workspace)}">${esc(short(workspace, 16))}</td>
          <td title="${esc(name)}">${esc(short(name, 44))}</td>
          <td>${enabled ? "enabled" : "off"}</td>
          <td><span class="cron-kind ${kind === "once" ? "once" : "repeat"}">${kind}</span></td>
          <td title="${esc(schedule)}"><code>${esc(short(schedule, 18))}</code></td>
        </tr>
        <tr id="${esc(detailId)}" class="cron-detail" hidden>
          <td colspan="5"><pre>${esc(detail)}</pre></td>
        </tr>
      `;
    })
    .join("");

  target.innerHTML = rows
    ? `
      <div class="table-wrap">
        <table class="data-table fixed-cols">
          <colgroup>
            <col class="col-workspace" />
            <col class="col-name" />
            <col class="col-status" />
            <col class="col-kind" />
            <col class="col-schedule" />
          </colgroup>
          <thead>
            <tr><th>Workspace</th><th>Job</th><th>Status</th><th>Type</th><th>Schedule</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    `
    : "<div class='content-empty'>No jobs found</div>";

  const cronRows = Array.from(target.querySelectorAll(".cron-row"));
  for (const row of cronRows) {
    const detailId = row.getAttribute("data-detail-id");
    if (!detailId) continue;
    const detail = byId(detailId);
    if (!detail) continue;

    const toggle = () => {
      const expanded = row.getAttribute("aria-expanded") === "true";
      row.setAttribute("aria-expanded", expanded ? "false" : "true");
      detail.hidden = expanded;
    };

    row.addEventListener("click", toggle);
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        toggle();
      }
    });
  }
}

function renderMapping(data) {
  const target = byId("systemStatusMapping");
  if (!target) return;
  const channels = Object.keys(data.channels || {}).length;
  const signalBindings = data.signal_bindings || [];
  const sessions = data.sessions || [];
  const signalContacts = Number(data.signal?.contact_count || 0);
  const signalGroups = Number(data.signal?.group_count || 0);

  setMini("mappingSummaryMini", `${signalGroups} groups | ${signalBindings.length} bindings`);

  const bindingRows = signalBindings
    .slice(0, 8)
    .map((binding) => {
      const agent = binding.agent_id || binding.agentId || binding.agent || "-";
      const kind = binding.target_kind || binding.match?.peer?.kind || "-";
      const target = binding.target_id || binding.match?.peer?.id || "-";
      return `<li><span>${esc(short(agent, 16))}</span><strong>${esc(kind)}</strong><code title="${esc(target)}">${esc(short(target, 24))}</code></li>`;
    })
    .join("");

  const sessionRows = sessions
    .slice(0, 10)
    .map((session) => `<li><span>${esc(short(session.agent, 16))}</span><code title="${esc(session.key)}">${esc(short(session.key, 28))}</code></li>`)
    .join("");

  target.innerHTML = `
    <div class="metric-grid">
      <div class="metric"><span class="k">Channels</span><strong>${channels}</strong></div>
      <div class="metric"><span class="k">Bindings</span><strong>${signalBindings.length}</strong></div>
      <div class="metric"><span class="k">Signal Contacts</span><strong>${signalContacts}</strong></div>
      <div class="metric"><span class="k">Signal Groups</span><strong>${signalGroups}</strong></div>
      <div class="metric"><span class="k">Sessions</span><strong>${sessions.length}</strong></div>
      <div class="metric"><span class="k">Default Workspace</span><strong>${esc(data.default_workspace || "-")}</strong></div>
    </div>
    <div class="two-col">
      <div><h3>Bindings</h3><ul class="compact-list">${bindingRows || "<li>No bindings</li>"}</ul></div>
      <div><h3>Mapped Sessions</h3><ul class="compact-list compact-two">${sessionRows || "<li>No sessions</li>"}</ul></div>
    </div>
  `;
}

function renderRepos(data) {
  const target = byId("reposContent");
  if (!target) return;

  const repos = data.repos || [];
  const workspaces = data.workspaces || [];
  const summary = data.summary || { total: repos.length, synced: 0, unsynced: 0 };
  setMini("reposSummaryMini", `${workspaces.length} workspaces | ${summary.total} repos | ${summary.unsynced} unsynced`);
  updateReposSidebar(data);

  const statusBadge = (status) => `<span class="repo-badge ${esc((status || "unknown").toLowerCase())}">${esc(status || "unknown")}</span>`;

  const rows = repos
    .slice()
    .sort((a, b) => String(a.workspace || "").localeCompare(String(b.workspace || "")) || String(a.name || "").localeCompare(String(b.name || "")))
    .map((repo) => {
      const track = `${repo.branch || "-"}${repo.upstream ? ` -> ${repo.upstream}` : ""}`;
      const dirty = Number(repo.dirty_count || 0);
      const staleBadge = repo.stale_uncommitted
        ? `<span class="alert-badge" title="Uncommitted changes and last push older than 24h">stale >24h</span>`
        : "";
      return `
        <tr>
          <td title="${esc(repo.workspace || "unknown")}">${esc(short(repo.workspace || "unknown", 14))}</td>
          <td title="${esc(repo.path || repo.name)}">${esc(short(repo.name || "repo", 22))}</td>
          <td>${statusBadge(repo.status)}</td>
          <td title="${esc(track)}"><code>${esc(short(track, 26))}</code></td>
          <td>${dirty}</td>
          <td>${staleBadge}</td>
        </tr>
      `;
    })
    .join("");

  const workspaceLabels = workspaces
    .slice(0, 10)
    .map((workspace) => `<code title="${esc(workspace)}">${esc(short(workspace, 24))}</code>`)
    .join("");

  target.innerHTML = rows
    ? `
      <div class="workspace-list-row">
        <span class="k">Workspaces</span>
        <div class="workspace-tags">${workspaceLabels || "<span class='content-empty'>none</span>"}</div>
      </div>
      <div class="table-wrap">
        <table class="data-table fixed-cols">
          <colgroup>
            <col class="col-workspace" />
            <col class="col-name" />
            <col class="col-status" />
            <col class="col-track" />
            <col class="col-small" />
            <col class="col-alert" />
          </colgroup>
          <thead>
            <tr><th>Workspace</th><th>Repo</th><th>Status</th><th>Branch/Upstream</th><th>Dirty</th><th>Alert</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    `
    : `<div class='content-empty'>No repositories found under ${esc(data.path || "configured root")}</div>`;
}

function updateReposSidebar(data) {
  const summary = data?.summary || {};
  const total = Number(summary.total || 0);
  const unsynced = Number(summary.unsynced || 0);
  const synced = Number(summary.synced || Math.max(0, total - unsynced));

  if (total === 0) {
    setNavState("navReposState", "navReposDetail", "No Repos", "neutral", "scan empty");
    return;
  }

  const tone = unsynced === 0 ? "ok" : "warn";
  const label = unsynced === 0 ? "Synced" : "Unsynced";
  setNavState("navReposState", "navReposDetail", label, tone, `${synced}/${total} synced`);
}

function renderRepoHooker(data) {
  const target = byId("repoHookerContent");
  if (!target) return;

  const repos = data.repos || [];
  const events = data.events || [];
  const defaultLabel = data.target_default?.label || defaultTargetLabel();
  const statusTone = events.length > 0 ? "warn" : "ok";
  const statusLabel = events.length > 0 ? "events detected" : "watching";
  const lastEventAt = events.length > 0 ? (events[0].committed_at || data.checked_at) : data.checked_at;

  setMini("repoHookerSummaryMini", `${repos.length} repos | ${events.length} recent events`);

  const eventCards = events
    .slice(0, 3)
    .map((event) => `
      <div class="hook-event-card">
        <div class="hook-event-meta">
          ${renderNotifyMeta(event.notify || {})}
          <span class="sync-meta">${esc(event.repo || "repo")}/${esc(event.branch || "-")}</span>
        </div>
        <pre>${esc(event.message || "")}</pre>
      </div>
    `)
    .join("");

  const rows = repos
    .slice()
    .sort((a, b) => String(a.workspace || "").localeCompare(String(b.workspace || "")) || String(a.name || "").localeCompare(String(b.name || "")))
    .slice(0, 18)
    .map((repo) => {
      const targetState = repo.notify_target || {};
      const targetValue = String(targetState.value || "");
      const isDefault = Boolean(targetState.is_default);
      return `
        <tr>
          <td title="${esc(repo.workspace || "-")}">${esc(short(repo.workspace || "-", 14))}</td>
          <td title="${esc(repo.name || "repo")}">${esc(short(repo.name || "repo", 22))}</td>
          <td><code>${esc(repo.head_short || "-")}</code></td>
          <td title="${esc(repo.subject || "")}">${esc(short(repo.subject || "-", 36))}</td>
          <td>
            <div class="hook-target-inline">
              <select class="repo-target-select" data-repo-path="${esc(repo.path || "")}">
                ${repoTargetOptionsHtml(targetValue, isDefault)}
              </select>
              <button type="button" class="btn-secondary btn-mini repo-test-btn" data-repo-name="${esc(repo.name || "repo")}" data-repo-branch="${esc(repo.branch || "")}">Test</button>
            </div>
          </td>
          <td>${esc(formatShortTime(repo.committed_at))}</td>
        </tr>
      `;
    })
    .join("");

  target.innerHTML = `
    <div class="sync-strip">
      <span class="sync-badge ${statusTone}">${statusLabel}</span>
      <span class="sync-meta">scans every ${SCAN_INTERVAL_MS / 1000}s</span>
      <span class="sync-meta">default ${esc(defaultLabel)}</span>
      <span class="sync-meta">overrides ${Number(data.repo_overrides_count || 0)}</span>
      <span class="sync-meta">last event ${esc(formatShortTime(lastEventAt))}</span>
    </div>
    ${eventCards ? `<div class="hook-event-list">${eventCards}</div>` : ""}
    ${rows
      ? `<div class="table-wrap">
          <table class="data-table fixed-cols">
            <colgroup>
              <col class="col-workspace" />
              <col class="col-name" />
              <col class="col-small" />
              <col class="col-track" />
              <col class="col-track" />
              <col class="col-schedule" />
            </colgroup>
            <thead>
              <tr><th>Workspace</th><th>Repo</th><th>Head</th><th>Latest Commit</th><th>Target</th><th>When</th></tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>`
      : "<div class='content-empty'>No repositories available for hook scan</div>"}
  `;

  bindRepoHookerControls(target);
}

function renderMemoryHooker(data) {
  const target = byId("memoryHookerContent");
  if (!target) return;

  const targetLabel = data.target?.label || "Kein Ziel";
  if (notifyTargetsState) {
    renderMemoryTargetSelect(data.target?.value);
  } else {
    const select = byId("memoryHookerTargetSelect");
    if (select) {
      const fallbackValue = String(data.target?.value || "");
      const fallbackLabel = String(data.target?.label || "Hauptkontakt");
      select.innerHTML = `<option value="${esc(fallbackValue)}">${esc(fallbackLabel)}</option>`;
      select.disabled = !fallbackValue;
    }
  }

  if (!data.found) {
    setMini("memoryHookerSummaryMini", "not found");
    target.innerHTML = `<div class="error-box">Memory repository not found (${esc(data.reason || "unknown")}).</div>`;
    setNavState("navMemoryState", "navMemoryDetail", "Missing", "bad", "memory repo missing");
    return;
  }

  const event = data.event;
  const tone = event ? "warn" : "ok";
  const label = event ? "event tracked" : "watching";
  setMini("memoryHookerSummaryMini", `${event ? 1 : 0} recent event | ${data.head_short || "-"}`);

  const eventCard = event
    ? `
      <div class="hook-event-list">
        <details class="hook-event-details">
          <summary>Letzte Nachricht anzeigen</summary>
          <div class="hook-event-card">
            <div class="hook-event-meta">
              ${renderNotifyMeta(event.notify || {})}
              <span class="sync-meta">${esc(event.repo || "memory")}/${esc(event.branch || "-")}</span>
            </div>
            <pre>${esc(event.message || "")}</pre>
          </div>
        </details>
      </div>
    `
    : "";

  target.innerHTML = `
    <div class="sync-strip">
      <span class="sync-badge ${tone}">${label}</span>
      <span class="sync-meta">branch ${esc(data.branch || "-")}</span>
      <span class="sync-meta">head ${esc(data.head_short || "-")}</span>
      <span class="sync-meta">target ${esc(targetLabel)}</span>
      <span class="sync-meta">last event ${esc(formatShortTime(event?.committed_at || data.checked_at))}</span>
    </div>
    ${eventCard}
    <ul class="kv-list">
      <li><span>Repo Path</span><strong>${esc(short(data.repo_path || "-", 52))}</strong></li>
      <li><span>README Path</span><strong>${esc(short(data.readme_path || "-", 52))}</strong></li>
      <li><span>Latest Commit</span><strong title="${esc(data.subject || "")}">${esc(short(data.subject || "-", 62))}</strong></li>
      <li><span>Committed At</span><strong>${esc(formatShortTime(data.committed_at))}</strong></li>
    </ul>
  `;
}

function initNavigation() {
  const buttons = Array.from(document.querySelectorAll(".nav-btn"));
  const views = Array.from(document.querySelectorAll(".view"));
  if (!buttons.length || !views.length) return;
  const storageKey = "clawq-active-view";

  function activate(viewName) {
    for (const button of buttons) {
      button.classList.toggle("active", button.dataset.view === viewName);
    }
    for (const view of views) {
      view.classList.toggle("active", view.id === `view-${viewName}`);
    }
    localStorage.setItem(storageKey, viewName);
  }

  for (const button of buttons) {
    button.addEventListener("click", () => activate(button.dataset.view));
  }

  const storedView = localStorage.getItem(storageKey);
  const defaultButton = buttons.find((button) => button.classList.contains("active")) || buttons[0];
  const initialView = buttons.find((button) => button.dataset.view === storedView)?.dataset.view || defaultButton.dataset.view;
  activate(initialView);

  window.addEventListener("keydown", (event) => {
    if (event.altKey || event.ctrlKey || event.metaKey) return;
    const tag = (event.target && event.target.tagName) ? event.target.tagName.toLowerCase() : "";
    if (tag === "input" || tag === "textarea" || tag === "select") return;

    const key = event.key;
    if (!["1", "2", "3"].includes(key)) return;
    const targetButton = buttons.find((button) => button.dataset.hotkey === key);
    if (!targetButton) return;

    activate(targetButton.dataset.view);
  });
}

async function loadAll() {
  const loaders = [
    ["/api/system-resources", renderSystem, "systemStatusResources", "Failed to load system resources"],
    ["/api/usage-stats", renderUsage, "systemStatusUsage", "Failed to load usage stats"],
    ["/api/stt-status", renderStt, "systemStatusStt", "Failed to load speech-to-text status"],
    ["/api/settings", renderSettings, "systemStatusSettings", "Failed to load settings"],
    ["/api/mapping", renderMapping, "systemStatusMapping", "Failed to load mapping"],
    ["/api/crons", renderCrons, "cronContent", "Failed to load cron jobs"],
    ["/api/repos-status", renderRepos, "reposContent", "Failed to load repositories status"],
    ["/api/workspaces-sync", renderSyncStatus, "syncStatus", "Failed to load workspaces sync"],
  ];

  await Promise.all(
    loaders.map(async ([url, renderer, targetId, errorLabel]) => {
      try {
        renderer(await fetchJson(url));
      } catch (error) {
        setError(targetId, `${errorLabel}: ${error.message}`);
      }
    })
  );

  try {
    const [notifyTargetsData, memorySaveConfigData] = await Promise.all([
      fetchJson("/api/notify-targets"),
      fetchJson("/api/memory-save-config"),
    ]);
    applyNotifyTargets(notifyTargetsData);
    applyMemorySaveConfig(memorySaveConfigData);
    renderSyncStatus(await fetchJson("/api/workspaces-sync"));
  } catch {
    // keep selectors in fallback mode on transient failures
  }

  try {
    await refreshHookerPanels();
  } catch {
    setError("repoHookerContent", "Failed to load repo hooker");
    setError("memoryHookerContent", "Failed to load memory hooker");
  }
}

window.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  loadAll();
  setInterval(async () => {
    try {
      const [systemData, syncData, reposData, notifyTargetsData, memorySaveConfigData] = await Promise.all([
        fetchJson("/api/system-resources"),
        fetchJson("/api/workspaces-sync"),
        fetchJson("/api/repos-status"),
        fetchJson("/api/notify-targets"),
        fetchJson("/api/memory-save-config"),
      ]);
      applyNotifyTargets(notifyTargetsData);
      applyMemorySaveConfig(memorySaveConfigData);
      renderSystem(systemData);
      renderSyncStatus(syncData);
      updateReposSidebar(reposData);
      await refreshHookerPanels();
    } catch {
      // keep current values on transient failures
    }
  }, SCAN_INTERVAL_MS);
});
