"use strict";

const $ = id => document.getElementById(id);
const severities = ["critical", "high", "medium", "low", "info"];
let token = "", activeId = "", report = null, source = null, severity = "", busy = false;
let recovery = null, lastEvent = 0, phase = "ready";

// Remote strings enter the DOM only as text, including evidence and references.
function node(tag, text = "", className = "") {
  const element = document.createElement(tag);
  element.textContent = text;
  element.className = className;
  return element;
}
function showError(message) {
  $("form-error").textContent = message;
  $("form-error").hidden = !message;
}
async function api(path, options = {}) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status}).`);
  return data;
}
function post(body) {
  return {method: "POST", headers: {"Content-Type": "application/json", "X-Vulnscope-Token": token}, body: JSON.stringify(body)};
}
function setBusy(value) {
  busy = value;
  $("scan-fields").disabled = value;
  $("start").disabled = value || !token;
  $("authorize-targets").disabled = value || !token;
  $("start").textContent = value ? "Assessment in progress…" : "Start assessment ↗";
  $("cancel").hidden = !value;
  $("activity-dot").classList.toggle("active", value);
}
function setStatus(text, state) {
  $("run-status").textContent = text;
  $("run-status").className = `status ${state}`;
}
function drawCounts() {
  $("severity-counts").replaceChildren();
  for (const name of severities) {
    const button = node("button", "", `severity-card ${name}`);
    button.type = "button";
    button.setAttribute("aria-pressed", String(severity === name));
    button.setAttribute("aria-label", `Filter ${name} findings`);
    button.append(node("strong", report ? String(report.counts[name]) : "—"), node("span", name[0].toUpperCase() + name.slice(1)));
    button.onclick = () => { severity = severity === name ? "" : name; drawCounts(); drawFindings(); };
    $("severity-counts").append(button);
  }
}
function badge(text, className = "") { return node("span", text, `badge ${className}`); }
function findingBadges(finding) {
  const badges = [badge(finding.severity, `severity ${finding.severity}`), badge(finding.validation, "validation"), badge(finding.check)];
  for (const cve of finding.cves) badges.push(badge(cve));
  return badges;
}
function drawFindings() {
  const all = report?.findings || [];
  const query = $("search").value.trim().toLowerCase();
  const checker = $("checker").value;
  // Report.to_dict() already supplies the engine's worst-first ordering.
  const filtered = all.filter(finding => (!severity || finding.severity === severity) &&
    (!checker || finding.check === checker) && (!query || Object.values(finding).join(" ").toLowerCase().includes(query)));
  $("findings").replaceChildren();
  $("finding-total").textContent = all.length;
  $("filter-status").textContent = `${severity || "All severities"} · ${checker || "All checkers"}${report ? ` · ${filtered.length} of ${all.length} shown` : ""}`;
  for (const finding of filtered) {
    const row = node("button", "", `finding-row ${finding.severity}`);
    row.type = "button";
    const badges = node("div", "", "badges");
    const arrow = node("span", "↗", "row-arrow");
    arrow.setAttribute("aria-hidden", "true");
    badges.append(...findingBadges(finding), arrow);
    row.append(badges, node("h3", finding.title), node("p", `${finding.target}${finding.port ? `:${finding.port}` : ""} · ${finding.ip} · View evidence`, "location"));
    row.onclick = () => openDetail(finding);
    $("findings").append(row);
  }
  $("empty").hidden = filtered.length > 0;
  let title = "Evidence makes the difference.", description = "Run an assessment to review findings, their validation status, and the next steps.";
  if (busy) { title = "Assessment is running."; description = "Follow target progress above. Findings appear when the engine finishes its report."; }
  else if (report && all.length) { title = "No matching findings."; description = "Try a different search or reset the filters."; }
  else if (report && !report.complete) { title = "No findings returned. Coverage is incomplete."; description = "Review the errors and refusals above before drawing conclusions."; }
  else if (report) { title = "No findings in this assessment."; description = "Review the service inventory and coverage notes. Completion does not mean exhaustive vulnerability coverage."; }
  else if (["failed", "cancelled"].includes(phase)) { title = "No final report available."; description = "This assessment did not complete. Review its status and start a new run when ready."; }
  $("empty").querySelector("h3").textContent = title;
  $("empty").querySelector("p").textContent = description;
}
function openDetail(finding) {
  $("detail-badges").replaceChildren(...findingBadges(finding));
  $("detail-title").textContent = finding.title;
  $("detail-location").textContent = `${finding.target}${finding.port ? `:${finding.port}` : ""} · Pinned IP: ${finding.ip || "Not available"}`;
  $("detail-description").textContent = finding.detail;
  $("detail-evidence").textContent = finding.evidence;
  $("detail-remediation").textContent = finding.remediation || "No specific remediation supplied; review the observation in context.";
  $("detail-references").replaceChildren();
  const references = [finding.reference, ...finding.cves.map(cve => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`)].filter(Boolean);
  for (const reference of new Set(references)) {
    let url;
    try { url = new URL(reference); } catch { /* Show non-URL references as text. */ }
    if (url && ["https:", "http:"].includes(url.protocol)) {
      const link = node("a", reference);
      link.href = url.href; link.target = "_blank"; link.rel = "noopener noreferrer";
      $("detail-references").append(link);
    } else $("detail-references").append(node("p", reference));
  }
  if (!references.length) $("detail-references").append(node("p", "No external reference supplied.", "small muted"));
  $("detail-caveat").textContent = finding.validation === "candidate" ? "A matching version is a CVE candidate. Applicability, vendor backports, and deployment configuration still need review; exploitability is not confirmed." : finding.validation === "confirmed" ? "Confirmed means the described protocol behavior was reproduced. Read the evidence and applicability limits before assessing impact." : "Observed means recorded service or protocol information. It does not establish exploitability.";
  $("detail-dialog").showModal();
  $("detail-dialog").scrollTop = 0;
}
$("close-detail").onclick = () => $("detail-dialog").close();
$("detail-dialog").addEventListener("click", event => { if (event.target === $("detail-dialog") && event.clientX < $("detail-dialog").getBoundingClientRect().left) $("detail-dialog").close(); });

function renderReport(data) {
  report = data;
  setStatus(data.complete ? "Completed" : "Incomplete · review errors", data.complete ? "completed" : "incomplete");
  $("run-targets").textContent = data.targets.join(" · ");
  $("run-context").textContent = `${new Date(data.started_at).toLocaleString()} · Authorized by ${data.authorized_by} · ${data.scope_summary}`;
  $("worst").replaceChildren(document.createTextNode("Worst finding "), node("strong", data.findings.length ? data.worst.toUpperCase() : "None returned"));
  $("coverage").hidden = false;
  $("coverage").textContent = data.complete ? "Completed without recorded operational errors. Coverage is limited to the selected service ports, checkers, and one vetted IP per target." : "Coverage is incomplete. Errors or scope refusals prevented a complete assessment; an empty finding list does not establish a clean target.";
  $("errors-wrap").hidden = !data.errors.length;
  $("errors-wrap").open = !!data.errors.length;
  $("errors-title").textContent = `${data.errors.length} error${data.errors.length === 1 ? "" : "s"} / refusal${data.errors.length === 1 ? "" : "s"}`;
  $("errors-list").replaceChildren(...data.errors.map(error => node("li", error)));
  $("notes-wrap").hidden = !data.notes.length && !Object.keys(data.services).length;
  $("notes-list").replaceChildren(...data.notes.map(note => node("li", note)));
  $("inventory").replaceChildren();
  for (const [host, inventory] of Object.entries(data.services)) {
    const item = node("div", "", "inventory-row");
    item.append(node("strong", `${host} · ${inventory.ip}`));
    item.append(node("p", inventory.services.length ? inventory.services.map(service => `${service.port}/${service.name} ${service.product} ${service.version} (${service.source})`.replace(/ +/g, " ")).join(" · ") : "No open services returned."));
    $("inventory").append(item);
  }
  const selected = $("checker").value;
  $("checker").replaceChildren(new Option("All checkers", ""), ...[...new Set(data.findings.map(finding => finding.check))].sort().map(check => new Option(check, check)));
  if ([...$("checker").options].some(option => option.value === selected)) $("checker").value = selected;
  $("json-download").disabled = $("html-download").disabled = false;
  drawCounts(); drawFindings();
}
function logEvent(data, id) {
  if (Number(id) <= lastEvent) return;
  lastEvent = Number(id);
  const nearBottom = $("event-log").scrollHeight - $("event-log").scrollTop - $("event-log").clientHeight < 35;
  const item = node("li");
  item.append(node("time", new Date(data.time).toLocaleTimeString()), node("span", data.message || data.error || `Assessment ${data.state}.`));
  $("event-log").append(item);
  while ($("event-log").children.length > 250) $("event-log").firstChild.remove();
  if (nearBottom) $("event-log").scrollTop = $("event-log").scrollHeight;
  $("activity-announcement").textContent = item.textContent;
}
function resetRun(id, targets) {
  source?.close(); clearTimeout(recovery);
  activeId = id; report = null; lastEvent = 0; phase = "running";
  $("event-log").replaceChildren();
  $("errors-wrap").hidden = $("notes-wrap").hidden = $("coverage").hidden = true;
  $("json-download").disabled = $("html-download").disabled = true;
  $("run-targets").textContent = targets?.join(" · ") || "Loading assessment…";
  $("run-context").textContent = "Checking scope; progress appears as each target starts or finishes.";
  $("worst").replaceChildren(document.createTextNode("Worst finding "), node("strong", "Pending"));
  severity = ""; $("search").value = ""; $("checker").replaceChildren(new Option("All checkers", ""));
  $("cancel").disabled = false;
  setBusy(true); setStatus("Running", "running"); drawCounts(); drawFindings();
}
async function refreshRun(id, replayPending = false) {
  try {
    const scan = await api(`/api/scans/${id}`);
    if (id !== activeId) return;
    $("run-targets").textContent = scan.targets.join(" · ");
    if (["completed", "failed", "cancelled"].includes(scan.state)) {
      if (!replayPending) source?.close();
      clearTimeout(recovery); phase = scan.state; setBusy(false);
      $("connection").textContent = "Run finished";
      if (scan.report) renderReport(scan.report);
      else { setStatus(scan.state === "cancelled" ? "Stopped · incomplete" : "Failed · incomplete", scan.state); $("coverage").hidden = false; $("coverage").textContent = scan.error; drawFindings(); }
    }
  } catch (error) {
    if (id !== activeId) return;
    $("connection").textContent = "Unable to retrieve run";
    showError(`${error.message} Refresh to reconnect, or start a new assessment if this run has expired.`);
    // Do not pretend a lost connection stopped an engine task.
    source?.close(); setBusy(false); setStatus("Status unavailable", "incomplete");
    phase = "failed"; drawFindings();
  }
}
function connect(id) {
  source = new EventSource(`/api/scans/${id}/events`);
  source.onopen = () => { if (id === activeId) $("connection").textContent = "Connected"; };
  for (const kind of ["status", "progress", "done"]) source.addEventListener(kind, event => {
    if (id !== activeId) return;
    logEvent(JSON.parse(event.data), event.lastEventId);
    if (kind === "done") refreshRun(id);
  });
  source.onerror = () => {
    if (id !== activeId) return;
    if (!busy) { source?.close(); return; }
    $("connection").textContent = "Reconnecting…";
    clearTimeout(recovery);
    recovery = setTimeout(() => refreshRun(id), 3000);
  };
}
function targetInputs() {
  return $("targets").value.split(/[\s,]+/).filter(Boolean);
}
$("authorize-targets").onclick = async () => {
  if (busy) return;
  showError("");
  $("scope-status").textContent = "";
  $("authorize-targets").disabled = true;
  const originalTargets = $("targets").value;
  try {
    const data = await api("/api/targets/normalize", post({targets: targetInputs()}));
    if (busy || $("targets").value !== originalTargets) {
      showError("Targets changed or an assessment started. Review targets and click Authorize these targets again.");
      return;
    }
    // Preserve existing rules, especially denials. Clicking never submits a scan.
    const existing = $("scope").value.trimEnd();
    const lines = new Set(existing.split("\n").map(line => line.trim()));
    const additions = data.targets.map(host => `allow ${host}`).filter(line => !lines.has(line));
    $("scope").value = [existing, ...additions].filter(Boolean).join("\n");
    $("scope-status").textContent = `${additions.length} allow rule(s) added. Review scope, then start the assessment.`;
    $("scope").focus();
  } catch (error) { showError(error.message); }
  finally { $("authorize-targets").disabled = busy || !token; }
};
$("scan-form").addEventListener("submit", async event => {
  event.preventDefault(); if (busy) return; showError("");
  const targets = targetInputs();
  const scope = $("scope").value, authorizedBy = $("authorized-by").value;
  if (!authorizedBy.trim()) { showError("Authorized by is required. Enter the owner or approval reference."); $("authorized-by").focus(); return; }
  if (!scope.trim()) { showError("An explicit scope with at least one allow rule is required."); $("scope").focus(); return; }
  if (!targets.length) { showError("Enter at least one individual target hostname, URL or IP."); $("targets").focus(); return; }
  setBusy(true);
  $("cancel").disabled = true;
  try {
    const scan = await api("/api/scans", post({targets, scope, authorized_by: authorizedBy, nmap: document.querySelector("input[name=discovery]:checked").value === "nmap"}));
    resetRun(scan.id, scan.targets);
    history.replaceState(null, "", `#scan=${scan.id}`);
    connect(scan.id);
  } catch (error) { setBusy(false); $("cancel").disabled = false; showError(error.message); }
});
$("cancel").onclick = async () => {
  const id = activeId; $("cancel").disabled = true;
  try { await api(`/api/scans/${id}/cancel`, post({})); await refreshRun(id); }
  catch (error) { showError(error.message); }
  finally { $("cancel").disabled = false; }
};
for (const format of ["json", "html"]) $(`${format}-download`).onclick = () => {
  if (report) { const link = node("a"); link.href = `/api/scans/${activeId}/report.${format}`; link.download = `vulnscope2.${format}`; document.body.append(link); link.click(); link.remove(); }
};
$("search").oninput = drawFindings; $("checker").onchange = drawFindings;
$("clear-filters").onclick = () => { severity = ""; $("search").value = ""; $("checker").value = ""; drawCounts(); drawFindings(); };
document.querySelectorAll("input[name=discovery]").forEach(input => input.onchange = () => {
  $("discovery-help").textContent = input.value === "nmap" ? "Checks the same 23 ports with service detection. Falls back to native only if nmap is absent." : "Checks 23 common service ports with async TCP connections.";
});
let theme = "system";
try { theme = localStorage.getItem("vulnscope-theme") || "system"; } catch { /* Storage is optional. */ }
function applyTheme() {
  if (!["system", "light", "dark"].includes(theme)) theme = "system";
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  $("theme").textContent = `Theme: ${theme}`;
}
applyTheme();
$("theme").onclick = () => { theme = {system: "light", light: "dark", dark: "system"}[theme]; applyTheme(); try { localStorage.setItem("vulnscope-theme", theme); } catch { /* Storage is optional. */ } };
drawCounts(); drawFindings();
(async () => {
  try {
    const config = await api("/api/config"); token = config.token;
    $("ports").textContent = config.ports.join(", "); setBusy(false);
    const match = location.hash.match(/^#scan=([A-Za-z0-9_-]+)$/);
    if (match) { resetRun(match[1]); connect(match[1]); await refreshRun(match[1], true); }
  } catch (error) { showError(`Could not connect to the server. ${error.message} Refresh to retry.`); }
})();
