"use strict";

// API do Tauri (disponível porque "withGlobalTauri" está ativo).
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const dialog = window.__TAURI__.dialog;

// ------------------------------------------------------------------ helpers

const $ = (id) => document.getElementById(id);

/**
 * Cria um elemento DOM. Todo texto entra via textContent, nunca via innerHTML,
 * pois nomes de arquivo podem conter qualquer caractere (proteção contra XSS).
 */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function formatBytes(n) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  return `${m} min ${Math.round(s % 60)} s`;
}

function formatDate(iso) {
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString("pt-BR");
}

function timeAgo(iso) {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (isNaN(diff)) return iso;
  if (diff < 60) return "agora mesmo";
  if (diff < 3600) return `há ${Math.floor(diff / 60)} min`;
  if (diff < 86400) return `há ${Math.floor(diff / 3600)} h`;
  return `há ${Math.floor(diff / 86400)} dia(s)`;
}

let toastTimer;
function toast(message, isError = false) {
  const t = $("toast");
  t.textContent = message;
  t.classList.toggle("error", isError);
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), isError ? 7000 : 4000);
}

function confirmDialog(title, text, okLabel = "Confirmar") {
  return new Promise((resolve) => {
    const modal = $("modal");
    $("modal-title").textContent = title;
    $("modal-text").textContent = text;
    $("modal-ok").textContent = okLabel;
    const done = (value) => {
      $("modal-ok").onclick = null;
      $("modal-cancel").onclick = null;
      modal.close();
      resolve(value);
    };
    $("modal-ok").onclick = () => done(true);
    $("modal-cancel").onclick = () => done(false);
    modal.oncancel = () => resolve(false);
    modal.showModal();
  });
}

const VERDICT_LABEL = { malicious: "MALICIOSO", suspicious: "SUSPEITO", clean: "LIMPO" };
const STATUS_LABEL = { quarantined: "ISOLADO", restored: "RESTAURADO", deleted: "EXCLUÍDO" };
const CATEGORY_LABEL = {
  test: "Arquivo de teste",
  trojan: "Cavalo de Troia",
  ransomware: "Ransomware",
  worm: "Worm",
  backdoor: "Backdoor / acesso remoto",
  spyware: "Spyware / roubo de dados",
  adware: "Adware",
  pua: "Programa indesejado",
  hack_tool: "Ferramenta de ataque",
  exploit: "Exploit",
  downloader: "Downloader / dropper",
  generic: "Genérico",
};

function scoreBadge(score) {
  const cls = score >= 70 ? "high" : score >= 40 ? "mid" : "";
  return h("div", { class: `score ${cls}` },
    h("div", { class: "score-num" }, score),
    h("div", { class: "score-label" }, "risco"));
}

// --------------------------------------------------------------- navegação

function showPage(name) {
  document.querySelectorAll(".nav-item").forEach((b) =>
    b.classList.toggle("active", b.dataset.page === name));
  document.querySelectorAll(".page").forEach((p) =>
    p.classList.toggle("active", p.id === `page-${name}`));
  if (name === "dashboard") refreshDashboard();
  if (name === "history") loadHistory();
  if (name === "quarantine") loadQuarantine();
  if (name === "settings") loadSettings();
}

document.querySelectorAll(".nav-item").forEach((b) =>
  b.addEventListener("click", () => showPage(b.dataset.page)));
document.querySelectorAll("[data-goto]").forEach((b) =>
  b.addEventListener("click", () => showPage(b.dataset.goto)));

// ------------------------------------------------------------------ painel

async function refreshDashboard() {
  try {
    const s = await invoke("get_status");
    $("version").textContent = `versão ${s.version}`;
    $("c-signatures").textContent = s.signatures;
    $("c-yara").textContent = s.yara_error ? "Erro" : s.yara_rules;
    $("c-yara-foot").textContent = s.yara_error || "padrões de detecção ativos";
    $("c-yara").classList.toggle("error-text", Boolean(s.yara_error));
    $("c-quarantine").textContent = s.quarantined;

    const badge = $("nav-q-badge");
    badge.textContent = s.quarantined;
    badge.classList.toggle("hidden", s.quarantined === 0);

    const last = s.last_scan;
    if (last) {
      $("c-last-scan").textContent = timeAgo(last.finished_at);
      $("c-last-scan-foot").textContent =
        `${last.files_scanned} arquivos · ${last.detections} detecção(ões)`;
    } else {
      $("c-last-scan").textContent = "Nunca";
      $("c-last-scan-foot").textContent = "faça sua primeira verificação";
    }

    const hero = $("hero");
    const issues = last && last.detections > 0;
    const stale = !last || (Date.now() - new Date(last.finished_at)) > 7 * 86400e3;
    hero.classList.toggle("warn", Boolean(issues || stale));
    if (!last) {
      $("hero-title").textContent = "Nenhuma verificação ainda";
      $("hero-sub").textContent = "Execute uma verificação rápida para conhecer o estado do seu computador.";
    } else if (issues) {
      $("hero-title").textContent = "Atenção necessária";
      $("hero-sub").textContent =
        `A última verificação encontrou ${last.detections} item(ns). Revise os resultados no Histórico.`;
    } else if (stale) {
      $("hero-title").textContent = "Verificação recomendada";
      $("hero-sub").textContent = "Faz mais de 7 dias desde a última verificação.";
    } else {
      $("hero-title").textContent = "Seu computador está protegido";
      $("hero-sub").textContent = "Nenhuma ameaça encontrada na última verificação.";
    }
  } catch (e) {
    toast(`Erro ao carregar status: ${e}`, true);
  }
}

// ---------------------------------------------------------------- métricas

async function refreshMetrics() {
  try {
    const m = await invoke("metrics");
    const pct = (v) => `${Math.min(100, Math.max(0, v)).toFixed(0)}%`;
    $("m-app-cpu").textContent = `${m.app_cpu.toFixed(1)}%`;
    $("m-app-cpu-bar").style.width = pct(m.app_cpu);
    $("m-app-mem").textContent = `${m.app_memory_mb.toFixed(0)} MB`;
    $("m-sys-cpu").textContent = `${m.system_cpu.toFixed(0)}%`;
    $("m-sys-cpu-bar").style.width = pct(m.system_cpu);
    $("m-sys-mem").textContent =
      `${(m.system_memory_used_mb / 1024).toFixed(1)} / ${(m.system_memory_total_mb / 1024).toFixed(1)} GB`;
    $("m-sys-mem-bar").style.width = pct((m.system_memory_used_mb / m.system_memory_total_mb) * 100);
  } catch (_) {
    /* métricas são opcionais */
  }
}

// -------------------------------------------------------------- verificação

const SCAN_LABEL = { quick: "Verificação rápida", full: "Verificação completa", custom: "Verificação personalizada" };
let scanning = false;

function setScanning(on) {
  scanning = on;
  document.querySelectorAll("[data-scan], [data-quick-scan]").forEach((b) => (b.disabled = on));
  $("scan-progress").classList.toggle("hidden", !on);
  $("scan-options").classList.toggle("hidden", on);
  $("btn-cancel").disabled = false;
}

listen("scan-progress", (event) => {
  $("scan-files").textContent = event.payload.files.toLocaleString("pt-BR");
  $("scan-current").textContent = event.payload.current;
});

async function startScan(kind) {
  if (scanning) return;
  let path = null;
  if (kind === "custom") {
    path = await dialog.open({ directory: true, multiple: false, title: "Escolha a pasta para verificar" });
    if (!path) return;
  }
  if (kind === "full") {
    const ok = await confirmDialog("Verificação completa",
      "Todas as unidades serão verificadas. Isso pode levar bastante tempo, mas você pode cancelar a qualquer momento.",
      "Iniciar");
    if (!ok) return;
  }

  showPage("scan");
  $("scan-result").classList.add("hidden");
  $("scan-label").textContent = path ? `Verificando ${path}` : `${SCAN_LABEL[kind]} em andamento…`;
  $("scan-files").textContent = "0";
  $("scan-current").textContent = "";
  setScanning(true);

  try {
    const result = await invoke("start_scan", { kind, path });
    renderScanResult(result);
  } catch (e) {
    toast(`Falha na verificação: ${e}`, true);
    $("scan-options").classList.remove("hidden");
  } finally {
    setScanning(false);
    if (!$("scan-result").classList.contains("hidden")) $("scan-options").classList.add("hidden");
    refreshDashboard();
  }
}

document.querySelectorAll("[data-scan]").forEach((b) =>
  b.addEventListener("click", () => startScan(b.dataset.scan)));
document.querySelectorAll("[data-quick-scan]").forEach((b) =>
  b.addEventListener("click", () => startScan("quick")));

$("btn-cancel").addEventListener("click", async () => {
  $("btn-cancel").disabled = true;
  await invoke("cancel_scan");
});

$("btn-new-scan").addEventListener("click", () => {
  $("scan-result").classList.add("hidden");
  $("scan-options").classList.remove("hidden");
});

function detectionItem(d, { quarantinedPaths = new Set(), allowIsolate = true } = {}) {
  const isolated = quarantinedPaths.has(d.path);
  const actions = h("div", { class: "item-actions" });
  if (isolated) {
    actions.append(h("span", { class: "pill quarantined" }, "ISOLADO"));
  } else if (allowIsolate) {
    const btn = h("button", { class: "btn danger small" }, "Isolar");
    btn.addEventListener("click", async () => {
      const ok = await confirmDialog("Isolar arquivo",
        `O arquivo será movido para a quarentena:\n${d.path}`, "Isolar");
      if (!ok) return;
      try {
        await invoke("quarantine_add", { path: d.path });
        actions.replaceChildren(h("span", { class: "pill quarantined" }, "ISOLADO"));
        toast("Arquivo isolado com sucesso.");
        refreshDashboard();
      } catch (e) {
        toast(`Não foi possível isolar: ${e}`, true);
      }
    });
    actions.append(btn);
  }

  const reasons = (d.indicators || []).map((i) => h("li", {}, i.description));
  return h("div", { class: "item" },
    scoreBadge(d.risk_score),
    h("div", { class: "item-main" },
      h("div", { class: "item-path" }, d.path),
      h("div", { class: "item-meta" },
        h("span", { class: `pill ${d.verdict}` }, VERDICT_LABEL[d.verdict] || d.verdict),
        d.category ? h("span", { class: "pill category" }, CATEGORY_LABEL[d.category] || d.category) : null,
        d.threat_name ? `  ${d.threat_name}` : "",
        `  ·  ${formatBytes(d.size)}  ·  SHA-256 ${d.sha256.slice(0, 16)}…`),
      reasons.length ? h("ul", { class: "item-reasons" }, reasons) : null),
    actions);
}

function renderScanResult(r) {
  const n = r.detections.length;
  $("result-title").textContent = r.cancelled
    ? "Verificação cancelada"
    : n === 0 ? "Nenhuma ameaça encontrada" : `${n} item(ns) encontrado(s)`;
  $("result-sub").textContent =
    `${r.label} · ${r.files_scanned.toLocaleString("pt-BR")} arquivos (${formatBytes(r.bytes_scanned)}) em ` +
    `${formatDuration(r.elapsed_ms)}` +
    (r.errors ? ` · ${r.errors} sem acesso` : "") +
    (r.quarantined.length ? ` · ${r.quarantined.length} isolado(s) automaticamente` : "");

  const list = $("result-list");
  list.replaceChildren();
  if (n === 0) {
    list.append(h("div", { class: "clean-result" },
      svgCheck(), r.cancelled ? "Nada encontrado até o cancelamento." : "Tudo limpo!"));
  } else {
    const qPaths = new Set(r.quarantined.map((q) => q.original_path));
    r.detections.forEach((d) => list.append(detectionItem(d, { quarantinedPaths: qPaths })));
  }
  r.quarantine_errors.forEach((e) => toast(`Falha ao isolar: ${e}`, true));
  $("scan-result").classList.remove("hidden");
}

function svgCheck() {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", "M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5zm-2 16-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9z");
  svg.append(path);
  return svg;
}

// --------------------------------------------------------------- histórico

async function loadHistory() {
  try {
    const scans = await invoke("history", { limit: 100 });
    const body = $("history-body");
    body.replaceChildren();
    $("history-empty").classList.toggle("hidden", scans.length > 0);
    scans.forEach((s) => {
      const row = h("tr", {},
        h("td", {}, s.id),
        h("td", {}, formatDate(s.finished_at)),
        h("td", {}, s.target),
        h("td", { class: "num" }, s.files_scanned.toLocaleString("pt-BR")),
        h("td", { class: `num ${s.detections ? "det-pos" : ""}` }, s.detections),
        h("td", { class: "num" }, formatDuration(s.duration_ms)));
      row.addEventListener("click", () => showScanDetails(s));
      body.append(row);
    });
  } catch (e) {
    toast(`Erro ao carregar histórico: ${e}`, true);
  }
}

async function showScanDetails(scan) {
  try {
    const dets = await invoke("scan_details", { scanId: scan.id });
    $("history-details-title").textContent = `Verificação #${scan.id} · ${formatDate(scan.finished_at)}`;
    const list = $("history-details-list");
    list.replaceChildren();
    if (dets.length === 0) {
      list.append(h("div", { class: "clean-result" }, svgCheck(), "Nenhuma ameaça nesta verificação."));
    }
    dets.forEach((d) => {
      let indicators = [];
      try { indicators = JSON.parse(d.indicators_json); } catch (_) { /* ignora */ }
      list.append(detectionItem({ ...d, indicators }, { allowIsolate: false }));
    });
    $("history-details").classList.remove("hidden");
    $("history-details").scrollIntoView({ behavior: "smooth" });
  } catch (e) {
    toast(`Erro ao carregar detalhes: ${e}`, true);
  }
}

$("btn-close-details").addEventListener("click", () => $("history-details").classList.add("hidden"));

// -------------------------------------------------------------- quarentena

async function loadQuarantine() {
  try {
    const items = await invoke("quarantine_list", { all: $("q-show-all").checked });
    const list = $("q-list");
    list.replaceChildren();
    $("q-empty").classList.toggle("hidden", items.length > 0);
    items.forEach((q) => list.append(quarantineItem(q)));
  } catch (e) {
    toast(`Erro ao carregar quarentena: ${e}`, true);
  }
}

function quarantineItem(q) {
  const actions = h("div", { class: "item-actions" });
  if (q.status === "quarantined") {
    actions.append(
      h("button", { class: "btn ghost small", onclick: () => restoreItem(q) }, "Restaurar"),
      h("button", { class: "btn danger small", onclick: () => deleteItem(q) }, "Excluir"));
  }
  return h("div", { class: "item" },
    scoreBadge(q.risk_score),
    h("div", { class: "item-main" },
      h("div", { class: "item-path" }, q.original_path),
      h("div", { class: "item-meta" },
        h("span", { class: `pill ${q.status}` }, STATUS_LABEL[q.status] || q.status),
        q.threat_name ? `  ${q.threat_name}` : "",
        `  ·  ${formatBytes(q.size)}  ·  isolado em ${formatDate(q.quarantined_at)}`)),
    actions);
}

async function restoreItem(q) {
  const ok = await confirmDialog("Restaurar arquivo",
    `O arquivo voltará para o local original. Só faça isso se tiver certeza de que ele é seguro.\n${q.original_path}`,
    "Restaurar");
  if (!ok) return;
  try {
    await invoke("quarantine_restore", { id: q.id, overwrite: false });
    toast("Arquivo restaurado.");
  } catch (e) {
    if (String(e).includes("já existe")) {
      const over = await confirmDialog("Arquivo já existe",
        "Já existe outro arquivo no local original. Deseja substituí-lo?", "Substituir");
      if (!over) return;
      try {
        await invoke("quarantine_restore", { id: q.id, overwrite: true });
        toast("Arquivo restaurado.");
      } catch (e2) {
        toast(`Não foi possível restaurar: ${e2}`, true);
      }
    } else {
      toast(`Não foi possível restaurar: ${e}`, true);
    }
  }
  loadQuarantine();
  refreshDashboard();
}

async function deleteItem(q) {
  const ok = await confirmDialog("Excluir definitivamente",
    `Esta ação não pode ser desfeita.\n${q.original_path}`, "Excluir");
  if (!ok) return;
  try {
    await invoke("quarantine_delete", { id: q.id });
    toast("Arquivo excluído definitivamente.");
  } catch (e) {
    toast(`Não foi possível excluir: ${e}`, true);
  }
  loadQuarantine();
  refreshDashboard();
}

$("q-show-all").addEventListener("change", loadQuarantine);

// ----------------------------------------------------------- configurações

async function loadSettings() {
  try {
    const s = await invoke("get_settings");
    $("s-auto-q").checked = s.auto_quarantine;
    $("s-max-size").value = s.max_file_size_mb;
    $("s-data-dir").textContent = s.data_dir;
  } catch (e) {
    toast(`Erro ao carregar configurações: ${e}`, true);
  }
}

$("btn-save-settings").addEventListener("click", async () => {
  const max = Number($("s-max-size").value);
  if (!Number.isInteger(max) || max < 0 || max > 100000) {
    toast("Tamanho máximo inválido (0 a 100000 MB).", true);
    return;
  }
  try {
    await invoke("save_settings", { autoQuarantine: $("s-auto-q").checked, maxFileSizeMb: max });
    toast("Configurações salvas.");
  } catch (e) {
    toast(`Erro ao salvar: ${e}`, true);
  }
});

// ------------------------------------------------------------- inicialização

refreshDashboard();
refreshMetrics();
setInterval(refreshMetrics, 2000);
