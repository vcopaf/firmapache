const invoke = window.__TAURI__.core.invoke;

let config = null;
let activeModalSession = null;
let loadingSessions = false;
const displayedSessionIds = new Set();

function showError(error) {
  const banner = document.getElementById("error-banner");
  banner.textContent = String(error);
  banner.classList.remove("hidden");
  window.setTimeout(() => banner.classList.add("hidden"), 6000);
}

function empty(element, text) {
  element.className = "list empty";
  element.textContent = text;
}

function item(title, details) {
  const article = document.createElement("article");
  article.className = "item";
  const heading = document.createElement("strong");
  heading.textContent = title;
  article.appendChild(heading);
  details.forEach((detail) => {
    const line = document.createElement("span");
    line.textContent = detail;
    article.appendChild(line);
  });
  return article;
}

function showItems(container, items) {
  container.className = "list";
  container.replaceChildren(...items);
}

function button(label, className, action) {
  const element = document.createElement("button");
  element.type = "button";
  element.textContent = label;
  if (className) {
    element.className = className;
  }
  element.addEventListener("click", action);
  return element;
}

function approximateSize(bytes) {
  if (bytes < 1024) {
    return `${bytes} B aprox.`;
  }
  return `${(bytes / 1024).toFixed(1)} KB aprox.`;
}

async function loadStatus() {
  const status = await invoke("get_status");
  document.getElementById("service-name").textContent = status.service;
  document.getElementById("service-version").textContent = status.version;
  document.getElementById("service-mode").textContent = status.https ? "HTTPS" : "HTTP";
  document.getElementById("service-port").textContent = status.port;
  document.getElementById("active-library-path").textContent =
    status.pkcs11_library_path || "No detectado";
  const indicator = document.getElementById("service-indicator");
  indicator.textContent = status.active ? "Activo" : "No disponible";
  indicator.className = `badge ${status.active ? "active" : "pending"}`;
}

async function loadConfig() {
  config = await invoke("get_config");
  document.getElementById("library-path").value = config.pkcs11.library_path || "";
}

async function selectLibrary() {
  const selected = await invoke("select_pkcs11_library");
  if (selected) {
    document.getElementById("library-path").value = selected;
  }
}

async function saveConfig() {
  if (!config) {
    await loadConfig();
  }
  config.pkcs11.library_path = document.getElementById("library-path").value;
  config = await invoke("save_config", { config });
  const message = document.getElementById("save-message");
  message.textContent = "Guardado";
  window.setTimeout(() => { message.textContent = ""; }, 2500);
}

async function loadTokens() {
  const container = document.getElementById("tokens");
  const tokens = await invoke("list_tokens");
  if (!tokens.length) {
    empty(container, "No se detectaron slots.");
    return;
  }
  showItems(container, tokens.map((token) => item(
    token.label || "Slot sin token",
    [
      `Slot ${token.slot_id} - ${token.token_present ? "presente" : "ausente"}`,
      `${token.manufacturer || ""} ${token.model || ""}`.trim(),
    ],
  )));
}

async function loadCertificates() {
  const container = document.getElementById("certificates");
  const certificates = await invoke("list_certificates");
  if (!certificates.length) {
    empty(container, "No se encontraron certificados.");
    return;
  }
  showItems(container, certificates.map((certificate) => item(
    certificate.label || "Certificado",
    [
      `Subject: ${certificate.subject || "-"}`,
      `Issuer: ${certificate.issuer || "-"}`,
      `Vence: ${certificate.not_after || "-"}`,
    ],
  )));
}

function closeSigningModal() {
  activeModalSession = null;
  document.getElementById("sign-modal-backdrop").classList.add("hidden");
  document.getElementById("modal-files").replaceChildren();
}

function openSigningModal(session) {
  activeModalSession = session;
  displayedSessionIds.add(session.id);
  document.getElementById("modal-session-id").textContent = session.id;
  document.getElementById("modal-format").textContent = session.format;
  document.getElementById("modal-language").textContent = session.language || "-";
  document.getElementById("modal-status").textContent = "pendiente";
  showItems(document.getElementById("modal-files"), session.files.map((file) => item(
    file.name,
    [`Tamano: ${approximateSize(file.approximate_size_bytes)}`],
  )));
  document.getElementById("sign-modal-backdrop").classList.remove("hidden");
  document.getElementById("modal-approve").focus();
}

async function resolveSigningSession(action, session) {
  const resolvingActiveModal = activeModalSession && activeModalSession.id === session.id;
  const modalApprove = document.getElementById("modal-approve");
  const modalReject = document.getElementById("modal-reject");
  if (resolvingActiveModal) {
    modalApprove.disabled = true;
    modalReject.disabled = true;
  }
  try {
    const command = action === "approve" ? "approve_signing_session" : "reject_signing_session";
    await invoke(command, { sessionId: session.id });
    if (resolvingActiveModal) {
      closeSigningModal();
    }
    await loadSessions();
  } finally {
    modalApprove.disabled = false;
    modalReject.disabled = false;
  }
}

function sessionItem(session) {
  const article = item(
    session.files.map((file) => file.name).join(", "),
    [
      `ID: ${session.id}`,
      `Formato: ${session.format} - Idioma: ${session.language || "-"}`,
      `Estado: ${session.status}`,
    ],
  );
  const actions = document.createElement("div");
  actions.className = "item-actions";
  actions.append(
    button("Ver solicitud", "secondary", () => openSigningModal(session)),
    button("Rechazar", "danger", () => run(() => resolveSigningSession("reject", session))),
    button("Aprobar", "", () => run(() => resolveSigningSession("approve", session))),
  );
  article.appendChild(actions);
  return article;
}

async function loadSessions() {
  const container = document.getElementById("sessions");
  const sessions = await invoke("list_signing_sessions");
  const pending = sessions.filter((session) => session.status === "pending");
  if (activeModalSession && !pending.some((session) => session.id === activeModalSession.id)) {
    closeSigningModal();
  }
  if (!pending.length) {
    empty(container, "Sin sesiones pendientes.");
    return;
  }
  showItems(container, pending.map(sessionItem));
  if (!activeModalSession) {
    const newSession = pending.find((session) => !displayedSessionIds.has(session.id));
    if (newSession) {
      openSigningModal(newSession);
    }
  }
}

async function run(task) {
  try {
    await task();
  } catch (error) {
    showError(error);
  }
}

document.getElementById("refresh-all").addEventListener("click", () => run(async () => {
  await Promise.all([loadStatus(), loadConfig(), loadSessions()]);
}));
document.getElementById("choose-library").addEventListener("click", () => run(selectLibrary));
document.getElementById("save-config").addEventListener("click", () => run(saveConfig));
document.getElementById("test-token").addEventListener("click", () => run(loadTokens));
document.getElementById("reload-tokens").addEventListener("click", () => run(loadTokens));
document.getElementById("reload-certificates").addEventListener("click", () => run(loadCertificates));
document.getElementById("reload-sessions").addEventListener("click", () => run(loadSessions));
document.getElementById("close-sign-modal").addEventListener("click", closeSigningModal);
document.getElementById("modal-approve").addEventListener("click", () => {
  if (activeModalSession) {
    run(() => resolveSigningSession("approve", activeModalSession));
  }
});
document.getElementById("modal-reject").addEventListener("click", () => {
  if (activeModalSession) {
    run(() => resolveSigningSession("reject", activeModalSession));
  }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && activeModalSession) {
    closeSigningModal();
  }
});

run(async () => {
  await Promise.all([loadStatus(), loadConfig(), loadSessions()]);
});

window.setInterval(() => {
  if (loadingSessions) {
    return;
  }
  loadingSessions = true;
  run(loadSessions).finally(() => {
    loadingSessions = false;
  });
}, 1000);
