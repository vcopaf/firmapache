const invoke = window.__TAURI__.core.invoke;
const currentWindow = window.__TAURI__.webviewWindow.getCurrentWebviewWindow();

let config = null;
let activeSigningSession = null;
let loadingSessions = false;
let certificates = [];
let tokens = [];
let certificatesLoaded = false;
let signingInProgress = false;
const windowMode = currentWindow.label === "signing" ? "signing" : "main";

function showError(error) {
  const banner = document.getElementById("error-banner");
  banner.textContent = String(error);
  banner.classList.remove("hidden");
  window.setTimeout(() => banner.classList.add("hidden"), 6000);
}

function setAppStatus(text, state = "pending") {
  const textElement = document.getElementById("app-status-text");
  const dot = document.getElementById("app-status-dot");
  if (!textElement || !dot) {
    return;
  }

  textElement.textContent = text;
  dot.className = `status-dot ${state}`;
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
    if (!detail) {
      return;
    }
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
  setAppStatus("Iniciando servidor...");
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
  setAppStatus("Servicio local operativo", "active");
}

async function loadConfig() {
  setAppStatus("Cargando configuracion...");
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

async function restartServer() {
  setAppStatus("Reiniciando servidor...");
  await invoke("restart_server");
  await loadStatus();
}

async function loadTokens() {
  const container = document.getElementById("tokens");
  setAppStatus("Detectando token...");
  tokens = await invoke("list_tokens");
  if (!tokens.length) {
    empty(container, "No se detectaron slots.");
    setAppStatus("No se detectaron tokens", "error");
    return;
  }
  showItems(container, tokens.map((token) => item(
    tokenName(token),
    [
      `Slot ${token.slot_id} - ${token.token_present ? "presente" : "ausente"}`,
      `${token.manufacturer || ""} ${token.model || ""}`.trim(),
      token.serial_number ? `Serial: ${token.serial_number}` : "",
    ],
  )));
  setAppStatus("Token detectado", "active");
}

async function loadCertificates() {
  const container = document.getElementById("certificates");
  setAppStatus("Cargando certificados...");
  const [loadedTokens, loadedCertificates] = await Promise.all([
    invoke("list_tokens"),
    invoke("list_certificates"),
  ]);
  tokens = loadedTokens;
  certificates = loadedCertificates;
  certificatesLoaded = true;
  if (!certificates.length) {
    empty(container, "No se encontraron certificados.");
    populateSigningCertificates();
    setAppStatus("No se encontraron certificados", "error");
    return;
  }
  showItems(container, certificates.map((certificate) => item(
    certificateTitle(certificate),
    [
      `Subject: ${certificate.subject || "-"}`,
      `Issuer: ${certificate.issuer || "-"}`,
      `Vence: ${certificate.not_after || "-"}`,
      `Slot: ${certificate.slot_id}`,
      certificate.id ? `ID: ${certificate.id}` : "",
    ],
  )));
  populateSigningCertificates();
  setAppStatus("Certificados cargados", "active");
}

function tokenName(token) {
  const label = token.label || "Token";
  const serial = token.serial_number ? ` - serial ${token.serial_number}` : "";
  return `${label}${serial}`;
}

function tokenForSlot(slotId) {
  return tokens.find((token) => token.slot_id === slotId);
}

function certificateTitle(certificate) {
  return certificate.subject || certificate.label || "Certificado";
}

function certificateDetails(certificate) {
  return [
    certificateTitle(certificate),
    `Issuer: ${certificate.issuer || "-"}`,
    `Vence: ${certificate.not_after || "-"}`,
    `Slot: ${certificate.slot_id}`,
    `ID: ${certificate.id || "-"}`,
  ].join(" | ");
}

function clearSigningForm() {
  activeSigningSession = null;
  clearPin();
  clearSigningError();
  document.getElementById("modal-files").replaceChildren();
  document.getElementById("modal-session-id").textContent = "-";
  document.getElementById("modal-format").textContent = "-";
  document.getElementById("modal-language").textContent = "-";
  document.getElementById("modal-status").textContent = "esperando";
  setSigningProgress("Esperando firma", false);
}

async function showSigningSession(session) {
  activeSigningSession = session;
  document.getElementById("modal-session-id").textContent = session.id;
  document.getElementById("modal-format").textContent = session.format;
  document.getElementById("modal-language").textContent = session.language || "-";
  document.getElementById("modal-status").textContent = session.status;
  showItems(document.getElementById("modal-files"), session.files.map((file) => item(
    file.name,
    [`Tamano: ${approximateSize(file.approximate_size_bytes)}`],
  )));
  clearPin();
  clearSigningError();
  setSigningProgress("Esperando firma", false);
  populateSigningCertificates();
  if (!certificatesLoaded) {
    await loadCertificates();
  }
  updateApprovalState();
  document.getElementById("modal-pin").focus();
}

async function resolveSigningSession(action, session) {
  const approve = document.getElementById("modal-approve");
  const reject = document.getElementById("modal-reject");
  approve.disabled = true;
  reject.disabled = true;
  try {
    if (action === "approve") {
      const approval = selectedApprovalInput();
      if (!approval) {
        return;
      }
      signingInProgress = true;
      setSigningProgress("Firmando... no retire el token", true);
      try {
        await invoke("approve_signing_session", {
          sessionId: session.id,
          slotId: approval.slotId,
          certificateId: approval.certificateId,
          pin: approval.pin,
        });
        setSigningProgress("Completando firma...", true);
        clearPin();
        clearSigningForm();
        if (windowMode === "signing") {
          await closeSigningWindow();
        }
      } catch (error) {
        clearPin();
        showSigningError(error);
        setSigningProgress("Error de firma", false);
        return;
      } finally {
        signingInProgress = false;
      }
    } else {
      await invoke("reject_signing_session", { sessionId: session.id });
      clearSigningForm();
      if (windowMode === "signing") {
        await closeSigningWindow();
      }
    }
    await loadSessions();
  } finally {
    updateApprovalState();
    reject.disabled = false;
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
    button("Ver solicitud", "secondary", () => run(() => openSigningWindow())),
    button("Rechazar", "danger", () => run(() => resolveSigningSession("reject", session))),
    button("Aprobar", "", () => run(() => openSigningWindow())),
  );
  article.appendChild(actions);
  return article;
}

async function loadSessions() {
  const container = document.getElementById("sessions");
  const sessions = await invoke("list_signing_sessions");
  const pending = sessions.filter((session) => session.status === "pending");

  if (windowMode === "main") {
    if (!pending.length) {
      empty(container, "Sin sesiones pendientes.");
      return;
    }
    showItems(container, pending.map(sessionItem));
    setAppStatus("Esperando firma", "pending");
    await openSigningWindow();
    return;
  }

  if (!pending.length) {
    clearSigningForm();
    return;
  }

  const nextSession = activeSigningSession
    ? pending.find((session) => session.id === activeSigningSession.id) || pending[0]
    : pending[0];
  if (!activeSigningSession || activeSigningSession.id !== nextSession.id) {
    await showSigningSession(nextSession);
  }
}

async function openSigningWindow() {
  await invoke("show_signing_window");
}

async function closeSigningWindow() {
  await invoke("hide_signing_window");
}

function populateSigningCertificates() {
  const select = document.getElementById("modal-certificate");
  if (!select) {
    return;
  }

  const selectedValue = select.value;
  const options = certificates.filter((certificate) => certificate.id);
  select.replaceChildren();
  if (!options.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = certificatesLoaded
      ? "No hay certificados disponibles"
      : "Cargando certificados...";
    select.appendChild(option);
    select.disabled = true;
    updateApprovalState();
    return;
  }

  select.disabled = false;
  const certificatesBySlot = groupBySlot(options);

  certificatesBySlot.forEach((slotCertificates, slotId) => {
    const group = document.createElement("optgroup");
    const token = tokenForSlot(Number(slotId));
    group.label = token
      ? `${tokenName(token)} - slot ${slotId}`
      : `Token slot ${slotId}`;
    slotCertificates.forEach((certificate) => {
      const option = document.createElement("option");
      option.value = `${certificate.slot_id}:${certificate.id}`;
      option.textContent = certificateDetails(certificate);
      group.appendChild(option);
    });
    select.appendChild(group);
  });

  if (options.length === 1) {
    select.value = `${options[0].slot_id}:${options[0].id}`;
  } else if ([...select.options].some((option) => option.value === selectedValue)) {
    select.value = selectedValue;
  }
  updateApprovalState();
}

function groupBySlot(items) {
  const groups = new Map();
  items.forEach((item) => {
    const group = groups.get(item.slot_id) || [];
    group.push(item);
    groups.set(item.slot_id, group);
  });
  return groups;
}

function selectedApprovalInput() {
  const certificateValue = document.getElementById("modal-certificate").value;
  const pin = document.getElementById("modal-pin").value;
  if (!certificateValue) {
    showSigningError("Missing certificate selection");
    updateApprovalState();
    return null;
  }
  if (!pin) {
    showSigningError("Missing PIN");
    updateApprovalState();
    return null;
  }

  const [slotId, certificateId] = certificateValue.split(":");
  return {
    slotId: Number(slotId),
    certificateId,
    pin,
  };
}

function updateApprovalState() {
  const approve = document.getElementById("modal-approve");
  const certificateValue = document.getElementById("modal-certificate").value;
  const pin = document.getElementById("modal-pin").value;
  approve.disabled = signingInProgress || !certificateValue || !pin;
}

function setSigningProgress(text, active) {
  const progress = document.getElementById("signing-progress");
  const progressText = document.getElementById("signing-progress-text");
  progressText.textContent = text;
  progress.classList.toggle("hidden", !active);
}

function showSigningError(error) {
  const message = document.getElementById("modal-sign-error");
  message.textContent = String(error);
  message.classList.remove("hidden");
}

function clearSigningError() {
  const message = document.getElementById("modal-sign-error");
  message.textContent = "";
  message.classList.add("hidden");
}

function clearPin() {
  document.getElementById("modal-pin").value = "";
  updateApprovalState();
}

async function run(task) {
  try {
    await task();
  } catch (error) {
    if (windowMode === "signing") {
      showSigningError(error);
      setSigningProgress("Error de firma", false);
    } else {
      showError(error);
      setAppStatus("Error", "error");
    }
  }
}

function configureWindowMode() {
  document.body.dataset.window = windowMode;
  if (windowMode === "signing") {
    document.getElementById("signing-view").classList.remove("hidden");
  }
}

function bindEvents() {
  if (windowMode === "main") {
    document.getElementById("refresh-all").addEventListener("click", () => run(async () => {
      await Promise.all([loadStatus(), loadConfig(), loadSessions()]);
    }));
    document.getElementById("choose-library").addEventListener("click", () => run(selectLibrary));
    document.getElementById("save-config").addEventListener("click", () => run(saveConfig));
    document.getElementById("test-token").addEventListener("click", () => run(loadTokens));
    document.getElementById("reload-tokens").addEventListener("click", () => run(loadTokens));
    document.getElementById("reload-certificates").addEventListener("click", () => run(loadCertificates));
    document.getElementById("reload-sessions").addEventListener("click", () => run(loadSessions));
  }

  document.getElementById("close-sign-modal").addEventListener("click", () => run(closeSigningWindow));
  document.getElementById("modal-certificate").addEventListener("change", () => {
    clearSigningError();
    updateApprovalState();
  });
  document.getElementById("modal-pin").addEventListener("input", () => {
    clearSigningError();
    updateApprovalState();
  });
  document.getElementById("modal-approve").addEventListener("click", () => {
    if (activeSigningSession) {
      run(() => resolveSigningSession("approve", activeSigningSession));
    }
  });
  document.getElementById("modal-reject").addEventListener("click", () => {
    if (activeSigningSession) {
      run(() => resolveSigningSession("reject", activeSigningSession));
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && windowMode === "signing") {
      run(closeSigningWindow);
    }
  });
}

async function bootstrap() {
  configureWindowMode();
  bindEvents();
  if (windowMode === "main") {
    await Promise.all([loadStatus(), loadConfig(), loadSessions()]);
  } else {
    clearSigningForm();
    await loadSessions();
  }
}

run(bootstrap);

window.setInterval(() => {
  if (loadingSessions) {
    return;
  }
  loadingSessions = true;
  run(loadSessions).finally(() => {
    loadingSessions = false;
  });
}, 1000);
