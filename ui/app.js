const invoke = window.__TAURI__.core.invoke;
const currentWindow = window.__TAURI__.webviewWindow.getCurrentWebviewWindow();

let config = null;
let activeSigningSession = null;
let loadingSessions = false;
let certificates = [];
let tokens = [];
let certificatesLoaded = false;
let tokenCertificateCache = null;
let cachePoll = null;
let signingInProgress = false;
let manualFile = null;
let manualResult = null;
let manualSigningInProgress = false;
let latestDiagnostics = null;
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

function yesNo(value) {
  return value ? "Si" : "No";
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
  certificates = [];
  tokens = [];
  certificatesLoaded = false;
  renderTokenCertificateCache(null);
  await refreshTokenCertificateCache();
}

async function restartServer() {
  setAppStatus("Reiniciando servidor...");
  await invoke("restart_server");
  await loadStatus();
}

async function loadTokens() {
  setAppStatus("Detectando token...");
  await loadTokenCertificateCache();
  if (!tokens.length) {
    setAppStatus("No se detectaron tokens", "error");
    return;
  }
  setAppStatus("Token detectado", "active");
}

async function loadCertificates() {
  setAppStatus("Cargando certificados...");
  await loadTokenCertificateCache();
  if (!certificates.length) {
    setAppStatus("No se encontraron certificados", "error");
    return;
  }
  setAppStatus("Certificados cargados", "active");
}

async function loadTokenCertificateCache() {
  const cache = await invoke("get_token_certificate_cache");
  applyTokenCertificateCache(cache);
  if (!cache.loaded_at) {
    setAppStatus("Cargando tokens y certificados...", "pending");
    startCacheWarmupPoll();
  }
}

async function refreshTokenCertificateCache() {
  setAppStatus("Actualizando tokens y certificados...");
  renderCacheLoading();
  const cache = await invoke("refresh_tokens_and_certificates");
  applyTokenCertificateCache(cache);
  setAppStatus("Tokens y certificados actualizados", "active");
}

function applyTokenCertificateCache(cache) {
  tokenCertificateCache = cache;
  tokens = cache.tokens || [];
  certificates = cache.certificates || [];
  certificatesLoaded = Boolean(cache.loaded_at);
  renderTokenCertificateCache(cache);
  renderTokens();
  renderCertificates();
  populateSigningCertificates();
  populateManualCertificates();
}

function renderTokens() {
  const container = document.getElementById("tokens");
  if (!container) {
    return;
  }
  if (!tokens.length) {
    empty(container, certificatesLoaded ? "No se detectaron slots." : "Cargando tokens...");
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
}

function renderCertificates() {
  const container = document.getElementById("certificates");
  if (!container) {
    return;
  }
  if (!certificates.length) {
    empty(container, certificatesLoaded ? "No se encontraron certificados." : "Cargando certificados...");
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
}

function renderTokenCertificateCache(cache) {
  const status = document.getElementById("cache-status");
  if (!status) {
    return;
  }
  if (!cache || !cache.loaded_at) {
    status.textContent = "Cargando tokens y certificados...";
    document.getElementById("cache-loaded-at").textContent = "-";
    document.getElementById("cache-token-count").textContent = "0";
    document.getElementById("cache-certificate-count").textContent = "0";
    document.getElementById("cache-library-path").textContent = "-";
    return;
  }
  status.textContent = "Cache cargada";
  document.getElementById("cache-loaded-at").textContent = new Date(cache.loaded_at).toLocaleString();
  document.getElementById("cache-token-count").textContent = cache.token_count;
  document.getElementById("cache-certificate-count").textContent = cache.certificate_count;
  document.getElementById("cache-library-path").textContent = cache.pkcs11_library_path || "-";
}

function renderCacheLoading() {
  const status = document.getElementById("cache-status");
  if (status) {
    status.textContent = "Actualizando...";
  }
}

function startCacheWarmupPoll() {
  if (windowMode !== "main" || cachePoll) {
    return;
  }
  let attempts = 0;
  cachePoll = window.setInterval(() => {
    attempts += 1;
    run(async () => {
      await loadTokenCertificateCache();
      if (tokenCertificateCache?.loaded_at || attempts >= 30) {
        window.clearInterval(cachePoll);
        cachePoll = null;
      }
    });
  }, 1000);
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
  document.getElementById("modal-approve").textContent = "Aprobar";
  setSigningProgress("Esperando firma", false);
}

async function showSigningSession(session) {
  activeSigningSession = session;
  document.getElementById("modal-session-id").textContent = session.id;
  document.getElementById("modal-format").textContent = humanSignFormat(session.format);
  document.getElementById("modal-language").textContent = session.language || "-";
  document.getElementById("modal-status").textContent = session.status;
  document.getElementById("modal-approve").textContent =
    session.format === "pdf" ? "Firmar PDF" : "Firmar JWS";
  showItems(document.getElementById("modal-files"), session.files.map((file) => item(
    file.name,
    [`Tamano: ${approximateSize(file.approximate_size_bytes)}`],
  )));
  clearPin();
  clearSigningError();
  setSigningProgress("Esperando firma", false);
  populateSigningCertificates();
  if (!certificatesLoaded) {
    await loadTokenCertificateCache();
    if (!certificatesLoaded) {
      await refreshTokenCertificateCache();
    }
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
      setSigningProgress(signingProgressText(session.format), true);
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
      `Formato: ${humanSignFormat(session.format)} - Idioma: ${session.language || "-"}`,
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
  populateCertificateSelect("modal-certificate", updateApprovalState);
}

function populateManualCertificates() {
  populateCertificateSelect("manual-certificate", updateManualState);
}

function populateCertificateSelect(selectId, onUpdate) {
  const select = document.getElementById(selectId);
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
    onUpdate();
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
  onUpdate();
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

function humanSignFormat(format) {
  if (format === "pdf") {
    return "PDF/PAdES";
  }
  if (format === "jws") {
    return "JWS";
  }
  return format || "-";
}

function signingProgressText(format) {
  if (format === "pdf") {
    return "Firmando PDF... No retire el token.";
  }
  return "Firmando JWS... No retire el token.";
}

async function selectManualFile() {
  const selected = await invoke("select_manual_file");
  if (!selected) {
    return;
  }
  manualFile = selected;
  manualResult = null;
  clearManualError();
  document.getElementById("manual-file-name").textContent = selected.name;
  document.getElementById("manual-file-size").textContent = approximateSize(selected.size_bytes);
  document.getElementById("manual-file-type").textContent = selected.detected_type;
  document.getElementById("manual-output-format").textContent = selected.output_format;
  document.getElementById("manual-suggested-name").textContent = selected.suggested_file_name || "-";
  document.getElementById("manual-sign-message").textContent = "";
  renderManualMode(selected);
  if ((selected.detected_type === "JSON" || selected.detected_type === "PDF") && !certificatesLoaded) {
    await loadTokenCertificateCache();
    if (!certificatesLoaded) {
      await refreshTokenCertificateCache();
    }
  }
  updateManualState();
}

async function signManualFile() {
  const input = selectedManualApprovalInput();
  if (!input) {
    return;
  }

  manualSigningInProgress = true;
  updateManualState();
  setManualProgress(true, manualFile.detected_type === "PDF"
    ? "Firmando PDF... No retire el token."
    : "Firmando archivo... no retire el token");
  clearManualError();
  try {
    if (manualFile.detected_type === "PDF") {
      manualResult = await invoke("sign_pdf", {
        path: manualFile.path,
        slotId: input.slotId,
        certificateId: input.certificateId,
        pin: input.pin,
      });
      document.getElementById("manual-sign-message").textContent = "PDF firmado. Abriendo Guardar como...";
      await saveManualPdfResult();
    } else {
      manualResult = await invoke("sign_file_as_jws", {
        path: manualFile.path,
        slotId: input.slotId,
        certificateId: input.certificateId,
        pin: input.pin,
      });
      document.getElementById("manual-sign-message").textContent = "Archivo firmado. Abriendo Guardar como...";
      await saveManualResult();
    }
  } catch (error) {
    manualResult = null;
    showManualError(error);
  } finally {
    clearManualPin();
    manualSigningInProgress = false;
    setManualProgress(false);
    updateManualState();
  }
}

async function saveManualResult() {
  if (!manualResult) {
    showManualError("No hay resultado firmado para guardar");
    return;
  }
  const response = await invoke("save_signed_file", {
    jwsBase64: manualResult.jws_base64,
    suggestedFileName: manualFile?.suggested_file_name || manualResult.suggested_file_name,
  });
  if (response.saved) {
    document.getElementById("manual-sign-message").textContent = `Guardado: ${response.path}`;
  } else {
    document.getElementById("manual-sign-message").textContent = "Archivo firmado. Guardado cancelado.";
  }
}

async function saveManualPdfResult() {
  if (!manualResult) {
    showManualError("No hay PDF firmado para guardar");
    return;
  }
  const response = await invoke("save_pdf_file", {
    pdfBase64: manualResult.pdf_base64,
    suggestedFileName: manualFile?.suggested_file_name || manualResult.suggested_file_name,
  });
  if (response.saved) {
    document.getElementById("manual-sign-message").textContent = `Guardado: ${response.path}`;
  } else {
    document.getElementById("manual-sign-message").textContent = "PDF firmado. Guardado cancelado.";
  }
}

function selectedManualApprovalInput() {
  if (!manualFile) {
    showManualError("archivo no seleccionado");
    updateManualState();
    return null;
  }
  if (manualFile.detected_type !== "JSON" && manualFile.detected_type !== "PDF") {
    showManualError("Actualmente solo se admiten archivos JSON y PDF");
    updateManualState();
    return null;
  }
  if (manualFile.detected_type === "PDF" && !pdfReady(manualFile)) {
    showManualError("El PDF no cumple las comprobaciones basicas para firma");
    updateManualState();
    return null;
  }
  const certificateValue = document.getElementById("manual-certificate").value;
  const pin = document.getElementById("manual-pin").value;
  if (!certificateValue) {
    showManualError("certificado no seleccionado");
    updateManualState();
    return null;
  }
  if (!pin) {
    showManualError("PIN vacio");
    updateManualState();
    return null;
  }

  const [slotId, certificateId] = certificateValue.split(":");
  return {
    slotId: Number(slotId),
    certificateId,
    pin,
  };
}

function updateManualState() {
  const signButton = document.getElementById("manual-sign-file");
  const certificate = document.getElementById("manual-certificate");
  const pinInput = document.getElementById("manual-pin");
  const certificateValue = document.getElementById("manual-certificate").value;
  const pin = document.getElementById("manual-pin").value;
  if (!manualFile || manualFile.detected_type === "No soportado") {
    signButton.textContent = "Firmar";
    signButton.disabled = true;
  } else if (manualFile.detected_type === "PDF") {
    signButton.textContent = "Firmar PDF";
    signButton.disabled = manualSigningInProgress || !pdfReady(manualFile) || !certificateValue || !pin;
  } else {
    signButton.textContent = "Firmar";
    signButton.disabled = manualSigningInProgress || !certificateValue || !pin;
  }
  const needsCredentials = manualFile?.detected_type === "JSON" || manualFile?.detected_type === "PDF";
  certificate.disabled = manualSigningInProgress || !needsCredentials;
  pinInput.disabled = manualSigningInProgress || !needsCredentials;
}

function setManualProgress(active, text = "Firmando archivo... no retire el token") {
  const textElement = document.getElementById("manual-sign-progress-text");
  if (textElement) {
    textElement.textContent = text;
  }
  document.getElementById("manual-sign-progress").classList.toggle("hidden", !active);
}

function showManualError(error) {
  const message = document.getElementById("manual-sign-error");
  message.textContent = String(error);
  message.classList.remove("hidden");
}

function clearManualError() {
  const message = document.getElementById("manual-sign-error");
  message.textContent = "";
  message.classList.add("hidden");
}

function clearManualPin() {
  document.getElementById("manual-pin").value = "";
  updateManualState();
}

function renderManualMode(file) {
  const isJson = file.detected_type === "JSON";
  const isPdf = file.detected_type === "PDF";
  const isUnsupported = file.detected_type === "No soportado";

  document.getElementById("manual-json-panel").classList.toggle("hidden", !(isJson || isPdf));
  document.getElementById("manual-pdf-panel").classList.toggle("hidden", !isPdf);
  document.getElementById("manual-unsupported-message").classList.toggle("hidden", !isUnsupported);
  document.getElementById("manual-pdf-progress").classList.add("hidden");

  if (isJson) {
    document.getElementById("manual-validation-status").textContent = "JSON listo para generar JWS.";
  } else if (isPdf) {
    renderManualPdfInfo(file.pdf_info);
  } else {
    document.getElementById("manual-validation-status").textContent =
      "Actualmente solo se admiten archivos JSON y PDF.";
  }
}

function renderManualPdfInfo(info) {
  const validHeader = Boolean(info?.valid_header);
  const hasEof = Boolean(info?.has_eof_marker);
  document.getElementById("manual-pdf-valid-header").textContent = validHeader ? "Si" : "No";
  document.getElementById("manual-pdf-has-eof").textContent = hasEof ? "Si" : "No";
  document.getElementById("manual-validation-status").textContent =
    validHeader && hasEof
      ? "PDF inspeccionado. Listo para firmar como ETSI.CAdES.detached."
      : "PDF inspeccionado, pero no cumple todas las comprobaciones basicas.";
}

function pdfReady(file) {
  return Boolean(file?.pdf_info?.valid_header && file?.pdf_info?.has_eof_marker);
}

async function selectAndValidateJws() {
  const selected = await invoke("select_file_to_validate");
  if (!selected) {
    return;
  }
  document.getElementById("validation-message").textContent = `Validando ${selected.name}...`;
  const report = await invoke("validate_jws_file", { path: selected.path });
  renderJwsValidation(selected, report);
  document.getElementById("validation-message").textContent = "Validacion JWS completada";
}

async function selectAndValidatePdf() {
  const selected = await invoke("select_file_to_validate");
  if (!selected) {
    return;
  }
  document.getElementById("validation-message").textContent = `Validando ${selected.name}...`;
  const report = await invoke("validate_pdf_file", { path: selected.path });
  renderPdfValidation(selected, report);
  document.getElementById("validation-message").textContent = "Validacion PDF completada";
}

function renderJwsValidation(selected, report) {
  const container = document.getElementById("jws-validation-result");
  showItems(container, [
    item(selected.name, [
      `Tamano: ${approximateSize(selected.size_bytes)}`,
      `Entrada detectada: ${report.detected_input}`,
      `Algoritmo: ${report.alg || "-"}`,
      `x5c presente: ${yesNo(report.has_x5c)}`,
      `Subject: ${report.certificate_subject || "-"}`,
      `Payload: ${approximateSize(report.payload_size_bytes)}`,
      `Firma RS256: ${report.valid ? "valida" : "invalida"}`,
      report.error ? `Error: ${report.error}` : "",
    ]),
  ]);
}

function renderPdfValidation(selected, report) {
  const container = document.getElementById("pdf-validation-result");
  showItems(container, [
    item(selected.name, [
      `Tamano: ${approximateSize(selected.size_bytes)}`,
      `Firma detectada: ${yesNo(report.signature_detected)}`,
      `ByteRange presente: ${yesNo(report.byte_range_present)}`,
      `Contents presente: ${yesNo(report.contents_present)}`,
      `Filter Adobe.PPKLite: ${yesNo(report.filter_adobe_ppklite)}`,
      `SubFilter ETSI.CAdES.detached: ${yesNo(report.subfilter_cades_detached)}`,
      `/M presente: ${yesNo(report.m_present)}`,
      `/Name presente: ${yesNo(report.name_present)}`,
      `/Reason presente: ${yesNo(report.reason_present)}`,
      `/Location presente: ${yesNo(report.location_present)}`,
      `/ContactInfo presente: ${yesNo(report.contact_info_present)}`,
      `Diagnostico estructural: ${report.structurally_valid ? "correcto" : "incompleto"}`,
      report.recommendation || "",
    ]),
  ]);
}

async function runSystemDiagnostics() {
  document.getElementById("validation-message").textContent = "Ejecutando diagnostico...";
  latestDiagnostics = await invoke("run_diagnostics");
  renderDiagnostics(latestDiagnostics);
  document.getElementById("validation-message").textContent = "Diagnostico completado";
}

function renderDiagnostics(report) {
  const container = document.getElementById("diagnostics-result");
  showItems(container, [
    item("Sistema", [
      `Version: ${report.app_version}`,
      `Servidor: ${report.server_https ? "HTTPS" : "HTTP"} ${report.server_host}:${report.server_port}`,
      `Driver configurado: ${report.configured_pkcs11_library_path || "-"}`,
      `Driver detectado: ${report.detected_pkcs11_library_path || "-"}`,
      `Driver encontrado: ${yesNo(report.driver_found)}`,
      `Fuente driver: ${report.driver_source || "-"}`,
      `PC/SC disponible: ${yesNo(report.pcsc_available)}`,
      report.last_error ? `Ultimo error: ${report.last_error}` : "",
    ]),
    item("Tokens y certificados", [
      `Tokens detectados: ${report.token_count}`,
      `Certificados detectados: ${report.certificate_count}`,
      ...((report.certificates || []).slice(0, 6).map((certificate) =>
        `${certificate.subject || certificate.label || "Certificado"} | vence: ${certificate.not_after || "-"} | slot: ${certificate.slot_id}`
      )),
    ]),
  ]);
}

async function exportDiagnostics() {
  const response = await invoke("export_diagnostics");
  document.getElementById("validation-message").textContent = response.saved
    ? `Diagnostico exportado: ${response.path}`
    : "Exportacion cancelada";
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
      await Promise.all([loadStatus(), loadConfig(), loadTokenCertificateCache(), loadSessions()]);
    }));
    document.getElementById("choose-library").addEventListener("click", () => run(selectLibrary));
    document.getElementById("save-config").addEventListener("click", () => run(saveConfig));
    document.getElementById("test-token").addEventListener("click", () => run(refreshTokenCertificateCache));
    document.getElementById("refresh-token-cache").addEventListener("click", () => run(refreshTokenCertificateCache));
    document.getElementById("reload-tokens").addEventListener("click", () => run(refreshTokenCertificateCache));
    document.getElementById("reload-certificates").addEventListener("click", () => run(refreshTokenCertificateCache));
    document.getElementById("reload-sessions").addEventListener("click", () => run(loadSessions));
    document.getElementById("manual-select-file").addEventListener("click", () => run(selectManualFile));
    document.getElementById("manual-sign-file").addEventListener("click", () => run(signManualFile));
    document.getElementById("validate-select-jws").addEventListener("click", () => run(selectAndValidateJws));
    document.getElementById("validate-select-pdf").addEventListener("click", () => run(selectAndValidatePdf));
    document.getElementById("run-diagnostics").addEventListener("click", () => run(runSystemDiagnostics));
    document.getElementById("export-diagnostics").addEventListener("click", () => run(exportDiagnostics));
    document.getElementById("manual-certificate").addEventListener("change", () => {
      clearManualError();
      updateManualState();
    });
    document.getElementById("manual-pin").addEventListener("input", () => {
      clearManualError();
      updateManualState();
    });
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
    await Promise.all([loadStatus(), loadConfig(), loadTokenCertificateCache(), loadSessions()]);
  } else {
    clearSigningForm();
    await loadTokenCertificateCache();
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
