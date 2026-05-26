const invoke = window.__TAURI__.core.invoke;

let config = null;

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

async function loadSessions() {
  const container = document.getElementById("sessions");
  const sessions = await invoke("list_signing_sessions");
  const pending = sessions.filter((session) => session.status === "pending");
  if (!pending.length) {
    empty(container, "Sin sesiones pendientes.");
    return;
  }
  showItems(container, pending.map((session) => item(
    session.files.map((file) => file.name).join(", "),
    [
      `ID: ${session.id}`,
      `Formato: ${session.format} - Estado: ${session.status}`,
    ],
  )));
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

run(async () => {
  await Promise.all([loadStatus(), loadConfig(), loadSessions()]);
});
