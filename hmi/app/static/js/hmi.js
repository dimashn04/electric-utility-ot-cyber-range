const els = {
  alarmBanner: document.getElementById("alarmBanner"),
  alarmText: document.getElementById("alarmText"),
  rtuStatus: document.getElementById("rtuStatus"),
  lastTelemetry: document.getElementById("lastTelemetry"),
  breakerSymbol: document.getElementById("breakerSymbol"),
  breakerLabel: document.getElementById("breakerLabel"),
  breakerState: document.getElementById("breakerState"),
  voltageValue: document.getElementById("voltageValue"),
  currentValue: document.getElementById("currentValue"),
  frequencyValue: document.getElementById("frequencyValue"),
  loadValue: document.getElementById("loadValue"),
  loadFill: document.getElementById("loadFill"),
  commandStatus: document.getElementById("commandStatus"),
  eventList: document.getElementById("eventList"),
  detectionList: document.getElementById("detectionList"),
  openBtn: document.getElementById("openBtn"),
  closeBtn: document.getElementById("closeBtn")
};

function fmt(value, digits = 2) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "--";
  return Number(value).toFixed(digits);
}

function setBreaker(state) {
  const closed = state === "CLOSED";
  els.breakerSymbol.classList.toggle("closed", closed);
  els.breakerSymbol.classList.toggle("open", !closed);
  document.querySelector(".downstream").classList.toggle("energized", closed);
  document.querySelector(".downstream").classList.toggle("deenergized", !closed);
  els.breakerLabel.textContent = `BREAKER ${state || "UNKNOWN"}`;
  els.breakerState.textContent = state || "UNKNOWN";
}

async function refreshStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    els.rtuStatus.textContent = data.rtu_connected ? "RTU: CONNECTED" : "RTU: DISCONNECTED";
    els.rtuStatus.classList.toggle("connected", Boolean(data.rtu_connected));
    els.rtuStatus.classList.toggle("disconnected", !data.rtu_connected);

    const telemetry = data.telemetry || {};
    const breaker = data.breaker || {};
    setBreaker(breaker.state);
    els.voltageValue.textContent = fmt(telemetry.voltage_kv);
    els.currentValue.textContent = fmt(telemetry.current_a);
    els.frequencyValue.textContent = fmt(telemetry.frequency_hz, 3);
    els.loadValue.textContent = `${fmt(telemetry.load_mw)} MW`;
    els.loadFill.style.width = `${Math.max(0, Math.min(100, (Number(telemetry.load_mw || 0) / 8) * 100))}%`;
    els.lastTelemetry.textContent = `Last telemetry: ${telemetry.timestamp || data.last_update || "--"}`;

    const alarms = data.alarms || [];
    els.alarmBanner.classList.toggle("alarm", alarms.length > 0);
    if (alarms.length > 0) {
      els.alarmText.textContent = `Alarm state: ${alarms[0].message}`;
      els.commandStatus.textContent = `Alarm: ${alarms[0].message}`;
    } else {
      els.alarmText.textContent = "Alarm state: normal workflow";
      if (!els.commandStatus.textContent.startsWith("Command status: sending")) {
        els.commandStatus.textContent = "Alarm: normal workflow";
      }
    }
  } catch (err) {
    els.rtuStatus.textContent = "RTU: API ERROR";
    els.rtuStatus.classList.add("disconnected");
    els.alarmBanner.classList.add("alarm");
    els.alarmText.textContent = "Alarm state: HMI API error";
  }
}

function eventHtml(event) {
  const details = event.details || {};
  const severityClass = event.severity === "warning" ? "event-warning" : "";
  const transition = details.previous_state || details.new_state ? `${details.previous_state || "?"} -> ${details.new_state || "?"}` : "";
  const selectState = details.select_token_status ? `select=${details.select_token_status}` : "";
  return `<div class="event-item ${severityClass}">
    <span class="event-type">${event.event_type || "event"}</span> <span class="muted">#${event.event_index || "--"}</span><br>
    ${event.message_type || ""} ${details.operation || ""} ${transition} ${selectState}<br>
    <span class="muted">claimed=${JSON.stringify(event.claimed_source || {})}</span><br>
    <span class="muted">correlation=${event.correlation_id || "none"}</span>
  </div>`;
}

function detectionHtml(item) {
  return `<div class="event-item event-critical">
    <span class="rule">${item.rule_id || "DETECTION"}</span><br>
    ${item.reason || ""}<br>
    <span class="muted">correlation=${item.correlation_id || "none"}</span>
  </div>`;
}

async function refreshEvents() {
  const res = await fetch("/api/events");
  const data = await res.json();
  const events = data.events || [];
  const detections = data.detections || [];
  els.eventList.innerHTML = events.length ? events.slice().reverse().map(eventHtml).join("") : "No RTU events.";
  els.detectionList.innerHTML = detections.length ? detections.slice().reverse().map(detectionHtml).join("") : "No detections.";
}

async function sendCommand(path, label) {
  els.commandStatus.textContent = `Command status: sending ${label}`;
  try {
    const res = await fetch(path, { method: "POST" });
    const data = await res.json();
    els.commandStatus.textContent = `Command status: ${label} correlation=${data.correlation_id || "unknown"}`;
    await refreshStatus();
    await refreshEvents();
  } catch (err) {
    els.commandStatus.textContent = `Command failed: ${err}`;
  }
}

els.openBtn.addEventListener("click", () => sendCommand("/api/commands/breaker/open", "OPEN BREAKER"));
els.closeBtn.addEventListener("click", () => sendCommand("/api/commands/breaker/close", "CLOSE BREAKER"));

refreshStatus();
refreshEvents();
setInterval(refreshStatus, 1000);
setInterval(refreshEvents, 2000);
