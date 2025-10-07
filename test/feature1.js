// ===== Config =====
const API_URL = 'http://127.0.0.1:5000/run-script'; // Flask endpoint

// ===== Tabs helper
function switchToScan() {
  document.getElementById('tab-scan').checked = true;
}

// ===== Elements
const enterScanBtn = document.getElementById('enterScan');
const overlay = document.getElementById('matrixOverlay');
const canvas = document.getElementById('matrixCanvas');
const ctx = canvas.getContext('2d');
const textEl = document.getElementById('matrixText');
const scanOutput = document.getElementById('scanOutput'); // if present

let columns = [], drops = [], rafId = null, running = false;
let pendingOutput = "Waiting for scan...";
let loadingTimer = null;

// Ensure the text is above the canvas just in case
if (textEl) textEl.style.zIndex = '1';

// ===== Matrix animation helpers
function sizeCanvas() {
  const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
  canvas.width = Math.floor(canvas.clientWidth * dpr);
  canvas.height = Math.floor(canvas.clientHeight * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const columnWidth = 16;
  columns = Math.ceil(canvas.clientWidth / columnWidth);
  drops = new Array(columns).fill(0).map(() => Math.floor(Math.random() * canvas.clientHeight));
}

function drawMatrix() {
  ctx.fillStyle = "rgba(0, 0, 0, 0.08)";
  ctx.fillRect(0, 0, canvas.clientWidth, canvas.clientHeight);
  ctx.font = "16px monospace";
  for (let i = 0; i < columns; i++) {
    const char = String.fromCharCode(0x30A0 + Math.floor(Math.random() * 96));
    const x = i * 16;
    const y = drops[i] * 16;
    ctx.fillStyle = "rgba(8, 247, 111, 0.9)";
    ctx.fillText(char, x, y);
    if (y > canvas.clientHeight && Math.random() > 0.975) drops[i] = 0;
    drops[i]++;
  }
  if (running) rafId = requestAnimationFrame(drawMatrix);
}

// Show a word with fade; keep it visible a bit longer so it’s noticeable
function showWord(word, visibleMs = 1200) {
  textEl.textContent = word;
  textEl.classList.add('show');
  setTimeout(() => textEl.classList.remove('show'), visibleMs);
}

// ===== Loading pulse (every 10s while overlay is visible)
// First pulse happens AFTER the intro words so it’s not hidden by them
function startLoadingPulse(initialDelayMs = 300 /* after SAFE */, intervalMs = 10000) {
  stopLoadingPulse(); // just in case
  // first pulse after the intro sequence
  const first = setTimeout(() => {
    showWord('Loading ...');                 // pulse 1
    loadingTimer = setInterval(() => {       // subsequent pulses
      showWord('Loading ...');
    }, intervalMs);
  }, initialDelayMs);
  // store the first timeout handle so we can clear if needed
  loadingTimer = { first, interval: null };
  // wrap setInterval handle when it starts
  setTimeout(() => {
    if (loadingTimer && !loadingTimer.interval) {
      loadingTimer.interval = 'started'; // marker; actual handle set above
    }
  }, initialDelayMs + 50);
}

function stopLoadingPulse() {
  if (!loadingTimer) return;
  // if we stored a Timeout + Interval pair, clear them safely
  if (loadingTimer.first) clearTimeout(loadingTimer.first);
  // Ugly but robust: try clearing both in case of shape change
  try { clearInterval(loadingTimer); } catch {}
  try { clearInterval(loadingTimer.interval); } catch {}
  loadingTimer = null;
}

// ===== Start/stop overlay
function startMatrixTransition() {
  overlay.style.display = 'block';
  sizeCanvas();
  running = true;
  drawMatrix();

  // Intro sequence
  setTimeout(() => showWord('HOME', 900), 600);
  setTimeout(() => showWord('NET', 900), 1300);
  setTimeout(() => showWord('SAFE', 900), 2000);

  // Start periodic "Loading ..." pulses AFTER the intro finishes
  startLoadingPulse(300); // ~2.3s from start
}

function endMatrixTransitionAndShowOutput() {
  running = false;
  cancelAnimationFrame(rafId);
  stopLoadingPulse();
  overlay.style.display = 'none';
  switchToScan();
  if (scanOutput) scanOutput.textContent = pendingOutput;
}

// ===== Call Python (Flask) to run "Device Discovery.py"
async function runDeviceDiscovery(){
  try {
    if (scanOutput) scanOutput.textContent = "Running scan...";
    const r = await fetch(API_URL, { method: 'GET', mode: 'cors', cache: 'no-store' });
    if (!r.ok) {
      const txt = await r.text().catch(()=> '');
      throw new Error(`HTTP ${r.status} ${r.statusText}${txt ? ' — ' + txt : ''}`);
    }
    const data = await r.json();

    let out = '';
    if (typeof data.stdout === 'string') out += data.stdout.trim();
    if (data.stderr && data.stderr.trim()) {
      out += (out ? '\n\n' : '') + '[stderr]\n' + data.stderr.trim();
    }
    pendingOutput = out || '(no output)';
  } catch (e) {
    pendingOutput = `Failed to contact server.\n${e}`;
  }
}

// ===== Logo click: keep matrix up until scan finishes
enterScanBtn?.addEventListener('click', async () => {
  // 1) Start overlay + animation + loading pulses
  startMatrixTransition();

  // 2) Run the Python script (awaits completion)
  await runDeviceDiscovery();

  // 3) Final flash and close overlay
  showWord('SAFE', 900);
  setTimeout(endMatrixTransitionAndShowOutput, 800);
});

// ===== Resize matrix if overlay visible
window.addEventListener('resize', () => {
  if (overlay.style.display === 'block') sizeCanvas();
});

// ===== Settings toggle (kept from your original)
function toggle(el) {
  el.textContent = el.textContent === 'On' ? 'Off' : 'On';
}
