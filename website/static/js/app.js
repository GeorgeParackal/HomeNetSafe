// ===== Config
  const API_URL = 'http://127.0.0.1:5000/run-script'; // Flask endpoint

  // ===== Tabs helper
  function switchToDevices(){ document.getElementById('tab-devices').checked = true; }

  // ===== Elements
  const enterScanBtn = document.getElementById('enterScan');
  const overlay = document.getElementById('matrixOverlay');
  const canvas = document.getElementById('matrixCanvas');
  const ctx = canvas.getContext('2d');
  const textEl = document.getElementById('matrixText');
  const scanOutput = document.getElementById('scanOutput');

  let columns = [], drops = [], rafId = null, running = false;
  let pendingOutput = "Waiting for scan...";
  let loadingInterval = null;

  function sizeCanvas(){
    const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
    canvas.width = Math.floor(canvas.clientWidth * dpr);
    canvas.height = Math.floor(canvas.clientHeight * dpr);
    ctx.setTransform(dpr,0,0,dpr,0,0);
    const columnWidth = 16;
    columns = Math.ceil(canvas.clientWidth / columnWidth);
    drops = new Array(columns).fill(0).map(()=> Math.floor(Math.random()*canvas.clientHeight));
  }

  function drawMatrix(){
    ctx.fillStyle = "rgba(0, 0, 0, 0.08)";
    ctx.fillRect(0, 0, canvas.clientWidth, canvas.clientHeight);

    ctx.font = "16px monospace";
    for(let i=0;i<columns;i++){
      const char = String.fromCharCode(0x30A0 + Math.floor(Math.random()*96));
      const x = i*16;
      const y = drops[i]*16;
      ctx.fillStyle = "rgba(8, 247, 111, 0.9)";
      ctx.fillText(char, x, y);
      if (y > canvas.clientHeight && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
    if (running) rafId = requestAnimationFrame(drawMatrix);
  }

  function showWord(word, visibleMs = 1000){
    textEl.textContent = word;
    textEl.classList.add('show');
    setTimeout(()=>textEl.classList.remove('show'), visibleMs);
  }

  // ===== Loading pulse logic
  function startLoadingPulse(){
    stopLoadingPulse();
    // First “Loading …” shortly after intro words
    setTimeout(()=> showWord('Loading ...'), 3000);
    // Then every 10 seconds
    loadingInterval = setInterval(()=> showWord('Loading ...'), 10000);
  }
  function stopLoadingPulse(){
    if (loadingInterval){
      clearInterval(loadingInterval);
      loadingInterval = null;
    }
  }

  function startTransition(){
    overlay.style.display = 'block';
    sizeCanvas();
    running = true;
    drawMatrix();

    // Sequence: HOME -> NET -> SAFE
    setTimeout(()=>showWord('HOME', 900), 600);
    setTimeout(()=>showWord('NET', 900), 1300);
    setTimeout(()=>showWord('SAFE', 900), 2000);

    // Begin periodic loading pulses after the intro
    startLoadingPulse();
  }

  // ===== localStorage helpers for registered devices
  const REG_KEY = 'homenetsafe_registered_devices_v1';
  function loadRegisteredDevices(){
    try{ const raw = localStorage.getItem(REG_KEY); return raw ? JSON.parse(raw) : {}; }catch{return {};}
  }
  function saveRegisteredDevices(obj){ localStorage.setItem(REG_KEY, JSON.stringify(obj)); }
  function isRegistered(mac){ const map = loadRegisteredDevices(); return !!map[mac]; }
  function registerDevice(dev, customName, notes){ 
    const map = loadRegisteredDevices(); 
    map[dev.mac] = { 
      ...dev, 
      customName: customName,
      notes: notes,
      registeredAt: new Date().toISOString() 
    }; 
    saveRegisteredDevices(map); 
  }
  function unregisterDevice(mac){
    const map = loadRegisteredDevices();
    delete map[mac];
    saveRegisteredDevices(map);
  }

  function renderDevices(devices){
    const tbody = document.getElementById('devicesBody');
    const failMsg = document.getElementById('scanFailMsg');
    const tableWrap = document.getElementById('devicesTableWrap');
    if (!devices || !Array.isArray(devices) || devices.length === 0){
      failMsg.style.display = 'block'; tableWrap.style.display = 'none'; tbody.innerHTML = ''; return;
    }
    failMsg.style.display = 'none'; tableWrap.style.display = 'block';
    const regMap = loadRegisteredDevices();
    tbody.innerHTML = devices.map(dev => {
      const reg = !!regMap[dev.mac];
      const statusLabel = reg ? 'Registered' : 'New';
      const statusColor = reg ? '#08f76f' : '#9fc9db';
      const registeredInfo = reg ? regMap[dev.mac] : null;
      return `
        <tr>
          <td style="text-align:center;color:${statusColor};font-weight:700;padding:12px 8px;border-bottom:1px solid var(--line);">${statusLabel}</td>
          <td style="text-align:left;padding:12px 8px;border-bottom:1px solid var(--line);">${registeredInfo?.customName || dev.name || ''}</td>
          <td style="text-align:center;padding:12px 8px;font-family:monospace;border-bottom:1px solid var(--line);">${dev.ip || ''}</td>
          <td style="text-align:center;padding:12px 8px;font-family:monospace;border-bottom:1px solid var(--line);">${dev.mac || ''}</td>
          <td style="text-align:left;padding:12px 8px;border-bottom:1px solid var(--line);">${dev.vendor || ''}</td>
          <td style="text-align:center;padding:12px 8px;border-bottom:1px solid var(--line);">${dev.first_seen || ''}</td>
          <td style="text-align:center;padding:12px 8px;border-bottom:1px solid var(--line);">${dev.last_seen || ''}</td>
          <td style="text-align:center;padding:12px 8px;border-bottom:1px solid var(--line);">
            ${reg ? 
              `<button class="unregBtn" data-mac="${dev.mac}" style="padding:6px 10px;border-radius:8px;border:none;cursor:pointer;background:#666;color:var(--ink);font-weight:700;white-space:nowrap;">Unregister</button>` :
              `<button class="regBtn" data-mac="${dev.mac}" style="padding:6px 10px;border-radius:8px;border:none;cursor:pointer;background:var(--accent);color:#032c33;font-weight:700;white-space:nowrap;">Register</button>`
            }
          </td>
        </tr>
        ${registeredInfo?.notes ? `
        <tr>
          <td colspan="8" style="text-align:left;padding:12px 16px;background:rgba(0,229,255,.05);border-bottom:1px solid var(--line);">
            <div style="display:flex;align-items:center;gap:8px;">
              <strong style="color:var(--accent);">Notes:</strong>
              <span style="color:var(--muted);">${registeredInfo.notes}</span>
            </div>
          </td>
        </tr>
        ` : ''}
      `;
    }).join('');

    // attach handlers for registration buttons
    Array.from(document.getElementsByClassName('regBtn')).forEach(btn => {
      btn.onclick = () => {
        const mac = btn.getAttribute('data-mac');
        const idx = devices.findIndex(d => d.mac === mac);
        if (idx > -1) {
          document.getElementById('regDeviceMac').value = devices[idx].mac;
          document.getElementById('regDeviceName').value = devices[idx].name || '';
          document.getElementById('regDeviceNotes').value = '';
          document.getElementById('registerModal').style.display = 'block';
        }
      };
    });

    // attach handlers for unregister buttons
    Array.from(document.getElementsByClassName('unregBtn')).forEach(btn => {
      btn.onclick = () => {
        const mac = btn.getAttribute('data-mac');
        if (confirm('Are you sure you want to unregister this device?')) {
          unregisterDevice(mac);
          renderDevices(devices);
        }
      };
    });

    // handle registration form submission
    document.getElementById('registerForm').onsubmit = (e) => {
      e.preventDefault();
      const mac = document.getElementById('regDeviceMac').value;
      const customName = document.getElementById('regDeviceName').value;
      const notes = document.getElementById('regDeviceNotes').value;
      const idx = devices.findIndex(d => d.mac === mac);
      if (idx > -1) {
        registerDevice(devices[idx], customName, notes);
        document.getElementById('registerModal').style.display = 'none';
        renderDevices(devices);
      }
    };
  }

  // Auto-scan on load
  window.addEventListener('load', async ()=>{
    // run scan automatically
    const result = await runDeviceDiscovery();
    let devices = [];
    if (result && typeof result === 'string'){
      try { devices = JSON.parse(result); } catch { devices = []; }
    }
    // if no devices, fall back to example data
    if (!devices || !devices.length){
      // example fallback (kept minimal)

      var networkDeviceList = await getNetworkDeviceList();

      console.log(networkDeviceList);

      for (const networkDevice of networkDeviceList) {
        devices.push({ip: networkDevice.ip, mac: networkDevice.mac, vendor: networkDevice.vendor, first_seen: networkDevice.first_seen, last_seen: networkDevice.last_seen, status: "TODO"});
      }

    //   devices = [
    //     { name:'Router', ip:'192.168.1.1', mac:'6C:DD:6C:B1:FF:02', vendor:'NetGear', first_seen:'2025-10-01', last_seen:'2025-10-22', status:'Healthy' },
    //     { name:'Laptop', ip:localDeviceIp, mac:'4E:4C:29:F6:13:C2', vendor:'Dell', first_seen:'2025-09-30', last_seen:'2025-10-22', status:'Healthy' }
    //   ];
    }
    renderDevices(devices);
  });

async function getNetworkDeviceList() {
  const response = await fetch('/get_network_device_list');  // Call Flask route
  const data = await response.json();            // Parse JSON
  return data;                           // Return string
}

  // Add scan button to the header
  const brandDiv = document.querySelector('.brand');
  const scanButton = document.createElement('button');
  scanButton.style.cssText = 'margin-left:16px;padding:8px 16px;border-radius:8px;background:var(--accent);color:#032c33;font-weight:700;border:none;cursor:pointer;';
  scanButton.textContent = 'Scan Network';
  scanButton.onclick = async () => {
    scanButton.disabled = true;
    scanButton.textContent = 'Scanning...';
    const result = await runDeviceDiscovery();
    let devices = [];
    if (result && typeof result === 'string') {
      try { devices = JSON.parse(result); } catch { devices = []; }
    }
    renderDevices(devices);
    scanButton.disabled = false;
    scanButton.textContent = 'Scan Network';
  };
  brandDiv.appendChild(scanButton);

  async function runDeviceDiscovery(){
    // Hit your Flask endpoint that runs "Device Discovery.py"
    try {
      if (scanOutput) scanOutput.textContent = "Running scan...";
      const r = await fetch(API_URL, { method:'GET', mode:'cors', cache:'no-store' });
      if(!r.ok){
        const txt = await r.text().catch(()=> '');
        throw new Error(`HTTP ${r.status} ${r.statusText}${txt ? ' — ' + txt : ''}`);
      }
      const data = await r.json();
      let out = '';
      if (data && typeof data.stdout === 'string') out += data.stdout.trim();
      if (data && data.stderr && data.stderr.trim()) out += (out?'\n\n':'') + '[stderr]\n' + data.stderr.trim();
      // If backend returned structured JSON devices, prefer that
      if (data && data.devices) {
        pendingOutput = JSON.stringify(data.devices);
      } else {
        pendingOutput = out || "(no output)";
      }
    } catch (e) {
      pendingOutput = "Failed to contact server.\n" + e;
    }
    return pendingOutput;
  }

  function endMatrixTransitionAndShowOutput(){
    running = false;
    cancelAnimationFrame(rafId);
    stopLoadingPulse();
    overlay.style.display = 'none';
    switchToScan();
    scanOutput.textContent = pendingOutput;
  }

  // Click the logo: start transition, run Python, then reveal output
  enterScanBtn?.addEventListener('click', async () => {
    startTransition();
    let scanFailed = false;
    let resultText = '';
    let devices = [];
    try {
      await runDeviceDiscovery();
      if (pendingOutput.startsWith('Failed to contact server')) {
        scanFailed = true;
        resultText = 'Scan failed. No devices found.';
      } else {
        // Try to parse output as JSON array of devices, fallback to plain text
        try {
          devices = JSON.parse(pendingOutput);
        } catch {
          resultText = pendingOutput;
        }
      }
    } catch (e) {
      scanFailed = true;
      resultText = 'Scan failed. No devices found.';
    }
    showWord('SAFE', 900);
    setTimeout(() => {
      running = false;
      cancelAnimationFrame(rafId);
      stopLoadingPulse();
      overlay.style.display = 'none';
      switchToDevices();
      // Show/hide device table or error
      const failMsg = document.getElementById('scanFailMsg');
      const tableWrap = document.getElementById('devicesTableWrap');
      const tbody = document.getElementById('devicesBody');
      if (scanFailed || !devices || !Array.isArray(devices) || devices.length === 0) {
        failMsg.style.display = 'block';
        tableWrap.style.display = 'none';
        tbody.innerHTML = '';
      } else {
        failMsg.style.display = 'none';
        tableWrap.style.display = 'block';
        tbody.innerHTML = devices.map(dev => `
          <tr style="text-align:center;">
            <td style="text-align:center;">${dev.name || ''}</td>
            <td style="text-align:center;">${dev.ip || ''}</td>
            <td style="text-align:center;">${dev.mac || ''}</td>
            <td style="text-align:center;">${dev.type || ''}</td>
            <td style="text-align:center;"><span style="color:${dev.status === 'Healthy' ? '#08f76f' : '#9fc9db'}">${dev.status || ''}</span></td>
          </tr>
        `).join('');
      }
    }, 800);
  });

  window.addEventListener('resize', ()=>{ if(overlay.style.display==='block') sizeCanvas(); });

  // tiny toggle button
  function toggle(el){ el.textContent = el.textContent === 'On' ? 'Off' : 'On'; }