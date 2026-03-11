// ============================================================
// ATM Remote — Mobile Web Client Application
// ============================================================

// ─── SVG Icons ─────────────────────────────────────────────────
const Icons = {
  chevronRight: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 3l5 5-5 5"/></svg>',
  arrowLeft: '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 10H5M5 10l5-5M5 10l5 5"/></svg>',
  search: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="7" cy="7" r="4.5"/><path d="M11 11l3.5 3.5"/></svg>',
  tree: '<svg viewBox="0 0 22 22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3H5a2 2 0 00-2 2v3m0 4v3a2 2 0 002 2h3m4 0h3a2 2 0 002-2v-3m0-4V5a2 2 0 00-2-2h-3"/><circle cx="11" cy="11" r="3"/></svg>',
  info: '<svg viewBox="0 0 22 22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><path d="M11 15V11M11 7h.01"/></svg>',
  deploy: '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 3v10M6 9l4 4 4-4M3 15v1a1 1 0 001 1h12a1 1 0 001-1v-1"/></svg>',
  edit: '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2.5a2.121 2.121 0 013 3L6 17l-4 1 1-4L14.5 2.5z"/></svg>',
  lock: '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="9" width="10" height="8" rx="1"/><path d="M7 9V6a3 3 0 016 0v3"/></svg>',
  refresh: '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17 10a7 7 0 01-12.9 3.7M3 10a7 7 0 0112.9-3.7"/><path d="M17 4v4h-4M3 16v-4h4"/></svg>',
  disconnect: '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 4l12 12M8 2h4v4M12 18H8v-4"/></svg>',
};

// ─── Application State ─────────────────────────────────────────
const state = {
  screen: 'auth',       // 'connect' | 'auth' | 'tree' | 'detail' | 'paired' | 'settings'
  prevScreen: null,
  ws: null,
  token: null,
  sessionId: null,
  nodes: [],
  selectedNode: null,
  expandedIds: new Set(),
  searchQuery: '',
  filterKind: null,
  connected: false,
  connecting: false,
  authError: null,
  authLoading: false,
  authLocked: false,
  authLockSeconds: 0,
  editing: false,
  editDraft: null,
  pullRefreshing: false,
  loadingTree: true,
  lastPingTime: 0,
  latencyMs: 0,
  reconnectTimer: null,
  lockoutTimer: null,
  // Cloud relay mode
  relayMode: false,
  roomCode: null,
  relayUrl: null,
  // E2E crypto
  keyPair: null,
  sharedKey: null,
  peerPublicKey: null,
  sendNonce: 0,
  // Persistent pairing
  savedPairing: null,     // { desktopId, token, desktopName, relayUrl, pairedAt, expiresAt, desktopPublicKey }
  pairingMode: false,     // true when using saved pairing (no room code needed)
  desktopOnline: false,   // whether desktop is connected to relay
  waitingForDesktop: false, // true when waiting for desktop to come online
};

// ─── Constants ─────────────────────────────────────────────────
const KIND_COLORS = {
  team: 'var(--kind-team)',
  agent: 'var(--kind-agent)',
  skill: 'var(--kind-skill)',
  pipeline: 'var(--kind-pipeline)',
  context: 'var(--kind-context)',
  setting: 'var(--kind-setting)',
};

const KIND_LABELS = {
  team: 'Teams',
  agent: 'Agents',
  skill: 'Skills',
  pipeline: 'Pipelines',
  context: 'Contexts',
  setting: 'Settings',
};

const SENSITIVE_VAR_TYPES = ['api-key', 'api_key', 'apikey', 'password', 'secret', 'token'];
const RECONNECT_DELAY = 3000;
const PING_INTERVAL = 30000;

// ─── E2E Crypto Helpers ──────────────────────────────────────
function initCrypto() {
  if (typeof nacl === 'undefined') {
    console.warn('tweetnacl not loaded, encryption unavailable');
    return;
  }
  state.keyPair = nacl.box.keyPair();
  state.sendNonce = 0;
}

function deriveSharedKey(peerPublicKeyBase64) {
  if (!state.keyPair) return;
  const peerKey = base64ToUint8(peerPublicKeyBase64);
  state.sharedKey = nacl.box.before(peerKey, state.keyPair.secretKey);
}

function encryptMessage(msg) {
  if (!state.sharedKey) return JSON.stringify(msg);
  if (state.sendNonce >= Number.MAX_SAFE_INTEGER) {
    showToast('Session expired, please reconnect', 'error');
    return null;
  }
  const plaintext = new TextEncoder().encode(JSON.stringify(msg));
  const nonce = makeNonce(state.sendNonce++);
  const ciphertext = nacl.secretbox(plaintext, nonce, state.sharedKey);
  return JSON.stringify({
    type: 'encrypted',
    nonce: uint8ToBase64(nonce),
    ciphertext: uint8ToBase64(ciphertext),
  });
}

function decryptMessage(data) {
  try {
    const parsed = typeof data === 'string' ? JSON.parse(data) : data;
    if (parsed.type !== 'encrypted') return parsed;
    if (!state.sharedKey) return null;
    const nonce = base64ToUint8(parsed.nonce);
    const ciphertext = base64ToUint8(parsed.ciphertext);
    const plaintext = nacl.secretbox.open(ciphertext, nonce, state.sharedKey);
    if (!plaintext) { console.warn('Decryption failed'); return null; }
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch (err) {
    console.warn('Failed to decrypt:', err);
    return null;
  }
}

function makeNonce(counter) {
  const nonce = new Uint8Array(24);
  // Byte 0: role prefix (0x02 = mobile, 0x01 = desktop) to prevent collisions
  nonce[0] = 0x02;
  const view = new DataView(nonce.buffer);
  view.setUint32(16, Math.floor(counter / 0x100000000), false);
  view.setUint32(20, counter >>> 0, false);
  return nonce;
}

function uint8ToBase64(arr) {
  return btoa(String.fromCharCode.apply(null, arr));
}

function base64ToUint8(str) {
  const bin = atob(str);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

function getPublicKeyBase64() {
  if (!state.keyPair) return '';
  return uint8ToBase64(state.keyPair.publicKey);
}

// ─── Pairing Storage (IndexedDB) ─────────────────────────────
function openPairingDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('atm-pairing', 1);
    request.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('pairings')) {
        db.createObjectStore('pairings', { keyPath: 'desktopId' });
      }
    };
    request.onsuccess = (e) => resolve(e.target.result);
    request.onerror = (e) => reject(e.target.error);
  });
}

async function savePairing(pairing) {
  const db = await openPairingDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('pairings', 'readwrite');
    tx.objectStore('pairings').put(pairing);
    tx.oncomplete = () => resolve();
    tx.onerror = (e) => reject(e.target.error);
  });
}

async function getSavedPairing() {
  const db = await openPairingDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('pairings', 'readonly');
    const store = tx.objectStore('pairings');
    const request = store.getAll();
    request.onsuccess = () => {
      const pairings = request.result;
      // Return the first non-expired pairing
      const now = Date.now();
      const valid = pairings.find(p => p.expiresAt > now);
      resolve(valid || null);
    };
    request.onerror = (e) => reject(e.target.error);
  });
}

async function deletePairing(desktopId) {
  const db = await openPairingDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('pairings', 'readwrite');
    tx.objectStore('pairings').delete(desktopId);
    tx.oncomplete = () => resolve();
    tx.onerror = (e) => reject(e.target.error);
  });
}

async function deleteAllPairings() {
  const db = await openPairingDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('pairings', 'readwrite');
    tx.objectStore('pairings').clear();
    tx.oncomplete = () => resolve();
    tx.onerror = (e) => reject(e.target.error);
  });
}

// ─── Toast System ──────────────────────────────────────────────
function showToast(message, type = 'info', duration = 3000) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('removing');
    toast.addEventListener('animationend', () => toast.remove());
  }, duration);
}

// ─── Escape HTML ───────────────────────────────────────────────
function esc(str) {
  if (str == null) return '';
  const d = document.createElement('div');
  d.textContent = String(str);
  return d.innerHTML;
}

// ─── Auth Flow ─────────────────────────────────────────────────
async function authenticate(pin) {
  if (state.authLoading) return;
  state.authLoading = true;
  state.authError = null;
  render();

  try {
    if (state.relayMode) {
      // In relay mode, send PIN via encrypted WebSocket
      sendMessage('auth', { pin });
      // Wait for auth_ok/auth_fail via WebSocket message
      // The handleServerMessage will handle the response
    } else {
      // LAN mode: REST API auth
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin }),
      });
      const data = await res.json();

      if (data.ok) {
        state.token = data.token;
        state.sessionId = data.sessionId;
        state.screen = 'tree';
        state.prevScreen = 'auth';
        state.loadingTree = true;
        state.authError = null;
        state.authLocked = false;
        history.pushState({ screen: 'tree' }, '');
        connectWebSocket();
      } else {
        state.authError = data.error || 'Authentication failed';
        if (res.status === 429) {
          state.authLocked = true;
          const match = data.error && data.error.match(/(\d+)\s*seconds?/);
          if (match) {
            state.authLockSeconds = parseInt(match[1], 10);
            startLockoutTimer();
          }
        }
      }
    }
  } catch (err) {
    state.authError = 'Connection failed. Is the ATM app running?';
  }

  state.authLoading = false;
  render();
}

function startLockoutTimer() {
  clearInterval(state.lockoutTimer);
  state.lockoutTimer = setInterval(() => {
    state.authLockSeconds--;
    if (state.authLockSeconds <= 0) {
      state.authLocked = false;
      clearInterval(state.lockoutTimer);
    }
    render();
  }, 1000);
}

// ─── WebSocket ─────────────────────────────────────────────────
function connectWebSocket() {
  if (state.ws && (state.ws.readyState === WebSocket.OPEN || state.ws.readyState === WebSocket.CONNECTING)) {
    return;
  }

  state.connecting = true;
  clearTimeout(state.reconnectTimer);

  let wsUrl;
  if (state.relayMode) {
    // Cloud relay mode: connect to relay server's /ws endpoint
    wsUrl = state.relayUrl.replace(/\/+$/, '') + '/ws';
  } else {
    // LAN mode: connect to local server
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    wsUrl = `${protocol}//${location.host}/ws?token=${state.token}`;
  }

  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    state.ws = ws;
    state.connected = true;
    state.connecting = false;

    if (state.pairingMode && state.savedPairing) {
      // Reconnect using saved pairing token
      initCrypto();
      ws.send(JSON.stringify({
        type: 'reconnect_paired',
        pairing_token: state.savedPairing.token,
        mobile_public_key: getPublicKeyBase64(),
      }));
    } else if (state.relayMode) {
      // In relay mode, send join_room with our public key
      initCrypto();
      ws.send(JSON.stringify({
        type: 'join_room',
        room_code: state.roomCode,
        mobile_public_key: getPublicKeyBase64(),
      }));
    } else {
      // LAN mode: request full tree immediately
      render();
      sendMessage('get_tree', {});
      startPing();
    }
  };

  ws.onmessage = (e) => {
    try {
      const raw = JSON.parse(e.data);

      // Handle relay protocol messages that can arrive at any time
      if (raw.type === 'peer_online') {
        state.desktopOnline = true;
        state.waitingForDesktop = false;
        // Desktop came online, derive shared key from pairing's desktop public key
        if (state.savedPairing && state.savedPairing.desktopPublicKey) {
          deriveSharedKey(state.savedPairing.desktopPublicKey);
        }
        // Auto-request tree sync
        state.screen = 'tree';
        state.loadingTree = true;
        sendMessage('get_tree', {});
        startPing();
        render();
        showToast('Desktop connected', 'success');
        return;
      }
      if (raw.type === 'peer_offline') {
        state.desktopOnline = false;
        state.waitingForDesktop = true;
        render();
        return;
      }
      if (raw.type === 'pairing_established') {
        // Reconnection via pairing token succeeded, desktop is online
        // The desktop_public_key comes with this message for key derivation
        if (raw.desktop_public_key) {
          deriveSharedKey(raw.desktop_public_key);
        }
        state.desktopOnline = true;
        state.waitingForDesktop = false;
        state.screen = 'tree';
        state.loadingTree = true;
        sendMessage('get_tree', {});
        startPing();
        render();
        showToast('Reconnected via saved pairing', 'success');
        return;
      }

      if (state.relayMode && !state.sharedKey) {
        // Handle relay protocol messages (pre-encryption)
        if (raw.type === 'room_joined') {
          // We got desktop's public key, derive shared secret
          deriveSharedKey(raw.desktop_public_key);
          state.screen = 'auth'; // Show PIN entry
          render();
          showToast('Connected to desktop, enter PIN', 'success');
          startPing();
          return;
        }
        if (raw.type === 'relay_error') {
          state.authError = raw.message || 'Relay error';
          state.connecting = false;
          // Stop auto-reconnect on fatal relay errors (room not found, etc.)
          state.roomCode = null;
          clearTimeout(state.reconnectTimer);
          render();
          return;
        }
        if (raw.type === 'peer_disconnected') {
          showToast('Desktop disconnected', 'error');
          handleDisconnect();
          return;
        }
        return;
      }

      // Handle encrypted messages (relay mode after pairing)
      let msg = raw;
      if (state.relayMode && raw.type === 'encrypted') {
        msg = decryptMessage(raw);
        if (!msg) return;
      }
      // Handle peer_disconnected even after pairing
      if (raw.type === 'peer_disconnected') {
        showToast('Desktop disconnected', 'error');
        handleDisconnect();
        return;
      }

      handleServerMessage(msg);
    } catch (err) {
      console.warn('Failed to parse WebSocket message:', err);
    }
  };

  ws.onerror = () => {
    console.warn('WebSocket error');
  };

  ws.onclose = (e) => {
    state.ws = null;
    state.connected = false;
    state.connecting = false;
    stopPing();
    render();

    // Auto-reconnect if we have credentials
    const shouldReconnect = state.pairingMode
      ? (state.savedPairing && state.screen !== 'connect')
      : (state.relayMode
        ? (state.roomCode && state.screen !== 'connect')
        : (state.token && state.screen !== 'auth'));

    if (shouldReconnect) {
      state.reconnectTimer = setTimeout(() => {
        connectWebSocket();
      }, RECONNECT_DELAY);
    }
  };
}

let pingIntervalId = null;

function startPing() {
  stopPing();
  pingIntervalId = setInterval(() => {
    state.lastPingTime = Date.now();
    sendMessage('ping', {});
  }, PING_INTERVAL);
}

function stopPing() {
  if (pingIntervalId) {
    clearInterval(pingIntervalId);
    pingIntervalId = null;
  }
}

function sendMessage(type, payload) {
  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    const msg = {
      type,
      id: crypto.randomUUID(),
      payload,
      timestamp: Date.now(),
    };

    if (state.relayMode && state.sharedKey) {
      const encrypted = encryptMessage(msg);
      if (encrypted === null) return;
      state.ws.send(encrypted);
    } else {
      state.ws.send(JSON.stringify(msg));
    }
  }
}

// ─── Message Handling ──────────────────────────────────────────
function handleServerMessage(msg) {
  switch (msg.type) {
    case 'full_sync': {
      const raw = msg.payload.nodes || [];
      state.nodes = Array.isArray(raw) ? raw : Object.values(raw);
      if (msg.payload.metadata) {
        state.metadata = msg.payload.metadata;
      }
      state.loadingTree = false;
      break;
    }

    case 'node_updated': {
      const idx = state.nodes.findIndex(n => n.id === msg.payload.node.id);
      if (idx >= 0) {
        state.nodes[idx] = msg.payload.node;
      }
      // Update selected node if viewing it
      if (state.selectedNode && state.selectedNode.id === msg.payload.node.id) {
        state.selectedNode = msg.payload.node;
      }
      break;
    }

    case 'node_added':
      state.nodes.push(msg.payload.node);
      break;

    case 'node_removed':
      state.nodes = state.nodes.filter(n => n.id !== msg.payload.id);
      if (state.selectedNode && state.selectedNode.id === msg.payload.id) {
        state.selectedNode = null;
        state.screen = 'tree';
      }
      break;

    case 'pong':
      if (state.lastPingTime) {
        state.latencyMs = Date.now() - state.lastPingTime;
      }
      break;

    case 'error':
      showToast(msg.payload.message || 'Server error', 'error');
      break;

    case 'auth_ok':
      if (state.relayMode) {
        state.sessionId = msg.payload.sessionId;
        state.screen = 'tree';
        state.prevScreen = 'auth';
        state.loadingTree = true;
        state.authError = null;
        history.pushState({ screen: 'tree' }, '');
        sendMessage('get_tree', {});
      }
      break;

    case 'auth_fail':
      if (state.relayMode) {
        state.authError = msg.payload.reason || 'Authentication failed';
      }
      break;

    case 'pairing_issued': {
      // Desktop issued a pairing token after successful auth
      const { pairing_token, desktop_device_id, desktop_name, expires_at } = msg.payload;
      if (pairing_token) {
        const pairing = {
          desktopId: desktop_device_id,
          token: pairing_token,
          desktopName: desktop_name || 'Desktop',
          relayUrl: state.relayUrl || 'wss://atm-relay.datafying.tech',
          pairedAt: Date.now(),
          expiresAt: expires_at || (Date.now() + 90 * 24 * 60 * 60 * 1000),
          desktopPublicKey: state.peerPublicKey || '',
        };
        state.savedPairing = pairing;
        state.pairingMode = true;
        savePairing(pairing).catch(err => console.warn('Failed to save pairing:', err));
        showToast('Device paired! Will auto-connect next time.', 'success', 5000);
      }
      break;
    }

    case 'pairing_revoked': {
      // Desktop revoked our pairing
      showToast('Pairing revoked by desktop', 'error');
      deleteAllPairings().catch(() => {});
      state.savedPairing = null;
      state.pairingMode = false;
      handleDisconnect();
      break;
    }

    default:
      break;
  }

  render();
}

// ─── Tree Building ─────────────────────────────────────────────
function buildTree(nodes) {
  const map = new Map(nodes.map(n => [n.id, { ...n, children: [] }]));
  const roots = [];
  for (const node of map.values()) {
    if (node.parentId && map.has(node.parentId)) {
      map.get(node.parentId).children.push(node);
    } else {
      roots.push(node);
    }
  }
  // Sort children by kind then name
  const sortChildren = (arr) => {
    arr.sort((a, b) => {
      const kindOrder = ['team', 'agent', 'skill', 'pipeline', 'context', 'setting'];
      const ai = kindOrder.indexOf(a.kind) ?? 99;
      const bi = kindOrder.indexOf(b.kind) ?? 99;
      if (ai !== bi) return ai - bi;
      return (a.name || '').localeCompare(b.name || '');
    });
    arr.forEach(n => sortChildren(n.children));
  };
  sortChildren(roots);
  return roots;
}

// ─── Filtering ─────────────────────────────────────────────────
function getFilteredNodes() {
  let filtered = state.nodes;

  if (state.filterKind) {
    filtered = filtered.filter(n => n.kind === state.filterKind);
  }

  if (state.searchQuery.trim()) {
    const q = state.searchQuery.trim().toLowerCase();
    filtered = filtered.filter(n => {
      const nameMatch = (n.name || '').toLowerCase().includes(q);
      const tagMatch = (n.tags || []).some(t => t.toLowerCase().includes(q));
      const kindMatch = (n.kind || '').toLowerCase().includes(q);
      return nameMatch || tagMatch || kindMatch;
    });
  }

  return filtered;
}

function getKindCounts() {
  const counts = {};
  for (const n of state.nodes) {
    counts[n.kind] = (counts[n.kind] || 0) + 1;
  }
  return counts;
}

// ─── Rendering ─────────────────────────────────────────────────
function render() {
  const app = document.getElementById('app');
  if (!app) return;

  const transition = getTransitionClass();

  switch (state.screen) {
    case 'connect':
      app.innerHTML = renderConnect();
      break;
    case 'auth':
      app.innerHTML = renderAuth();
      break;
    case 'tree':
      app.innerHTML = renderTree();
      break;
    case 'detail':
      app.innerHTML = renderDetail();
      break;
    case 'paired':
      app.innerHTML = renderPairedConnect();
      break;
    case 'settings':
      app.innerHTML = renderMobileSettings();
      break;
  }

  if (transition) {
    app.firstElementChild?.classList.add(transition);
  }

  attachEventListeners();
  state.prevScreen = state.screen;
}

function getTransitionClass() {
  if (!state.prevScreen || state.prevScreen === state.screen) return null;
  if (state.prevScreen === 'tree' && state.screen === 'detail') return 'slide-in-right';
  if (state.prevScreen === 'detail' && state.screen === 'tree') return 'slide-in-left';
  if (state.prevScreen === 'auth' && state.screen === 'tree') return 'fade-in';
  return 'fade-in';
}

// ─── Auth Screen ───────────────────────────────────────────────
function renderAuth() {
  if (state.authLocked) {
    return `
      <div class="auth-screen">
        <div class="auth-logo">ATM</div>
        <h1 class="auth-title">ATM Remote</h1>
        <div class="auth-lockout">
          <div class="lockout-icon">${Icons.lock}</div>
          <div class="lockout-title">Access Locked</div>
          <div class="lockout-msg">Too many failed attempts.<br>Try again in <strong>${state.authLockSeconds}</strong> seconds.</div>
        </div>
      </div>
    `;
  }

  // In relay mode, block PIN entry until encrypted tunnel is established
  if (state.relayMode && !state.sharedKey) {
    return `
      <div class="auth-screen">
        <div class="auth-logo">ATM</div>
        <h1 class="auth-title">ATM Remote</h1>
        <p class="auth-subtitle">Establishing secure connection...</p>
        <div style="display:flex;justify-content:center;padding:32px 0">
          <span class="auth-loading"></span>
        </div>
        ${state.authError ? `<div class="auth-error">${esc(state.authError)}</div>` : ''}
      </div>
    `;
  }

  return `
    <div class="auth-screen">
      <div class="auth-logo">ATM</div>
      <h1 class="auth-title">ATM Remote</h1>
      <p class="auth-subtitle">Enter the 6-digit PIN shown on your desktop</p>
      <div class="pin-container" id="pin-container">
        <input class="pin-input${state.authError ? ' error' : ''}" type="tel" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="one-time-code" data-pin="0" aria-label="PIN digit 1">
        <input class="pin-input${state.authError ? ' error' : ''}" type="tel" maxlength="1" inputmode="numeric" pattern="[0-9]" data-pin="1" aria-label="PIN digit 2">
        <input class="pin-input${state.authError ? ' error' : ''}" type="tel" maxlength="1" inputmode="numeric" pattern="[0-9]" data-pin="2" aria-label="PIN digit 3">
        <input class="pin-input${state.authError ? ' error' : ''}" type="tel" maxlength="1" inputmode="numeric" pattern="[0-9]" data-pin="3" aria-label="PIN digit 4">
        <input class="pin-input${state.authError ? ' error' : ''}" type="tel" maxlength="1" inputmode="numeric" pattern="[0-9]" data-pin="4" aria-label="PIN digit 5">
        <input class="pin-input${state.authError ? ' error' : ''}" type="tel" maxlength="1" inputmode="numeric" pattern="[0-9]" data-pin="5" aria-label="PIN digit 6">
      </div>
      <button class="auth-btn" id="auth-submit" ${state.authLoading ? 'disabled' : ''}>
        ${state.authLoading ? '<span class="auth-loading"></span>' : 'Connect'}
      </button>
      ${state.authError ? `<div class="auth-error">${esc(state.authError)}</div>` : ''}
    </div>
  `;
}

// ─── Paired Connect Screen ──────────────────────────────────────
function renderPairedConnect() {
  return `
    <div class="auth-screen">
      <div class="auth-logo">ATM</div>
      <h1 class="auth-title">ATM Remote</h1>
      ${state.waitingForDesktop ? `
        <div style="text-align:center;padding:24px 0">
          <div style="font-size:14px;color:var(--text);margin-bottom:8px">
            ${state.connecting ? 'Connecting...' : 'Desktop is offline'}
          </div>
          <div style="font-size:12px;color:var(--text-dim);margin-bottom:24px">
            ${state.savedPairing ? esc(state.savedPairing.desktopName || 'Desktop') : 'Desktop'}
          </div>
          ${!state.connecting ? `
            <button class="auth-btn" id="retry-paired-btn" style="margin-bottom:12px">
              Retry Connection
            </button>
          ` : `
            <div style="display:flex;justify-content:center;padding:16px 0">
              <span class="auth-loading"></span>
            </div>
          `}
        </div>
      ` : `
        <div style="text-align:center;padding:24px 0">
          <div style="display:flex;justify-content:center;padding:16px 0">
            <span class="auth-loading"></span>
          </div>
          <div style="font-size:14px;color:var(--text);margin-bottom:4px">
            Connecting to ${esc(state.savedPairing ? state.savedPairing.desktopName || 'Desktop' : 'Desktop')}...
          </div>
          <div style="font-size:12px;color:var(--text-dim)">
            Using saved pairing
          </div>
        </div>
      `}
      ${state.authError ? '<div class="auth-error">' + esc(state.authError) + '</div>' : ''}
      <div style="margin-top:24px;text-align:center">
        <button class="link-btn" id="unpair-btn" style="background:none;border:none;color:var(--text-dim);font-size:12px;cursor:pointer;text-decoration:underline;">
          Unpair and connect manually
        </button>
      </div>
    </div>
  `;
}

// ─── Connect Screen (Relay Mode) ────────────────────────────────
function renderConnect() {
  return `
    <div class="auth-screen">
      <div class="auth-logo">ATM</div>
      <h1 class="auth-title">ATM Remote</h1>
      <p class="auth-subtitle">Enter the room code shown on your desktop</p>
      <div style="margin-bottom:16px">
        <input class="room-code-input" id="room-code-input" type="search"
          placeholder="ATM-XXXXXX" maxlength="10" autocomplete="off"
          inputmode="search" autocorrect="off" spellcheck="false" autocapitalize="characters"
          style="font-size:24px;text-align:center;letter-spacing:4px;padding:12px 16px;width:100%;box-sizing:border-box;background:var(--bg-card);border:2px solid var(--border);border-radius:12px;color:var(--text);font-family:monospace;-webkit-appearance:none;appearance:none;"
          value="${esc(state.roomCode || '')}">
      </div>
      <button class="auth-btn" id="connect-relay-btn" ${state.connecting ? 'disabled' : ''}>
        ${state.connecting ? '<span class="auth-loading"></span>' : 'Connect'}
      </button>
      ${state.authError ? '<div class="auth-error">' + esc(state.authError) + '</div>' : ''}
      <div style="margin-top:24px;text-align:center">
        <button class="link-btn" id="switch-to-lan" style="background:none;border:none;color:var(--text-dim);font-size:12px;cursor:pointer;text-decoration:underline;">
          Connect via LAN instead
        </button>
      </div>
    </div>
  `;
}

function handleConnectRelay() {
  const input = document.getElementById('room-code-input');
  if (!input) return;
  let code = input.value.trim();

  // Normalize: add ATM- prefix if missing
  if (!code.startsWith('ATM-')) {
    code = 'ATM-' + code;
  }

  if (code.length < 7) {
    state.authError = 'Room code too short';
    render();
    return;
  }

  state.relayMode = true;
  state.roomCode = code;
  state.relayUrl = state.relayUrl || 'wss://atm-relay.datafying.tech';

  if (!state.relayUrl.startsWith('wss://')) {
    state.authError = 'Invalid relay URL: only secure (wss://) connections are allowed';
    render();
    return;
  }

  state.authError = null;

  connectWebSocket();
  render();
}

// ─── Tree Screen ───────────────────────────────────────────────
function renderTree() {
  const filtered = getFilteredNodes();
  const tree = state.filterKind || state.searchQuery.trim()
    ? filtered.map(n => ({ ...n, children: [] }))
    : buildTree(filtered);
  const counts = getKindCounts();

  return `
    <div class="tree-screen">
      ${renderStatusBar()}

      <div class="search-bar">
        <div class="search-input-wrap">
          ${Icons.search}
          <input class="search-input" id="search-input" type="search"
            placeholder="Search nodes..." value="${esc(state.searchQuery)}"
            autocomplete="off" autocorrect="off" spellcheck="false">
        </div>
      </div>

      <div class="filter-chips" id="filter-chips">
        <button class="filter-chip${!state.filterKind ? ' active' : ''}" data-filter="">All</button>
        ${Object.entries(KIND_LABELS).map(([kind, label]) => `
          <button class="filter-chip${state.filterKind === kind ? ' active' : ''}" data-filter="${kind}">
            <span class="chip-dot" style="background:${KIND_COLORS[kind]}"></span>
            ${label}${counts[kind] ? ` (${counts[kind]})` : ''}
          </button>
        `).join('')}
      </div>

      <div class="tree-content" id="tree-content">
        <div class="pull-indicator${state.pullRefreshing ? ' active' : ''}" id="pull-indicator">
          <span class="pull-spinner"></span> Refreshing...
        </div>

        ${state.loadingTree ? renderSkeleton() :
          tree.length === 0 ? renderEmptyState() :
          `<div class="tree-list" id="tree-list">${tree.map(n => renderTreeNode(n, 0)).join('')}</div>`
        }
      </div>

      ${renderStatsBar(counts)}
      ${renderBottomNav('tree')}
    </div>
  `;
}

function renderStatusBar() {
  const statusClass = state.connected ? 'connected' : 'disconnected';
  const statusText = state.connected ? 'Connected' : (state.connecting ? 'Connecting...' : 'Reconnecting...');
  const latency = state.connected && state.latencyMs > 0 ? `${state.latencyMs}ms` : '';

  return `
    <div class="status-bar">
      <span class="status-dot ${statusClass}"></span>
      <span class="title">ATM Remote</span>
      ${latency ? `<span style="font-size:0.6875rem;color:var(--text-dim)">${latency}</span>` : ''}
      ${state.sessionId ? `<span class="session-badge">${esc(state.sessionId.slice(0, 8))}</span>` : ''}
    </div>
  `;
}

function renderTreeNode(node, depth) {
  const hasChildren = node.children && node.children.length > 0;
  const isExpanded = state.expandedIds.has(node.id);
  const kind = (node.kind || 'agent').toLowerCase();
  const tags = (node.tags || []).slice(0, 3);

  let childrenHtml = '';
  if (hasChildren) {
    childrenHtml = `
      <div class="tree-children${isExpanded ? '' : ' collapsed'}" style="max-height:${isExpanded ? (node.children.length * 200) + 'px' : '0'}">
        ${node.children.map(c => renderTreeNode(c, depth + 1)).join('')}
      </div>
    `;
  }

  return `
    <div class="tree-node" data-node-id="${esc(node.id)}">
      <div class="tree-node-row kind-${kind}" data-node-id="${esc(node.id)}" style="padding-left:${depth * 16 + 8}px">
        <span class="tree-chevron${hasChildren ? (isExpanded ? ' expanded' : '') : ' empty'}"
              data-toggle="${esc(node.id)}" role="button" tabindex="0" aria-label="${hasChildren ? (isExpanded ? 'Collapse' : 'Expand') : ''}">
          ${Icons.chevronRight}
        </span>
        <div class="tree-node-info" data-select="${esc(node.id)}">
          <span class="tree-node-name">${esc(node.name || 'Unnamed')}</span>
          <div class="tree-node-meta">
            <span class="kind-badge ${kind}">${esc(kind)}</span>
            ${tags.map(t => `<span class="tag-chip">${esc(t)}</span>`).join('')}
          </div>
        </div>
      </div>
      ${childrenHtml}
    </div>
  `;
}

function renderSkeleton() {
  const rows = Array.from({ length: 8 }, (_, i) => `
    <div class="skeleton-row">
      <div class="skeleton skeleton-circle"></div>
      <div class="skeleton-lines">
        <div class="skeleton skeleton-line w${i % 2 === 0 ? '60' : '80'}"></div>
        <div class="skeleton skeleton-line w40"></div>
      </div>
    </div>
  `).join('');
  return `<div class="tree-list">${rows}</div>`;
}

function renderEmptyState() {
  if (state.searchQuery || state.filterKind) {
    return `
      <div class="empty-state">
        <div class="empty-state-icon">${Icons.search}</div>
        <div class="empty-state-title">No results</div>
        <div class="empty-state-msg">Try adjusting your search or filter</div>
      </div>
    `;
  }
  return `
    <div class="empty-state">
      <div class="empty-state-icon">${Icons.tree}</div>
      <div class="empty-state-title">No nodes yet</div>
      <div class="empty-state-msg">Your agent team tree is empty</div>
    </div>
  `;
}

function renderStatsBar(counts) {
  const entries = Object.entries(counts);
  if (entries.length === 0) return '';
  return `
    <div class="stats-bar">
      <span class="stat-item"><span class="stat-count">${state.nodes.length}</span> total</span>
      ${entries.map(([kind, count]) => `
        <span class="stat-item">
          <span class="stat-dot" style="background:${KIND_COLORS[kind] || 'var(--text-dim)'}"></span>
          <span class="stat-count">${count}</span> ${kind}
        </span>
      `).join('')}
    </div>
  `;
}

function renderBottomNav(active) {
  return `
    <nav class="bottom-nav">
      <button class="bottom-nav-item${active === 'tree' ? ' active' : ''}" data-nav="tree">
        ${Icons.tree}
        <span>Tree</span>
      </button>
      <button class="bottom-nav-item" data-nav="refresh" aria-label="Refresh tree">
        ${Icons.refresh}
        <span>Refresh</span>
      </button>
      <button class="bottom-nav-item${active === 'settings' ? ' active' : ''}" data-nav="settings">
        ${Icons.info}
        <span>Settings</span>
      </button>
      <button class="bottom-nav-item" data-nav="disconnect" aria-label="Disconnect">
        ${Icons.disconnect}
        <span>Disconnect</span>
      </button>
    </nav>
  `;
}

// ─── Settings Screen ────────────────────────────────────────────
function renderMobileSettings() {
  const pairing = state.savedPairing;
  return `
    <div class="tree-screen">
      ${renderStatusBar()}
      <div class="detail-content" style="padding:16px">
        <div class="detail-card">
          <div class="detail-card-header">
            <span class="detail-card-title">Connection</span>
          </div>
          <div class="detail-card-body">
            <div class="info-row">
              <span class="info-label">Status</span>
              <span class="info-value">${state.connected ? 'Connected' : 'Disconnected'}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Mode</span>
              <span class="info-value">${state.pairingMode ? 'Persistent Pairing' : (state.relayMode ? 'Cloud Relay' : 'LAN')}</span>
            </div>
            ${state.latencyMs > 0 ? `
              <div class="info-row">
                <span class="info-label">Latency</span>
                <span class="info-value">${state.latencyMs}ms</span>
              </div>
            ` : ''}
          </div>
        </div>
        ${pairing ? `
          <div class="detail-card">
            <div class="detail-card-header">
              <span class="detail-card-title">Paired Desktop</span>
            </div>
            <div class="detail-card-body">
              <div class="info-row">
                <span class="info-label">Name</span>
                <span class="info-value">${esc(pairing.desktopName || 'Desktop')}</span>
              </div>
              <div class="info-row">
                <span class="info-label">Paired</span>
                <span class="info-value">${new Date(pairing.pairedAt).toLocaleDateString()}</span>
              </div>
              <div class="info-row">
                <span class="info-label">Expires</span>
                <span class="info-value">${new Date(pairing.expiresAt).toLocaleDateString()}</span>
              </div>
            </div>
          </div>
          <button class="action-btn secondary" id="unpair-settings-btn" style="width:100%;margin-top:12px">
            Unpair Device
          </button>
        ` : ''}
      </div>
      ${renderBottomNav('settings')}
    </div>
  `;
}

// ─── Detail Screen ─────────────────────────────────────────────
function renderDetail() {
  const node = state.selectedNode;
  if (!node) {
    state.screen = 'tree';
    return renderTree();
  }

  const kind = (node.kind || 'agent').toLowerCase();

  if (state.editing) {
    return renderEditScreen(node, kind);
  }

  return `
    <div class="detail-screen">
      <div class="detail-header">
        <button class="back-btn" id="back-btn" aria-label="Back">${Icons.arrowLeft}</button>
        <div class="detail-header-info">
          <div class="detail-header-name">${esc(node.name || 'Unnamed')}</div>
          <span class="kind-badge ${kind}">${esc(kind)}</span>
        </div>
      </div>

      <div class="detail-content">
        ${renderDetailInfo(node, kind)}
        ${renderDetailPrompt(node)}
        ${renderDetailVariables(node)}
        ${renderDetailTags(node)}
        ${renderDetailSkills(node)}
        ${renderDetailPipeline(node, kind)}
        ${renderDetailActions(node, kind)}
      </div>
    </div>
  `;
}

function renderDetailInfo(node, kind) {
  const rows = [
    { label: 'ID', value: node.id },
    { label: 'Kind', value: kind },
  ];
  if (node.team) rows.push({ label: 'Team', value: node.team });
  if (node.parentId) rows.push({ label: 'Parent ID', value: node.parentId });

  return `
    <div class="detail-card">
      <div class="detail-card-header">
        <span class="detail-card-title">Info</span>
      </div>
      <div class="detail-card-body">
        ${rows.map(r => `
          <div class="info-row">
            <span class="info-label">${esc(r.label)}</span>
            <span class="info-value">${esc(r.value)}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function renderDetailPrompt(node) {
  if (!node.prompt && !node.body) return '';
  const text = node.prompt || node.body || '';
  if (!text.trim()) return '';

  return `
    <div class="detail-card">
      <div class="detail-card-header">
        <span class="detail-card-title">Prompt</span>
      </div>
      <div class="detail-card-body">
        <div class="prompt-body" id="prompt-body">${esc(text)}</div>
      </div>
      <button class="expand-btn" id="expand-prompt">Show more</button>
    </div>
  `;
}

function renderDetailVariables(node) {
  const vars = node.variables || node.vars || [];
  if (!Array.isArray(vars) || vars.length === 0) return '';

  return `
    <div class="detail-card">
      <div class="detail-card-header">
        <span class="detail-card-title">Variables (${vars.length})</span>
      </div>
      <div class="detail-card-body">
        ${vars.map(v => {
          const isSensitive = SENSITIVE_VAR_TYPES.some(t =>
            (v.type || '').toLowerCase().includes(t) ||
            (v.name || '').toLowerCase().includes(t)
          );
          const displayValue = isSensitive
            ? redactValue(v.value || '')
            : (v.value || '');
          return `
            <div class="info-row">
              <span class="info-label">${esc(v.name || v.key || 'unnamed')}</span>
              <span class="info-value${isSensitive ? ' redacted' : ''}">${esc(displayValue)}</span>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;
}

function redactValue(value) {
  if (!value || value.length <= 4) return '****';
  return '****' + value.slice(-4);
}

function renderDetailTags(node) {
  const tags = node.tags || [];
  if (tags.length === 0) return '';

  return `
    <div class="detail-card">
      <div class="detail-card-header">
        <span class="detail-card-title">Tags (${tags.length})</span>
      </div>
      <div class="detail-card-body">
        <div class="tags-wrap">
          ${tags.map(t => `<span class="detail-tag">${esc(t)}</span>`).join('')}
        </div>
      </div>
    </div>
  `;
}

function renderDetailSkills(node) {
  const skills = node.skills || node.assignedSkills || [];
  if (!Array.isArray(skills) || skills.length === 0) return '';

  return `
    <div class="detail-card">
      <div class="detail-card-header">
        <span class="detail-card-title">Assigned Skills (${skills.length})</span>
      </div>
      <div class="detail-card-body">
        ${skills.map(s => {
          const name = typeof s === 'string' ? s : (s.name || s.id || 'unnamed');
          return `
            <div class="skill-list-item">
              <span class="skill-dot"></span>
              <span class="skill-name">${esc(name)}</span>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;
}

function renderDetailPipeline(node, kind) {
  if (kind !== 'pipeline') return '';
  const steps = node.steps || node.pipelineSteps || [];
  if (!Array.isArray(steps) || steps.length === 0) return '';

  return `
    <div class="detail-card">
      <div class="detail-card-header">
        <span class="detail-card-title">Pipeline Steps (${steps.length})</span>
      </div>
      <div class="detail-card-body">
        ${steps.map((s, i) => {
          const name = typeof s === 'string' ? s : (s.name || s.action || `Step ${i + 1}`);
          const detail = typeof s === 'object' ? (s.description || s.type || '') : '';
          return `
            <div class="pipeline-step">
              <span class="step-index">${i + 1}</span>
              <div class="step-info">
                <span class="step-name">${esc(name)}</span>
                ${detail ? `<span class="step-detail">${esc(detail)}</span>` : ''}
              </div>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;
}

function renderDetailActions(node, kind) {
  const buttons = [];

  if (kind === 'pipeline') {
    buttons.push(`<button class="action-btn primary" id="deploy-btn">${Icons.deploy} Deploy</button>`);
  }

  buttons.push(`<button class="action-btn secondary" id="edit-btn">${Icons.edit} Edit</button>`);

  return `<div class="action-btns">${buttons.join('')}</div>`;
}

// ─── Edit Screen ───────────────────────────────────────────────
function renderEditScreen(node, kind) {
  const draft = state.editDraft || {
    name: node.name || '',
    prompt: node.prompt || node.body || '',
    tags: (node.tags || []).join(', '),
  };

  return `
    <div class="detail-screen">
      <div class="detail-header">
        <button class="back-btn" id="cancel-edit-btn" aria-label="Cancel">${Icons.arrowLeft}</button>
        <div class="detail-header-info">
          <div class="detail-header-name">Edit ${esc(node.name || 'Unnamed')}</div>
          <span class="kind-badge ${kind}">${esc(kind)}</span>
        </div>
      </div>

      <div class="detail-content">
        <div class="detail-card">
          <div class="detail-card-body">
            <div class="edit-field">
              <label class="edit-label" for="edit-name">Name</label>
              <input class="edit-input" id="edit-name" type="text" value="${esc(draft.name)}">
            </div>
            <div class="edit-field">
              <label class="edit-label" for="edit-prompt">Prompt / Body</label>
              <textarea class="edit-input edit-textarea" id="edit-prompt">${esc(draft.prompt)}</textarea>
            </div>
            <div class="edit-field">
              <label class="edit-label" for="edit-tags">Tags (comma separated)</label>
              <input class="edit-input" id="edit-tags" type="text" value="${esc(draft.tags)}">
            </div>
          </div>
        </div>

        <div class="action-btns">
          <button class="action-btn secondary" id="cancel-edit-btn2">Cancel</button>
          <button class="action-btn primary" id="save-edit-btn">Save Changes</button>
        </div>
      </div>
    </div>
  `;
}

// ─── Event Listeners ───────────────────────────────────────────
function attachEventListeners() {
  // --- Connect Screen (Relay) ---
  if (state.screen === 'connect') {
    const input = document.getElementById('room-code-input');
    const btn = document.getElementById('connect-relay-btn');
    const lanBtn = document.getElementById('switch-to-lan');

    if (input) {
      input.focus();
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleConnectRelay();
      });
    }
    if (btn) btn.addEventListener('click', handleConnectRelay);
    if (lanBtn) {
      lanBtn.addEventListener('click', () => {
        state.relayMode = false;
        state.screen = 'auth';
        render();
      });
    }
  }

  // --- Auth Screen ---
  if (state.screen === 'auth') {
    attachPinListeners();
    const submitBtn = document.getElementById('auth-submit');
    if (submitBtn) {
      submitBtn.addEventListener('click', handleAuthSubmit);
    }
  }

  // --- Paired Screen ---
  if (state.screen === 'paired') {
    const retryBtn = document.getElementById('retry-paired-btn');
    if (retryBtn) retryBtn.addEventListener('click', () => connectWebSocket());
    const unpairBtn = document.getElementById('unpair-btn');
    if (unpairBtn) unpairBtn.addEventListener('click', handleUnpair);
  }

  // --- Settings Screen ---
  if (state.screen === 'settings') {
    const unpairBtn = document.getElementById('unpair-settings-btn');
    if (unpairBtn) unpairBtn.addEventListener('click', handleUnpair);
    attachBottomNavListeners();
  }

  // --- Tree Screen ---
  if (state.screen === 'tree') {
    attachSearchListeners();
    attachFilterListeners();
    attachTreeListeners();
    attachPullToRefresh();
    attachBottomNavListeners();
  }

  // --- Detail Screen ---
  if (state.screen === 'detail') {
    const backBtn = document.getElementById('back-btn');
    if (backBtn) {
      backBtn.addEventListener('click', () => {
        state.screen = 'tree';
        state.editing = false;
        state.editDraft = null;
        render();
      });
    }

    const expandBtn = document.getElementById('expand-prompt');
    if (expandBtn) {
      expandBtn.addEventListener('click', () => {
        const body = document.getElementById('prompt-body');
        if (body) {
          body.classList.toggle('expanded');
          expandBtn.textContent = body.classList.contains('expanded') ? 'Show less' : 'Show more';
        }
      });
    }

    const deployBtn = document.getElementById('deploy-btn');
    if (deployBtn) {
      deployBtn.addEventListener('click', handleDeploy);
    }

    const editBtn = document.getElementById('edit-btn');
    if (editBtn) {
      editBtn.addEventListener('click', () => {
        state.editing = true;
        state.editDraft = {
          name: state.selectedNode.name || '',
          prompt: state.selectedNode.prompt || state.selectedNode.body || '',
          tags: (state.selectedNode.tags || []).join(', '),
        };
        render();
      });
    }

    // Edit mode buttons
    const cancelEditBtn = document.getElementById('cancel-edit-btn');
    const cancelEditBtn2 = document.getElementById('cancel-edit-btn2');
    [cancelEditBtn, cancelEditBtn2].forEach(btn => {
      if (btn) {
        btn.addEventListener('click', () => {
          state.editing = false;
          state.editDraft = null;
          render();
        });
      }
    });

    const saveEditBtn = document.getElementById('save-edit-btn');
    if (saveEditBtn) {
      saveEditBtn.addEventListener('click', handleSaveEdit);
    }
  }
}

// ─── PIN Input ─────────────────────────────────────────────────
function attachPinListeners() {
  const inputs = document.querySelectorAll('.pin-input');
  if (inputs.length === 0) return;

  // Focus first empty input
  requestAnimationFrame(() => {
    const firstEmpty = Array.from(inputs).find(i => !i.value);
    if (firstEmpty) firstEmpty.focus();
    else inputs[0].focus();
  });

  inputs.forEach((input, idx) => {
    input.addEventListener('input', (e) => {
      const val = e.target.value.replace(/\D/g, '');
      e.target.value = val.slice(0, 1);

      // Clear error state
      if (state.authError) {
        state.authError = null;
        inputs.forEach(i => i.classList.remove('error'));
      }

      // Auto-advance
      if (val && idx < inputs.length - 1) {
        inputs[idx + 1].focus();
      }

      // Auto-submit when all filled
      const allFilled = Array.from(inputs).every(i => i.value.length === 1);
      if (allFilled) {
        handleAuthSubmit();
      }
    });

    input.addEventListener('keydown', (e) => {
      // Handle backspace to go to previous
      if (e.key === 'Backspace' && !e.target.value && idx > 0) {
        inputs[idx - 1].focus();
        inputs[idx - 1].value = '';
      }
      // Handle Enter
      if (e.key === 'Enter') {
        handleAuthSubmit();
      }
    });

    // Handle paste
    input.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasted = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '');
      if (pasted.length > 0) {
        for (let i = 0; i < Math.min(pasted.length, inputs.length); i++) {
          inputs[i].value = pasted[i];
        }
        // Focus next empty or last
        const nextEmpty = Array.from(inputs).findIndex(i => !i.value);
        if (nextEmpty >= 0) {
          inputs[nextEmpty].focus();
        } else {
          inputs[inputs.length - 1].focus();
          // Auto-submit if all filled
          handleAuthSubmit();
        }
      }
    });
  });
}

function handleAuthSubmit() {
  const inputs = document.querySelectorAll('.pin-input');
  const pin = Array.from(inputs).map(i => i.value).join('');
  if (pin.length === 6 && /^\d{6}$/.test(pin)) {
    authenticate(pin);
  }
}

// ─── Search ────────────────────────────────────────────────────
function attachSearchListeners() {
  const searchInput = document.getElementById('search-input');
  if (!searchInput) return;

  let debounce = null;
  searchInput.addEventListener('input', (e) => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      state.searchQuery = e.target.value;
      // Re-render tree content only
      const content = document.getElementById('tree-content');
      if (content) {
        const filtered = getFilteredNodes();
        const tree = state.filterKind || state.searchQuery.trim()
          ? filtered.map(n => ({ ...n, children: [] }))
          : buildTree(filtered);
        const treeList = document.getElementById('tree-list');
        if (treeList) {
          treeList.innerHTML = tree.length === 0
            ? renderEmptyState()
            : tree.map(n => renderTreeNode(n, 0)).join('');
          attachTreeListeners();
        } else {
          // Full re-render needed
          render();
        }
      }
    }, 200);
  });
}

// ─── Filter Chips ──────────────────────────────────────────────
function attachFilterListeners() {
  const chips = document.querySelectorAll('.filter-chip');
  chips.forEach(chip => {
    chip.addEventListener('click', () => {
      const kind = chip.dataset.filter || null;
      state.filterKind = kind || null;
      render();
    });
  });
}

// ─── Tree Interactions ─────────────────────────────────────────
function attachTreeListeners() {
  // Toggle expand/collapse
  document.querySelectorAll('[data-toggle]').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = el.dataset.toggle;
      if (state.expandedIds.has(id)) {
        state.expandedIds.delete(id);
      } else {
        state.expandedIds.add(id);
      }
      render();
    });
  });

  // Select node
  document.querySelectorAll('[data-select]').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = el.dataset.select;
      const node = state.nodes.find(n => n.id === id);
      if (node) {
        state.selectedNode = node;
        state.screen = 'detail';
        state.editing = false;
        state.editDraft = null;
        history.pushState({ screen: 'detail', nodeId: id }, '');
        render();
      }
    });
  });
}

// ─── Pull to Refresh ───────────────────────────────────────────
function attachPullToRefresh() {
  const content = document.getElementById('tree-content');
  if (!content) return;

  let startY = 0;
  let pulling = false;

  content.addEventListener('touchstart', (e) => {
    if (content.scrollTop === 0) {
      startY = e.touches[0].clientY;
      pulling = true;
    }
  }, { passive: true });

  content.addEventListener('touchmove', (e) => {
    if (!pulling) return;
    const diff = e.touches[0].clientY - startY;
    if (diff > 60 && content.scrollTop === 0) {
      const indicator = document.getElementById('pull-indicator');
      if (indicator && !indicator.classList.contains('active')) {
        indicator.classList.add('active');
      }
    }
  }, { passive: true });

  content.addEventListener('touchend', () => {
    if (!pulling) return;
    pulling = false;
    const indicator = document.getElementById('pull-indicator');
    if (indicator && indicator.classList.contains('active')) {
      state.pullRefreshing = true;
      sendMessage('get_tree', {});
      // Hide indicator after a short delay
      setTimeout(() => {
        state.pullRefreshing = false;
        if (indicator) indicator.classList.remove('active');
      }, 1500);
    }
  });
}

// ─── Bottom Navigation ─────────────────────────────────────────
function attachBottomNavListeners() {
  document.querySelectorAll('[data-nav]').forEach(btn => {
    btn.addEventListener('click', () => {
      const action = btn.dataset.nav;
      switch (action) {
        case 'tree':
          state.screen = 'tree';
          render();
          break;
        case 'refresh':
          state.loadingTree = true;
          render();
          sendMessage('get_tree', {});
          break;
        case 'settings':
          state.screen = 'settings';
          render();
          break;
        case 'disconnect':
          handleDisconnect();
          break;
      }
    });
  });
}

// ─── Actions ───────────────────────────────────────────────────
function handleDeploy() {
  if (!state.selectedNode) return;
  const btn = document.getElementById('deploy-btn');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="auth-loading"></span> Deploying...';
  }

  sendMessage('deploy_pipeline', {
    id: state.selectedNode.id,
    name: state.selectedNode.name,
  });

  showToast('Deploy command sent', 'success');

  setTimeout(() => {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `${Icons.deploy} Deploy`;
    }
  }, 3000);
}

function handleSaveEdit() {
  if (!state.selectedNode) return;

  const nameInput = document.getElementById('edit-name');
  const promptInput = document.getElementById('edit-prompt');
  const tagsInput = document.getElementById('edit-tags');

  const updated = {
    id: state.selectedNode.id,
    name: nameInput ? nameInput.value.trim() : state.selectedNode.name,
    prompt: promptInput ? promptInput.value : (state.selectedNode.prompt || ''),
    tags: tagsInput
      ? tagsInput.value.split(',').map(t => t.trim()).filter(Boolean)
      : (state.selectedNode.tags || []),
  };

  sendMessage('update_node', { node: updated });
  showToast('Changes sent', 'info');

  // Optimistically update local state
  const idx = state.nodes.findIndex(n => n.id === state.selectedNode.id);
  if (idx >= 0) {
    state.nodes[idx] = { ...state.nodes[idx], ...updated };
    state.selectedNode = state.nodes[idx];
  }

  state.editing = false;
  state.editDraft = null;
  render();
}

function handleUnpair() {
  deleteAllPairings().catch(() => {});
  state.savedPairing = null;
  state.pairingMode = false;
  handleDisconnect();
  state.screen = 'connect';
  render();
}

function handleDisconnect() {
  if (state.ws) {
    state.ws.close();
  }
  clearTimeout(state.reconnectTimer);
  stopPing();
  clearInterval(state.lockoutTimer);

  state.ws = null;
  state.connected = false;
  state.connecting = false;
  state.token = null;
  state.sessionId = null;
  state.nodes = [];
  state.selectedNode = null;
  state.expandedIds.clear();
  state.searchQuery = '';
  state.filterKind = null;
  state.screen = 'auth';
  state.editing = false;
  state.editDraft = null;
  state.loadingTree = true;
  state.authError = null;
  state.authLocked = false;
  state.pairingMode = false;
  state.desktopOnline = false;
  state.waitingForDesktop = false;
  // Don't clear savedPairing from IndexedDB on disconnect — only on explicit unpair
  state.relayMode = false;
  state.roomCode = null;
  state.relayUrl = null;
  // Zero key material before releasing references
  if (state.keyPair && state.keyPair.secretKey) state.keyPair.secretKey.fill(0);
  if (state.sharedKey) state.sharedKey.fill(0);
  state.keyPair = null;
  state.sharedKey = null;
  state.peerPublicKey = null;
  state.sendNonce = 0;

  render();
}

// ─── Service Worker Registration ───────────────────────────────
function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(err => {
      console.warn('SW registration failed:', err);
    });
  }
}

// ─── Init ──────────────────────────────────────────────────────
async function init() {
  // Check for saved pairing FIRST
  try {
    const savedPairing = await getSavedPairing();
    if (savedPairing) {
      state.savedPairing = savedPairing;
      state.pairingMode = true;
      state.relayMode = true;
      state.relayUrl = savedPairing.relayUrl;
      state.screen = 'paired';
      render();
      // Auto-connect
      connectWebSocket();
      registerServiceWorker();

      // Handle visibility change — reconnect if needed
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible' && !state.connected && state.screen !== 'connect') {
          if (state.pairingMode && state.savedPairing) {
            connectWebSocket();
          } else if (state.relayMode ? state.roomCode : state.token) {
            connectWebSocket();
          }
        }
      });

      // Handle back button / swipe gesture
      window.addEventListener('popstate', (e) => {
        if (state.screen === 'detail') {
          state.screen = 'tree';
          state.editing = false;
          state.editDraft = null;
          render();
        } else if (state.screen === 'tree') {
          if (state.connected) {
            history.pushState({ screen: 'tree' }, '');
          }
        } else if (state.screen === 'settings') {
          state.screen = 'tree';
          render();
        }
      });

      history.replaceState({ screen: state.screen }, '');
      return;
    }
  } catch (err) {
    console.warn('Failed to load saved pairing:', err);
  }

  // Check URL params for relay mode (from QR code scan)
  const params = new URLSearchParams(window.location.search);
  const relayCode = params.get('code');
  const relayKey = params.get('key');
  const relayUrlParam = params.get('relay');

  if (relayCode) {
    // QR code scanned - go directly to connecting
    const resolvedRelayUrl = relayUrlParam || 'wss://atm-relay.datafying.tech';
    if (!resolvedRelayUrl.startsWith('wss://')) {
      state.screen = 'connect';
      state.authError = 'Invalid relay URL: only secure (wss://) connections are allowed';
      render();
      return;
    }
    state.relayMode = true;
    state.roomCode = relayCode;
    state.relayUrl = resolvedRelayUrl;
    state.peerPublicKey = relayKey;
    state.screen = 'auth'; // Will switch after crypto handshake
    render();
    connectWebSocket();
  } else if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1' && !window.location.hostname.match(/^192\.|^10\.|^172\./)) {
    // Not on local network - show relay connect screen
    state.screen = 'connect';
    render();
  } else {
    // Local network - show PIN auth (existing behavior)
    state.screen = 'auth';
    render();
  }

  registerServiceWorker();

  // Handle visibility change — reconnect if needed
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && !state.connected && state.screen !== 'auth' && state.screen !== 'connect') {
      if (state.pairingMode && state.savedPairing) {
        connectWebSocket();
      } else if (state.relayMode ? state.roomCode : state.token) {
        connectWebSocket();
      }
    }
  });

  // Handle back button / swipe gesture
  window.addEventListener('popstate', (e) => {
    if (state.screen === 'detail') {
      state.screen = 'tree';
      state.editing = false;
      state.editDraft = null;
      render();
    } else if (state.screen === 'tree') {
      // Prevent going back to auth if connected
      if (state.connected) {
        history.pushState({ screen: 'tree' }, '');
      }
    } else if (state.screen === 'settings') {
      state.screen = 'tree';
      render();
    }
  });

  // Push initial history state
  history.replaceState({ screen: state.screen }, '');
}

init();
