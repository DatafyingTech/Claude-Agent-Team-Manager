import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import nacl from "tweetnacl";
import { encodeBase64, decodeBase64 } from "tweetnacl-util";
import type { AuiNode } from "@/types/aui-node";
import type {
  RedactedRemoteNode,
  RemoteMessage,
  ServerEventType,
  EncryptedEnvelope,
  RelayStatus,
  PairedDevice,
  PairingToken,
} from "@/types/remote";
import { redactNode } from "@/types/remote";

// ── Serialization helpers ────────────────────────────

/**
 * Convert an AuiNode to a RedactedRemoteNode (strips sourcePath) and redact
 * sensitive variable values (api-key, password) to prevent leaking secrets
 * over the wire.
 */
export function nodeToRemote(node: AuiNode): RedactedRemoteNode {
  return redactNode({
    id: node.id,
    name: node.name,
    kind: node.kind,
    parentId: node.parentId,
    team: node.team,
    config: node.config,
    promptBody: node.promptBody,
    tags: node.tags,
    lastModified: node.lastModified,
    validationErrors: node.validationErrors,
    assignedSkills: node.assignedSkills,
    variables: node.variables,
    launchPrompt: node.launchPrompt,
    pipelineSteps: node.pipelineSteps,
  });
}

/** Convert a Map<string, AuiNode> to a RedactedRemoteNode array. */
export function serializeNodes(nodes: Map<string, AuiNode>): RedactedRemoteNode[] {
  const result: RedactedRemoteNode[] = [];
  for (const node of nodes.values()) {
    result.push(nodeToRemote(node));
  }
  return result;
}

// ── E2E Crypto Session ───────────────────────────────

/**
 * Manages X25519 key exchange and XSalsa20-Poly1305 authenticated encryption.
 * Used in cloud relay mode to ensure the relay never sees plaintext.
 *
 * Nonce space is partitioned by role to prevent collisions: desktop uses
 * prefix byte 0x01, mobile uses 0x02.  Both sides start their counter at 0
 * but will never produce identical nonces because the first byte differs.
 */
export class CryptoSession {
  private keyPair: nacl.BoxKeyPair;
  private sharedKey: Uint8Array | null = null;
  /** Counter-based nonce for sending (incremented per message) */
  private sendNonce: number = 0;
  /** Role prefix byte: 0x01 = desktop, 0x02 = mobile */
  private readonly rolePrefix: number;

  constructor(role: "desktop" | "mobile" = "desktop") {
    this.keyPair = nacl.box.keyPair();
    this.rolePrefix = role === "desktop" ? 0x01 : 0x02;
  }

  /** Base64-encoded public key to share with the peer */
  get publicKeyBase64(): string {
    return encodeBase64(this.keyPair.publicKey);
  }

  /** Whether a shared secret has been derived (peer key received) */
  get isPaired(): boolean {
    return this.sharedKey !== null;
  }

  /**
   * Derive the shared secret from the peer's public key.
   * After this, encrypt() and decrypt() can be used.
   */
  deriveSharedKey(peerPublicKeyBase64: string): void {
    const peerPublicKey = decodeBase64(peerPublicKeyBase64);
    this.sharedKey = nacl.box.before(peerPublicKey, this.keyPair.secretKey);
  }

  /**
   * Encrypt a RemoteMessage into an EncryptedEnvelope.
   * Uses counter-based nonces to prevent reuse.
   */
  encrypt(message: RemoteMessage): EncryptedEnvelope {
    if (!this.sharedKey) throw new Error("CryptoSession not paired");
    if (this.sendNonce >= Number.MAX_SAFE_INTEGER)
      throw new Error("Nonce space exhausted, reconnect required");

    const plaintext = new TextEncoder().encode(JSON.stringify(message));
    const nonce = this.makeNonce(this.sendNonce++);
    const ciphertext = nacl.secretbox(plaintext, nonce, this.sharedKey);

    if (!ciphertext) throw new Error("Encryption failed");

    return {
      type: "encrypted",
      nonce: encodeBase64(nonce),
      ciphertext: encodeBase64(ciphertext),
    };
  }

  /**
   * Decrypt an EncryptedEnvelope back into a RemoteMessage.
   */
  decrypt(envelope: EncryptedEnvelope): RemoteMessage | null {
    if (!this.sharedKey) throw new Error("CryptoSession not paired");

    const nonce = decodeBase64(envelope.nonce);
    const ciphertext = decodeBase64(envelope.ciphertext);
    const plaintext = nacl.secretbox.open(ciphertext, nonce, this.sharedKey);

    if (!plaintext) {
      console.warn("[CryptoSession] Decryption failed — invalid ciphertext or nonce");
      return null;
    }

    return JSON.parse(new TextDecoder().decode(plaintext)) as RemoteMessage;
  }

  /** Zero out key material to prevent leakage after session ends. */
  destroy(): void {
    this.keyPair.secretKey.fill(0);
    if (this.sharedKey) this.sharedKey.fill(0);
  }

  /** Build a 24-byte nonce from a counter value, prefixed by role byte */
  private makeNonce(counter: number): Uint8Array {
    const nonce = new Uint8Array(24);
    // Byte 0: role prefix (0x01 desktop, 0x02 mobile) to prevent collisions
    nonce[0] = this.rolePrefix;
    // Write counter as big-endian in the last 8 bytes
    const view = new DataView(nonce.buffer);
    // Use two 32-bit writes for the 64-bit counter space
    view.setUint32(16, Math.floor(counter / 0x100000000), false);
    view.setUint32(20, counter >>> 0, false);
    return nonce;
  }
}

// ── Remote Sync Service ──────────────────────────────

type PushHandler = (msg: RemoteMessage) => void;
type ConnectionHandler = (connected: boolean, clientCount: number) => void;

/**
 * Bridges the desktop frontend with the Rust remote access server using
 * Tauri commands and events (NOT WebSocket -- the desktop communicates
 * with the Rust backend via IPC, not over the network).
 *
 * Supports two modes:
 * - LAN mode: Direct local server (existing behavior)
 * - Cloud mode: Via relay server with E2E encryption
 *
 * Communication flow (LAN):
 *   Local store change -> broadcastEvent() -> invoke("broadcast_to_remote") -> Rust bridge -> WS fan-out to mobiles
 *   Mobile command -> WS -> Rust bridge -> Tauri event ("remote:request-sync") -> onPush handler -> local store
 *
 * Communication flow (Cloud):
 *   Local store change -> broadcastEvent() -> encrypt -> invoke("send_to_relay") -> relay -> mobile
 *   Mobile command -> relay -> Tauri event ("relay:message") -> decrypt -> onPush handler -> local store
 */
class RemoteSyncService {
  private pushHandlers: Set<PushHandler> = new Set();
  private connectionHandlers: Set<ConnectionHandler> = new Set();
  private reconnectHandlers: Set<() => void> = new Set();
  private _connected: boolean = false;
  private _clientCount: number = 0;
  /** Whether the mobile peer has authenticated via PIN (cloud mode only). */
  private _authenticated: boolean = false;
  /** When true, the next state mutation was triggered by a remote command -- skip broadcasting. */
  private _remoteOrigin: boolean = false;
  /** Cleanup functions for all Tauri event listeners. */
  private _unlisteners: Array<() => void> = [];

  /** Current operating mode */
  private _mode: "lan" | "cloud" = "lan";

  /** E2E crypto session (cloud mode only) */
  private _crypto: CryptoSession | null = null;

  /** Relay connection status */
  private _relayStatus: RelayStatus = {
    connected: false,
    roomCode: null,
    clientConnected: false,
    publicKey: null,
    persistentMode: false,
    desktopDeviceId: null,
    pairedDevices: [],
  };

  get connected(): boolean {
    return this._connected;
  }

  get clientCount(): number {
    return this._clientCount;
  }

  get mode(): "lan" | "cloud" {
    return this._mode;
  }

  get relayStatus(): RelayStatus {
    return { ...this._relayStatus };
  }

  get cryptoSession(): CryptoSession | null {
    return this._crypto;
  }

  /** Check and consume the remote-origin flag (prevents echo loops). */
  consumeRemoteOrigin(): boolean {
    if (this._remoteOrigin) {
      this._remoteOrigin = false;
      return true;
    }
    return false;
  }

  /** Mark the next store mutation as originating from a remote client. */
  markRemoteOrigin(): void {
    this._remoteOrigin = true;
  }

  /** Register a handler for incoming push events from the server. */
  onPush(handler: PushHandler): () => void {
    this.pushHandlers.add(handler);
    return () => this.pushHandlers.delete(handler);
  }

  /** Register a handler for connection status changes. */
  onConnectionChange(handler: ConnectionHandler): () => void {
    this.connectionHandlers.add(handler);
    return () => this.connectionHandlers.delete(handler);
  }

  /** Register a handler called on reconnect (not first connect). Used to push full resync. */
  onReconnect(handler: () => void): () => void {
    this.reconnectHandlers.add(handler);
    return () => this.reconnectHandlers.delete(handler);
  }

  /**
   * Broadcast a server event to all connected remote clients.
   * In LAN mode: via Rust bridge. In cloud mode: encrypted via relay.
   * No-op if not connected.
   */
  broadcastEvent(type: ServerEventType, payload: unknown): void {
    if (!this._connected) return;

    if (this._mode === "cloud") {
      if (!this._authenticated) return;
      this.broadcastViaRelay(type, payload);
    } else {
      invoke("broadcast_to_remote", {
        eventType: type,
        payload,
      }).catch((err) => {
        console.warn("[RemoteSync] Failed to broadcast:", err);
      });
    }
  }

  /**
   * Encrypt and send a message through the relay (cloud mode).
   */
  private broadcastViaRelay(type: ServerEventType, payload: unknown): void {
    if (!this._crypto?.isPaired) return;

    const msg: RemoteMessage = {
      type,
      id: crypto.randomUUID(),
      payload,
      timestamp: Date.now(),
    };

    try {
      const envelope = this._crypto.encrypt(msg);
      invoke("send_to_relay", { data: JSON.stringify(envelope) }).catch((err) => {
        console.warn("[RemoteSync] Failed to send via relay:", err);
      });
    } catch (err) {
      console.warn("[RemoteSync] Encryption failed:", err);
    }
  }

  /**
   * Initialize LAN mode: listen for Tauri events from the Rust server.
   */
  async init(): Promise<void> {
    if (this._unlisteners.length > 0) this.dispose();
    this._mode = "lan";

    const u1 = await listen<{ port: number; url: string; pin: string }>(
      "remote-server-started",
      (event) => {
        console.log("[RemoteSync] Server started on port", event.payload?.port);
        this._connected = true;
        this.notifyConnectionChange();

        for (const handler of this.reconnectHandlers) {
          try {
            handler();
          } catch (err) {
            console.warn("[RemoteSync] Reconnect handler error:", err);
          }
        }
      },
    );

    const u2 = await listen("remote-server-stopped", () => {
      console.log("[RemoteSync] Server stopped");
      this._connected = false;
      this._clientCount = 0;
      this.notifyConnectionChange();
    });

    const u3 = await listen("remote:request-sync", () => {
      const msg: RemoteMessage = {
        type: "get_tree",
        id: crypto.randomUUID(),
        payload: {},
        timestamp: Date.now(),
      };
      for (const handler of this.pushHandlers) {
        try {
          handler(msg);
        } catch (err) {
          console.warn("[RemoteSync] Push handler error:", err);
        }
      }
    });

    const u4 = await listen<{ id: string }>("remote:request-node", (event) => {
      const nodeId = event.payload?.id;
      if (!nodeId) return;
      const msg: RemoteMessage = {
        type: "get_node",
        id: crypto.randomUUID(),
        payload: { id: nodeId },
        timestamp: Date.now(),
      };
      for (const handler of this.pushHandlers) {
        try {
          handler(msg);
        } catch (err) {
          console.warn("[RemoteSync] Push handler error:", err);
        }
      }
    });

    this._unlisteners.push(u1, u2, u3, u4);
  }

  /**
   * Initialize cloud relay mode: connect to relay and create a room.
   */
  async initRelay(relayUrl: string): Promise<RelayStatus> {
    if (this._unlisteners.length > 0) this.dispose();
    this._mode = "cloud";

    // Create crypto session
    this._crypto = new CryptoSession();
    this._relayStatus = {
      connected: false,
      roomCode: null,
      clientConnected: false,
      publicKey: this._crypto.publicKeyBase64,
      persistentMode: false,
      desktopDeviceId: null,
      pairedDevices: [],
    };

    // Listen for relay events from Rust backend
    const u1 = await listen<{ room_code: string }>("relay:room-created", (event) => {
      console.log("[RemoteSync] Relay room created:", event.payload.room_code);
      this._relayStatus.roomCode = event.payload.room_code;
      this._relayStatus.connected = true;
      this._connected = true;
      this.notifyConnectionChange();
    });

    const u2 = await listen<{ mobile_public_key: string }>("relay:peer-joined", (event) => {
      console.log("[RemoteSync] Peer joined relay room — awaiting PIN auth");
      if (this._crypto) {
        this._crypto.deriveSharedKey(event.payload.mobile_public_key);
      }
      this._relayStatus.clientConnected = true;
      this._clientCount = 1;
      this._authenticated = false;
      this.notifyConnectionChange();
      // Do NOT fire reconnect handlers here — wait for PIN auth
    });

    const u3 = await listen("relay:peer-disconnected", () => {
      console.log("[RemoteSync] Peer disconnected from relay");
      this._relayStatus.clientConnected = false;
      this._clientCount = 0;
      this._authenticated = false;
      this.notifyConnectionChange();
    });

    const u4 = await listen("relay:disconnected", () => {
      console.log("[RemoteSync] Disconnected from relay");
      this._connected = false;
      this._relayStatus.connected = false;
      this._relayStatus.clientConnected = false;
      this._clientCount = 0;
      this.notifyConnectionChange();
    });

    // Handle encrypted messages from mobile via relay
    const u5 = await listen<{ data: string }>("relay:message", (event) => {
      if (!this._crypto?.isPaired) return;

      try {
        const envelope = JSON.parse(event.payload.data) as EncryptedEnvelope;
        if (envelope.type !== "encrypted") return;

        const msg = this._crypto.decrypt(envelope);
        if (!msg) return;

        // ── PIN auth gate ──
        if (msg.type === "auth" && !this._authenticated) {
          this.handleAuthMessage(msg);
          return;
        }

        // Drop all non-auth messages until authenticated
        if (!this._authenticated) return;

        for (const handler of this.pushHandlers) {
          try {
            handler(msg);
          } catch (err) {
            console.warn("[RemoteSync] Push handler error:", err);
          }
        }
      } catch (err) {
        console.warn("[RemoteSync] Failed to process relay message:", err);
      }
    });

    this._unlisteners.push(u1, u2, u3, u4, u5);

    // Connect to relay and create room
    try {
      const result = await invoke<{ room_code: string }>("connect_to_relay", {
        relayUrl,
        publicKey: this._crypto.publicKeyBase64,
      });
      this._relayStatus.roomCode = result.room_code;
      this._relayStatus.connected = true;
      this._connected = true;
      this.notifyConnectionChange();
    } catch (err) {
      console.warn("[RemoteSync] Failed to connect to relay:", err);
      this._relayStatus.connected = false;
      // Provide user-friendly error for common failure modes
      const errStr = String(err);
      if (errStr.includes("302") || errStr.includes("redirect")) {
        throw new Error("Cloud relay server unavailable (received redirect). The relay may not be deployed yet.");
      }
      if (errStr.includes("404")) {
        throw new Error("Cloud relay server not found. Check the relay URL.");
      }
      if (errStr.includes("503") || errStr.includes("502")) {
        throw new Error("Cloud relay server is temporarily unavailable. Try again later.");
      }
      throw err;
    }

    return { ...this._relayStatus };
  }

  /**
   * Initialize persistent relay mode: register desktop with relay for
   * persistent pairing (no room code needed). Paired mobiles reconnect
   * automatically using saved tokens.
   */
  async initRelayPersistent(relayUrl: string): Promise<RelayStatus> {
    if (this._unlisteners.length > 0) this.dispose();
    this._mode = "cloud";

    // Create or load long-term crypto session
    this._crypto = new CryptoSession();
    const publicKey = this._crypto.publicKeyBase64;

    // Derive desktop device ID as SHA-256 of public key
    const keyBytes = decodeBase64(publicKey);
    const hashBuffer = await crypto.subtle.digest("SHA-256", keyBytes.buffer as ArrayBuffer);
    const hashArray = new Uint8Array(hashBuffer);
    const desktopDeviceId = Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');

    this._relayStatus = {
      connected: false,
      roomCode: null,
      clientConnected: false,
      publicKey,
      persistentMode: true,
      desktopDeviceId,
      pairedDevices: [],
    };

    // Listen for relay events from Rust backend
    const u1 = await listen("relay:registered", () => {
      console.log("[RemoteSync] Desktop registered with relay for persistent pairing");
      this._relayStatus.connected = true;
      this._connected = true;
      this.notifyConnectionChange();
    });

    const u2 = await listen<{ mobile_public_key: string; pairing_id?: string }>("relay:peer-joined", (event) => {
      console.log("[RemoteSync] Peer joined via pairing");
      if (this._crypto) {
        this._crypto.deriveSharedKey(event.payload.mobile_public_key);
      }
      this._relayStatus.clientConnected = true;
      this._clientCount = 1;
      // In persistent mode, paired mobiles are pre-authenticated
      if (this._relayStatus.persistentMode && event.payload.pairing_id) {
        this._authenticated = true;
        // Fire reconnect handlers to push full state
        for (const handler of this.reconnectHandlers) {
          try { handler(); } catch (err) {
            console.warn("[RemoteSync] Reconnect handler error:", err);
          }
        }
      } else {
        this._authenticated = false;
      }
      this.notifyConnectionChange();
    });

    const u3 = await listen("relay:peer-disconnected", () => {
      console.log("[RemoteSync] Peer disconnected from relay");
      this._relayStatus.clientConnected = false;
      this._clientCount = 0;
      this._authenticated = false;
      this.notifyConnectionChange();
    });

    const u4 = await listen("relay:disconnected", () => {
      console.log("[RemoteSync] Disconnected from relay");
      this._connected = false;
      this._relayStatus.connected = false;
      this._relayStatus.clientConnected = false;
      this._clientCount = 0;
      this.notifyConnectionChange();
    });

    // Handle encrypted messages from mobile via relay
    const u5 = await listen<{ data: string }>("relay:message", (event) => {
      if (!this._crypto?.isPaired) return;

      try {
        const envelope = JSON.parse(event.payload.data) as EncryptedEnvelope;
        if (envelope.type !== "encrypted") return;

        const msg = this._crypto.decrypt(envelope);
        if (!msg) return;

        // PIN auth gate (for initial pairing flow via room code)
        if (msg.type === "auth" && !this._authenticated) {
          this.handleAuthMessage(msg);
          return;
        }

        if (!this._authenticated) return;

        for (const handler of this.pushHandlers) {
          try { handler(msg); } catch (err) {
            console.warn("[RemoteSync] Push handler error:", err);
          }
        }
      } catch (err) {
        console.warn("[RemoteSync] Failed to process relay message:", err);
      }
    });

    this._unlisteners.push(u1, u2, u3, u4, u5);

    // Register desktop with relay
    try {
      await invoke("register_desktop_relay", {
        relayUrl,
        desktopDeviceId,
        publicKey,
      });
      this._relayStatus.connected = true;
      this._connected = true;
      this.notifyConnectionChange();
    } catch (err) {
      console.warn("[RemoteSync] Failed to register with relay:", err);
      this._relayStatus.connected = false;
      throw err;
    }

    return { ...this._relayStatus };
  }

  /**
   * Issue a pairing token to the currently connected mobile peer.
   * Called after successful PIN authentication.
   * Returns the token info for display/confirmation.
   */
  async issuePairingToken(deviceName: string = "Mobile Device"): Promise<PairingToken | null> {
    if (!this._crypto?.isPaired || !this._relayStatus.desktopDeviceId) return null;

    try {
      const result = await invoke<{
        token: string;
        pairing_id: string;
        expires_at: number;
      }>("issue_pairing_token", {
        desktopDeviceId: this._relayStatus.desktopDeviceId,
        desktopPublicKey: this._relayStatus.publicKey,
        deviceName,
      });

      // Send the pairing token to mobile over the encrypted channel
      const pairingMsg: RemoteMessage = {
        type: "pairing_issued" as ServerEventType,
        id: crypto.randomUUID(),
        payload: {
          pairing_token: result.token,
          desktop_device_id: this._relayStatus.desktopDeviceId,
          desktop_name: "ATM Desktop",
          expires_at: result.expires_at,
        },
        timestamp: Date.now(),
      };
      const envelope = this._crypto.encrypt(pairingMsg);
      await invoke("send_to_relay", { data: JSON.stringify(envelope) });

      return {
        token: result.token,
        desktopDeviceId: this._relayStatus.desktopDeviceId,
        desktopName: "ATM Desktop",
        expiresAt: result.expires_at,
      };
    } catch (err) {
      console.warn("[RemoteSync] Failed to issue pairing token:", err);
      return null;
    }
  }

  /**
   * List paired devices from the relay.
   */
  async listPairedDevices(): Promise<PairedDevice[]> {
    if (!this._relayStatus.desktopDeviceId) return [];
    try {
      const devices = await invoke<PairedDevice[]>("list_paired_devices", {
        desktopDeviceId: this._relayStatus.desktopDeviceId,
      });
      this._relayStatus.pairedDevices = devices;
      return devices;
    } catch (err) {
      console.warn("[RemoteSync] Failed to list paired devices:", err);
      return [];
    }
  }

  /**
   * Revoke a specific paired device.
   */
  async revokePairing(pairingId: string): Promise<boolean> {
    try {
      await invoke("revoke_pairing", { pairingId });
      this._relayStatus.pairedDevices = this._relayStatus.pairedDevices.filter(
        d => d.pairingId !== pairingId
      );
      return true;
    } catch (err) {
      console.warn("[RemoteSync] Failed to revoke pairing:", err);
      return false;
    }
  }

  /**
   * Push the full app state to the Rust shared state so the REST API
   * and new WebSocket clients can access it.
   */
  async syncFullState(
    nodes: Map<string, AuiNode>,
    layouts: unknown,
    settings: unknown,
  ): Promise<void> {
    if (this._mode === "cloud") {
      if (!this._authenticated) return;
      // In cloud mode, send full_sync via encrypted relay
      const remoteNodes: RedactedRemoteNode[] = [];
      for (const node of nodes.values()) {
        remoteNodes.push(nodeToRemote(node));
      }
      this.broadcastEvent("full_sync", { nodes: remoteNodes, metadata: {} });
      return;
    }

    // LAN mode: push to Rust shared state
    const remoteNodes: RedactedRemoteNode[] = [];
    for (const node of nodes.values()) {
      remoteNodes.push(nodeToRemote(node));
    }
    await invoke("sync_state_to_remote", {
      nodes: remoteNodes,
      layouts: layouts ?? null,
      settings: settings ?? null,
    }).catch((err) => {
      console.warn("[RemoteSync] syncFullState failed:", err);
    });
  }

  /** Tear down the service and clean up all resources. */
  dispose(): void {
    // If in cloud mode, disconnect from relay
    if (this._mode === "cloud") {
      if (this._relayStatus.persistentMode) {
        invoke("disconnect_desktop_relay").catch(() => {});
      } else {
        invoke("disconnect_from_relay").catch(() => {});
      }
    }

    this._connected = false;
    this._clientCount = 0;
    this._authenticated = false;
    if (this._crypto) {
      this._crypto.destroy();
      this._crypto = null;
    }
    this._relayStatus = {
      connected: false,
      roomCode: null,
      clientConnected: false,
      publicKey: null,
      persistentMode: false,
      desktopDeviceId: null,
      pairedDevices: [],
    };
    for (const unlisten of this._unlisteners) {
      unlisten();
    }
    this._unlisteners = [];
  }

  // ── Private ──────────────────────────────────────

  /**
   * Handle an incoming auth message from the mobile peer.
   * Verifies the PIN and, on success, fires reconnect handlers to push full state.
   */
  private async handleAuthMessage(msg: RemoteMessage): Promise<void> {
    if (!this._crypto?.isPaired) return;

    try {
      const desktopPin = await invoke<string>("get_remote_pin");
      const submittedPin = (msg.payload as { pin?: string })?.pin;

      if (typeof submittedPin === "string" && submittedPin === desktopPin) {
        this._authenticated = true;
        console.log("[RemoteSync] PIN auth succeeded");

        // Send auth_ok response
        const okMsg: RemoteMessage = {
          type: "auth_ok" as ServerEventType,
          id: crypto.randomUUID(),
          payload: {},
          timestamp: Date.now(),
        };
        const envelope = this._crypto.encrypt(okMsg);
        await invoke("send_to_relay", { data: JSON.stringify(envelope) });

        // Auto-issue pairing token for persistent reconnection
        if (this._relayStatus.persistentMode || this._relayStatus.desktopDeviceId) {
          try {
            await this.issuePairingToken("Mobile Device");
            console.log("[RemoteSync] Pairing token issued to mobile");
          } catch (err) {
            console.warn("[RemoteSync] Failed to auto-issue pairing token:", err);
          }
        }

        // Now push full state via reconnect handlers
        for (const handler of this.reconnectHandlers) {
          try {
            handler();
          } catch (err) {
            console.warn("[RemoteSync] Reconnect handler error:", err);
          }
        }
      } else {
        console.warn("[RemoteSync] PIN auth failed — incorrect PIN");

        // Send auth_fail response
        const failMsg: RemoteMessage = {
          type: "auth_fail" as ServerEventType,
          id: crypto.randomUUID(),
          payload: {},
          timestamp: Date.now(),
        };
        const envelope = this._crypto.encrypt(failMsg);
        await invoke("send_to_relay", { data: JSON.stringify(envelope) });
      }
    } catch (err) {
      console.warn("[RemoteSync] Auth handling error:", err);
    }
  }

  private notifyConnectionChange(): void {
    for (const handler of this.connectionHandlers) {
      try {
        handler(this._connected, this._clientCount);
      } catch (err) {
        console.warn("[RemoteSync] Connection handler error:", err);
      }
    }
  }
}

/** Singleton instance shared across the app. */
export const remoteSync = new RemoteSyncService();
