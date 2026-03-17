import { create } from "zustand";
import { REMOTE_CONFIG_DEFAULTS, type RemoteConfig } from "@/types/remote";
import type { RelayStatus, PairedDevice } from "@/types/remote";
import { remoteSync } from "@/services/remote-sync";
import { useTreeStore } from "@/store/tree-store";

/** Module-level storage for event listener unsubscribe functions */
let unsubscribers: Array<() => void> = [];

interface RemoteState {
  /** Remote server configuration (persisted to .aui/remote.json) */
  remoteConfig: RemoteConfig;
  /** Whether the desktop WebSocket is connected to the local server */
  remoteConnected: boolean;
  /** Number of mobile clients currently connected */
  remoteClientCount: number;
  /** Cloud relay connection status */
  relayStatus: RelayStatus;
}

interface UiState {
  selectedNodeId: string | null;
  inspectorOpen: boolean;
  contextHubOpen: boolean;
  contextHubTab: string;
  searchQuery: string;
  contextMenu: { x: number; y: number; nodeId?: string } | null;
  createDialogOpen: boolean;
  createDialogParentId: string | null;
  createDialogDefaultKind: string | null;
  deleteDialogNodeId: string | null;
  filterKind: string | null;
  chatPanelOpen: boolean;
  settingsOpen: boolean;
  scheduleOpen: boolean;
  schedulePreselectedTeamId: string | null;
  toasts: Array<{ id: string; message: string; type: 'success' | 'error' | 'info' }>;
  collapsedGroups: Set<string>;
  multiSelectedNodeIds: Set<string>;
  theme: "dark" | "light";
}

interface RemoteActions {
  /** Update remote server config and optionally persist. */
  setRemoteConfig(updates: Partial<RemoteConfig>): void;
  /** Load remote config from .aui/remote.json. */
  loadRemoteConfig(projectPath: string): Promise<void>;
  /** Persist remote config to .aui/remote.json. */
  saveRemoteConfig(projectPath: string): Promise<void>;
  /** Start the desktop WebSocket connection to the local server. */
  connectRemote(): void;
  /** Stop the desktop WebSocket connection. */
  disconnectRemote(): void;
  /** Connect to cloud relay and create a room (ephemeral). */
  connectRelay(relayUrl: string): Promise<void>;
  /** Connect to cloud relay in persistent mode (auto-register, no room code). */
  connectRelayPersistent(relayUrl: string): Promise<void>;
  /** Disconnect from cloud relay. */
  disconnectRelay(): void;
  /** Update relay status (called from event listeners). */
  setRelayStatus(updates: Partial<RelayStatus>): void;
  /** List paired devices from relay. */
  loadPairedDevices(): Promise<void>;
  /** Revoke a specific paired device. */
  revokePairing(pairingId: string): Promise<void>;
}

interface UiActions {
  selectNode(id: string | null): void;
  toggleInspector(): void;
  toggleContextHub(): void;
  setContextHubTab(tab: string): void;
  setSearchQuery(query: string): void;
  openContextMenu(x: number, y: number, nodeId?: string): void;
  closeContextMenu(): void;
  openCreateDialog(parentId?: string, defaultKind?: string): void;
  closeCreateDialog(): void;
  openDeleteDialog(nodeId: string): void;
  closeDeleteDialog(): void;
  setFilterKind(kind: string | null): void;
  toggleChatPanel(): void;
  toggleSettings(): void;
  toggleSchedule(preselectedTeamId?: string): void;
  addToast(message: string, type?: 'success' | 'error' | 'info'): void;
  removeToast(id: string): void;
  toggleCollapse(groupId: string): void;
  toggleMultiSelect(nodeId: string): void;
  clearMultiSelect(): void;
  collapseAllGroups(groupIds: Set<string>): void;
  expandAllGroups(): void;
  setTheme(theme: "dark" | "light"): void;
}

type UiStore = UiState & RemoteState & UiActions & RemoteActions;

const DEFAULT_REMOTE_CONFIG: RemoteConfig = { ...REMOTE_CONFIG_DEFAULTS };

export const useUiStore = create<UiStore>()((set, get) => ({
  // ── UI state ──────────────────────────────────────
  selectedNodeId: null,
  inspectorOpen: true,
  contextHubOpen: false,
  contextHubTab: "memory",
  searchQuery: "",
  contextMenu: null,
  createDialogOpen: false,
  createDialogParentId: null,
  createDialogDefaultKind: null,
  deleteDialogNodeId: null,
  filterKind: null,
  chatPanelOpen: false,
  settingsOpen: false,
  scheduleOpen: false,
  schedulePreselectedTeamId: null,
  toasts: [],
  collapsedGroups: new Set<string>(),
  multiSelectedNodeIds: new Set<string>(),
  theme: "dark",

  // ── Remote state ──────────────────────────────────
  remoteConfig: { ...DEFAULT_REMOTE_CONFIG },
  remoteConnected: false,
  remoteClientCount: 0,
  relayStatus: {
    connected: false,
    roomCode: null,
    clientConnected: false,
    publicKey: null,
    persistentMode: false,
    desktopDeviceId: null,
    pairedDevices: [],
  },

  selectNode(id: string | null) {
    if (id !== null) {
      set({
        selectedNodeId: id,
        inspectorOpen: true,
        // Close overlay panels so the inspector is visible
        settingsOpen: false,
        scheduleOpen: false,
        contextHubOpen: false,
      });
    } else {
      set({ selectedNodeId: null });
    }
  },

  toggleInspector() {
    set((state) => ({ inspectorOpen: !state.inspectorOpen }));
  },

  toggleContextHub() {
    set((state) => ({
      contextHubOpen: !state.contextHubOpen,
      // Close other overlays when opening context hub
      ...(!state.contextHubOpen ? { chatPanelOpen: false, settingsOpen: false, scheduleOpen: false } : {}),
    }));
  },

  setContextHubTab(tab: string) {
    set({ contextHubTab: tab });
  },

  setSearchQuery(query: string) {
    set({ searchQuery: query });
  },

  openContextMenu(x: number, y: number, nodeId?: string) {
    set({ contextMenu: { x, y, nodeId } });
  },

  closeContextMenu() {
    set({ contextMenu: null });
  },

  openCreateDialog(parentId?: string, defaultKind?: string) {
    set({
      createDialogOpen: true,
      createDialogParentId: parentId ?? null,
      createDialogDefaultKind: defaultKind ?? null,
    });
  },

  closeCreateDialog() {
    set({ createDialogOpen: false, createDialogParentId: null, createDialogDefaultKind: null });
  },

  openDeleteDialog(nodeId: string) {
    set({ deleteDialogNodeId: nodeId });
  },

  closeDeleteDialog() {
    set({ deleteDialogNodeId: null });
  },

  setFilterKind(kind: string | null) {
    set({ filterKind: kind });
  },

  toggleChatPanel() {
    set((state) => ({
      chatPanelOpen: !state.chatPanelOpen,
      // Close other overlays when opening chat
      ...(!state.chatPanelOpen ? { settingsOpen: false, scheduleOpen: false, contextHubOpen: false } : {}),
    }));
  },

  toggleSettings() {
    set((state) => ({
      settingsOpen: !state.settingsOpen,
      // Close other overlays when opening settings
      ...(!state.settingsOpen ? { chatPanelOpen: false, scheduleOpen: false, contextHubOpen: false } : {}),
    }));
  },

  toggleSchedule(preselectedTeamId?: string) {
    set((state) => ({
      scheduleOpen: !state.scheduleOpen,
      schedulePreselectedTeamId: !state.scheduleOpen ? (preselectedTeamId ?? null) : null,
      // Close other overlays when opening schedule
      ...(!state.scheduleOpen ? { chatPanelOpen: false, settingsOpen: false, contextHubOpen: false } : {}),
    }));
  },

  addToast(message: string, type: 'success' | 'error' | 'info' = 'info') {
    const id = Math.random().toString(36).slice(2);
    set((state) => ({
      toasts: [...state.toasts, { id, message, type }],
    }));
    setTimeout(() => get().removeToast(id), 3000);
  },

  removeToast(id: string) {
    set((state) => ({
      toasts: state.toasts.filter((t) => t.id !== id),
    }));
  },

  toggleCollapse(groupId: string) {
    set((state) => {
      const next = new Set(state.collapsedGroups);
      if (next.has(groupId)) {
        next.delete(groupId);
      } else {
        next.add(groupId);
      }
      return { collapsedGroups: next };
    });
  },

  toggleMultiSelect(nodeId: string) {
    set((state) => {
      const next = new Set(state.multiSelectedNodeIds);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      } else {
        next.add(nodeId);
      }
      return { multiSelectedNodeIds: next };
    });
  },

  clearMultiSelect() {
    set({ multiSelectedNodeIds: new Set<string>() });
  },

  collapseAllGroups(groupIds: Set<string>) {
    set({ collapsedGroups: new Set(groupIds) });
  },

  expandAllGroups() {
    set({ collapsedGroups: new Set<string>() });
  },

  setTheme(theme: "dark" | "light") {
    set({ theme });
  },

  // ── Remote actions ──────────────────────────────────

  setRemoteConfig(updates: Partial<RemoteConfig>) {
    set((state) => ({
      remoteConfig: { ...state.remoteConfig, ...updates },
    }));
  },

  async loadRemoteConfig(projectPath: string) {
    try {
      const { readTextFile, exists } = await import("@tauri-apps/plugin-fs");
      const configPath = projectPath.replace(/\\/g, "/") + "/.aui/remote.json";
      if (await exists(configPath)) {
        const raw = await readTextFile(configPath);
        const parsed = JSON.parse(raw);
        set((state) => ({
          remoteConfig: { ...DEFAULT_REMOTE_CONFIG, ...parsed },
        }));
      }
    } catch (err) {
      console.warn("[ATM] Failed to load remote config:", err);
    }
  },

  async saveRemoteConfig(projectPath: string) {
    try {
      const { writeTextFile, exists, mkdir } = await import("@tauri-apps/plugin-fs");
      const auiDir = projectPath.replace(/\\/g, "/") + "/.aui";
      if (!(await exists(auiDir))) {
        await mkdir(auiDir, { recursive: true });
      }
      const configPath = auiDir + "/remote.json";
      await writeTextFile(configPath, JSON.stringify(get().remoteConfig, null, 2));
    } catch (err) {
      console.warn("[ATM] Failed to save remote config:", err);
    }
  },

  async connectRemote() {
    // Listen for connection changes from the sync service
    const unsub = remoteSync.onConnectionChange((connected, clientCount) => {
      set({ remoteConnected: connected, remoteClientCount: clientCount });
    });
    unsubscribers.push(unsub);

    // Initialize Tauri event listeners for server started/stopped events
    await remoteSync.init();

    // Register tree-store push/reconnect handlers so mobile get_tree requests work
    const unsubTree = useTreeStore.getState().initRemoteSync();
    unsubscribers.push(unsubTree);
  },

  disconnectRemote() {
    unsubscribers.forEach((fn) => fn());
    unsubscribers = [];
    remoteSync.dispose();
    set({ remoteConnected: false, remoteClientCount: 0 });
  },

  async connectRelay(relayUrl: string) {
    try {
      const status = await remoteSync.initRelay(relayUrl);
      set({
        remoteConnected: true,
        relayStatus: status,
      });
    } catch (err) {
      console.warn("[ATM] Failed to connect to relay:", err);
      remoteSync.dispose();
      throw err;
    }

    const unsub = remoteSync.onConnectionChange((connected, clientCount) => {
      set({
        remoteConnected: connected,
        remoteClientCount: clientCount,
        relayStatus: {
          ...get().relayStatus,
          connected,
          clientConnected: clientCount > 0,
        },
      });
    });
    unsubscribers.push(unsub);

    // Register tree-store push/reconnect handlers so mobile get_tree requests work
    const unsubTree = useTreeStore.getState().initRemoteSync();
    unsubscribers.push(unsubTree);
  },

  async connectRelayPersistent(relayUrl: string) {
    try {
      const status = await remoteSync.initRelayPersistent(relayUrl);
      set({
        remoteConnected: true,
        relayStatus: status,
      });
    } catch (err) {
      console.warn("[ATM] Failed to connect to relay (persistent):", err);
      remoteSync.dispose();
      throw err;
    }

    const unsub = remoteSync.onConnectionChange((connected, clientCount) => {
      set({
        remoteConnected: connected,
        remoteClientCount: clientCount,
        relayStatus: {
          ...get().relayStatus,
          connected,
          clientConnected: clientCount > 0,
        },
      });
    });
    unsubscribers.push(unsub);

    // Register tree-store push/reconnect handlers
    const unsubTree = useTreeStore.getState().initRemoteSync();
    unsubscribers.push(unsubTree);
  },

  disconnectRelay() {
    unsubscribers.forEach((fn) => fn());
    unsubscribers = [];
    remoteSync.dispose();
    set({
      remoteConnected: false,
      remoteClientCount: 0,
      relayStatus: {
        connected: false,
        roomCode: null,
        clientConnected: false,
        publicKey: null,
        persistentMode: false,
        desktopDeviceId: null,
        pairedDevices: [],
      },
    });
  },

  setRelayStatus(updates: Partial<RelayStatus>) {
    set((state) => ({
      relayStatus: { ...state.relayStatus, ...updates },
    }));
  },

  async loadPairedDevices() {
    const devices = await remoteSync.listPairedDevices();
    set((state) => ({
      relayStatus: { ...state.relayStatus, pairedDevices: devices },
    }));
  },

  async revokePairing(pairingId: string) {
    const success = await remoteSync.revokePairing(pairingId);
    if (success) {
      set((state) => ({
        relayStatus: {
          ...state.relayStatus,
          pairedDevices: state.relayStatus.pairedDevices.filter(
            (d) => d.pairingId !== pairingId
          ),
        },
      }));
    }
  },
}));
