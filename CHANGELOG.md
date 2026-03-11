# ATM (Agent Team Manager) — Changelog

## v0.8.5 — March 5, 2026

### Persistent Mobile Pairing & PWA

**Persistent Device Pairing:**
- **Pair once, connect forever** — after initial room-code + PIN pairing, desktop issues a 256-bit pairing token (valid 90 days) that mobile stores in IndexedDB. Subsequent connections are fully automatic — no room code needed
- **Relay server pairing registry** — SQLite-backed pairing storage on the relay server with SHA-256 token hashing, expiry tracking, and automatic cleanup of expired records
- **Desktop auto-registration** — desktop registers with relay on cloud mode enable (`register_desktop` protocol), allowing paired mobiles to find it without ephemeral rooms
- **Waiting room pattern** — if mobile reconnects while desktop is offline, relay holds the connection and sends `peer_offline` / `peer_online` notifications with automatic bridging when desktop comes back
- **Pairing management UI** — Settings panel shows paired devices with name, last used date, expiry, and revoke button
- **Revoke pairing** — desktop can revoke individual or all pairings; mobile is immediately disconnected and token invalidated

**Mobile PWA Enhancements:**
- **Saved pairing screen** — when a pairing token exists, mobile shows "Connecting to [Desktop Name]..." with auto-reconnect instead of room code input
- **PWA installable** — service worker caches app shell (HTML, CSS, JS, icons) for offline startup; manifest enables "Add to Home Screen"
- **Settings screen** — mobile shows paired desktop name, connection status, pairing expiry, and "Unpair" button
- **Auto-reconnect** — on app open, automatically connects to relay using saved pairing token
- **Offline UI** — installed PWA opens without network, shows cached UI with "connecting..." status

**Relay Server Protocol Extensions:**
- `register_desktop` — desktop registers for persistent connections (keyed by device ID)
- `reconnect_paired` — mobile reconnects using pairing token (relay validates SHA-256 hash)
- `register_pairing` / `pairing_registered` — desktop registers new pairing with relay
- `revoke_pairing` / `pairing_revoked` — desktop revokes a specific pairing
- `peer_offline` / `peer_online` — relay signals desktop availability to waiting mobiles
- Desktop-to-mobile message forwarding in persistent mode

**Desktop Tauri Commands:**
- `register_desktop_relay` — register desktop with relay for persistent pairing
- `disconnect_desktop_relay` — disconnect persistent relay connection
- `issue_pairing_token` — generate 256-bit token, register SHA-256 hash with relay
- `list_paired_devices` — list locally tracked paired devices
- `revoke_pairing` — revoke a pairing via relay control message

**QA:**
- Full TypeScript compilation check (`tsc --noEmit`) — zero errors
- Rust compilation check (`cargo check`) — both `src-tauri/` and `relay/` pass

---

## v0.8.3 — March 5, 2026

### Production-Ready Remote Access

**Cloud Relay Deployment:**
- **Relay server deployed** — cloud relay now live at `wss://atm-relay.datafying.tech` on Linode (Ubuntu 22.04), fronted by Caddy with automatic TLS
- **Domain switch** — migrated from `atm-relay.datafying.com` (CloudFront, broken) to `atm-relay.datafying.tech` (direct DNS to Linode)
- **systemd hardening** — relay runs as dedicated `atm-relay` user with NoNewPrivileges, ProtectSystem=strict, MemoryMax=500M
- **Caddy reverse proxy** — automatic HTTPS certificate provisioning, WebSocket upgrade handling, security headers

**Bug Fixes:**
- **LAN mobile skeleton loading** — `initRemoteSync()` was never called on LAN connect; mobile clients now receive tree data immediately after PIN auth
- **Domain references updated** — all hardcoded `.datafying.com` URLs replaced with `.datafying.tech` across desktop, mobile client, and relay config

**QA:**
- Full TypeScript compilation check (`tsc --noEmit`) — zero errors
- Rust compilation check (`cargo check`) — both `src-tauri/` and `relay/` pass
- Cloud E2E verified: desktop → relay → mobile with PIN auth and encrypted sync
- LAN E2E verified: desktop → mobile on same network with real-time updates

---

## v0.8.2 — March 5, 2026

### Security Hotfix: Cloud Relay Hardening

**High Priority Fixes:**
- **PIN auth gate for cloud mode** — desktop no longer sends full_sync until mobile provides correct PIN over encrypted channel. Prevents unauthorized data access via room code guessing
- **Bounded relay channels** — relay server now uses bounded mpsc channels (128 capacity) with backpressure. Slow or malicious clients get disconnected instead of consuming unlimited memory
- **Join rate limiting** — relay limits join attempts to 10 per minute per IP (governor GCRA). Prevents room code brute-force attacks
- **Command injection prevention** — `create_scheduled_task` now escapes single quotes in crontab entries and validates file extensions (.sh/.bash on Unix, .ps1 on Windows)
- **SSRF prevention** — `fetch_url` now requires HTTPS URLs and blocks private IP ranges (localhost, 10.x, 172.16-31.x, 192.168.x, link-local, IPv6 loopback)

**Medium Priority Fixes:**
- **CORS hardening** — relay server uses split routing: `/health` gets restrictive CORS, `/ws` allows WebSocket upgrades from any origin
- **Public key removed from QR** — desktop public key no longer encoded in QR URL; exchanged securely via relay protocol only
- **Key validation** — relay validates all public keys are valid base64 decoding to exactly 32 bytes before storing
- **Log redaction** — relay redacts room codes in log output (shows only prefix)
- **Room code retry limit** — code generation loop bounded to 100 attempts with proper error on exhaustion
- **Event listener leak fix** — `connectRelay()`/`connectRemote()` unsubscribe functions now properly stored and called on disconnect
- **Nonce overflow guard** — both desktop and mobile throw/disconnect if nonce counter reaches MAX_SAFE_INTEGER

**Other Fixes:**
- **Key material zeroing** — crypto session `destroy()` fills secret keys and shared secrets with zeros before nulling
- **Mobile auth screen gating** — PIN entry hidden until encrypted tunnel established ("Establishing secure connection..." shown while key exchange completes)
- **LAN expose default** — `exposeOnNetwork` now defaults to `true` so LAN mode works out of the box
- **Better relay error messages** — cloud mode shows helpful error when relay server is unavailable

---

## v0.8.1 — March 5, 2026

### New Feature: Cloud Relay — Remote Access from Anywhere (GitHub Issue #14)
- **Cloud relay mode** — connect to your ATM desktop from anywhere in the world, not just the same WiFi. Turn on "Cloud" mode in Settings, get a room code, enter it on your phone — it just works
- **End-to-end encryption** — all messages between desktop and phone are encrypted with X25519 ECDH key exchange + XSalsa20-Poly1305 authenticated encryption. The relay server never sees plaintext
- **Standalone relay server** — new `relay/` Rust crate: a lightweight WebSocket relay that forwards opaque encrypted blobs between desktop and mobile. Runs on `atm-relay.datafying.com`
- **Room code system** — 8-character base58 room codes (e.g., `ATM-X7K3mP`) with 5-minute TTL for joining and 30-minute idle timeout
- **QR code for instant pairing** — Settings panel shows a scannable QR code encoding the relay URL, room code, and desktop public key. Scan on phone to connect instantly
- **LAN/Cloud mode toggle** — new mode selector in Settings panel. LAN mode unchanged; Cloud mode uses the encrypted relay. Switch freely between modes
- **Custom relay URL** — advanced option to point at a self-hosted relay server instead of the default

### Security
- E2E encryption using tweetnacl-js (X25519 + XSalsa20-Poly1305, audited library)
- Nonce space partitioned by role (desktop=0x01, mobile=0x02) to prevent nonce collisions
- Relay server rate limiting: per-IP connection limits, room creation throttling, message rate limiting
- Room codes use cryptographically random base58 characters
- Relay never stores data to disk, never logs message content

### Technical
- New Rust crate: `relay/` with axum 0.8, dashmap, governor rate limiting
- New Rust module: `src-tauri/src/remote/relay_client.rs` — outbound WSS client to relay
- New Tauri commands: `connect_to_relay`, `disconnect_from_relay`, `get_relay_status`, `send_to_relay`
- New TypeScript class: `CryptoSession` in `remote-sync.ts` for E2E encryption
- Updated `remote-sync.ts` with `initRelay()`, dual-mode broadcasting, encrypted message handling
- Updated `ui-store.ts` with `relayStatus`, `connectRelay()`, `disconnectRelay()`
- Updated `SettingsPanel.tsx` with LAN/Cloud toggle, room code display, QR code
- Updated mobile client `app.js` with room code entry, relay WebSocket, E2E crypto
- Added `tweetnacl` and `tweetnacl-util` npm dependencies
- Added `tokio-tungstenite` Cargo dependency for outbound WSS
- Deployment files: Dockerfile, systemd service, Caddyfile for relay server

---

## v0.8.0 — March 4, 2026

### New Feature: Remote Access from Mobile (GitHub Issue #14)
- **Remote control from any phone** — access and manage your agent teams from iPhone or Android using your phone's browser. No app install required
- **Embedded HTTPS server** — a secure web server runs inside ATM with auto-generated TLS certificates. Scan a QR code from the Settings panel to connect your phone
- **PIN-based authentication** — 6-digit server-generated PIN displayed on desktop, entered on phone. Rate limited with lockout after 5 failed attempts
- **Real-time sync via WebSocket** — changes on desktop instantly appear on mobile and vice versa. Full bidirectional state synchronization
- **Mobile-optimized tree view** — collapsible card-based hierarchy with color-coded nodes, search, kind filters, breadcrumb navigation, and pull-to-refresh
- **Remote editing** — edit agent names, prompts, tags, and variables directly from your phone
- **Pipeline deployment** — trigger pipeline deploys from mobile with real-time status updates
- **Optimistic locking** — conflict detection with version numbers prevents silent data loss when editing from multiple devices simultaneously
- **Secret redaction** — API keys and passwords are automatically masked (****xxxx) in remote responses to prevent leaking secrets over the network
- **Session management** — up to 2 concurrent remote sessions with 30-minute idle timeout. Sessions auto-expire and PINs regenerate after each successful auth
- **Settings panel integration** — new Remote Access section in Settings with enable/disable toggle, QR code display, PIN code, port configuration, and network exposure control

### Security
- Auto-generated self-signed TLS certificates (HTTPS only, no plaintext)
- CORS origin validation on all endpoints
- Bearer token authentication for API endpoints
- WebSocket origin checking
- Default bind to 127.0.0.1 (localhost only) — explicit opt-in required for LAN exposure
- Server OFF by default — only starts when user enables it

### Technical
- New Rust modules: `server/` with auth.rs, bridge.rs, server.rs, state.rs, ws.rs, qr.rs
- Cargo dependencies: axum 0.8, axum-server 0.7 (TLS), tokio, tower-http, rcgen, qrcode, image
- New TypeScript types: `src/types/remote.ts` with full Zod schema validation
- New service: `src/services/remote-sync.ts` — WebSocket sync service with echo loop prevention
- Tree store integration: `initRemoteSync()` with node diff broadcasting and remote command handling
- UI store integration: `remoteConfig`, `connectRemote()`, `disconnectRemote()`
- Mobile web client: vanilla HTML/CSS/JS SPA served as static files from `remote-ui/`
- Mobile tree visualization: `src/components/remote/MobileTreeView.tsx`
- Settings panel: new Remote Access section with QR code, PIN display, and configuration

---

## v0.6.2 — February 25, 2026

### Bug Fix: Multi-Select Drag
- **Multi-node drag works correctly** — selecting 4+ nodes with Ctrl+Click then dragging now moves all selected nodes together. Previously only the clicked node moved because React Flow's internal `selected` state wasn't synced with ATM's multi-select tracking
- **Selection state sync** — `multiSelectedNodeIds` from ui-store is now synced to React Flow's `node.selected` property, enabling built-in multi-drag behavior
- **Filtered selection changes** — React Flow's automatic selection changes are filtered out to prevent conflicts with manual Ctrl+Click selection
- **Proximity reparenting skipped for multi-drag** — drag-drop reparenting is disabled when dragging multiple nodes to prevent accidental reparenting

### New Feature: Ctrl+Z Undo for Position Moves
- **Position undo** — pressing Ctrl+Z restores nodes to their previous positions after a drag move
- **Undo stack** — up to 20 moves are tracked, including multi-select drags and group drags with children
- **Escape clears selection** — pressing Escape now also clears multi-select (previously only cleared single select)

---

## v0.6.1 — February 25, 2026

### Pipeline Deploy Overhaul: Inter-Step Handoffs
- **Step handoff summaries** — each step in a pipeline now writes a handoff file (`step-{N}-output.md`) summarizing what was accomplished, key decisions, and outputs. The next step's primer automatically instructs Claude to read the previous step's handoff, so team 2 knows exactly what team 1 did
- **Previous/Next step context** — each step's primer now includes a "Previous Steps" section (with objectives of all completed steps) and a "Next Steps" section (what comes after), giving each team full pipeline awareness
- **Error handling** — deploy scripts now check exit codes after each step. If a step fails, subsequent steps are skipped and the pipeline reports which step failed
- **Status tracking** — a `status.json` file is written to the pipeline directory, tracking each step's status (pending/running/completed/failed) with timestamps. Updated in real-time as steps execute
- **Better terminal output** — timestamps on every step, elapsed time per step, total pipeline duration, clear pass/fail summary with visual formatting

### Technical
- `deployPipeline` method in tree-store.ts completely rewritten with handoff architecture
- Primer template now includes `## Previous Steps`, `## Next Steps`, and handoff read/write instructions
- Deploy scripts (PS1 + bash) now track `$LASTEXITCODE` / `$?` and skip remaining steps on failure
- `status.json` written to `.aui/pipeline-{slug}/` with per-step timing data

---

## v0.6.0 — February 25, 2026

### New Feature: Typed Variables with Sensitive Masking
- **Variable types** — variables now have a type: Text, API Key, Password, or Note. Each type has distinct visual styling with color-coded left borders (orange for API keys, red for passwords, purple for notes)
- **Sensitive value masking** — API Key and Password variables are masked by default with `****` display. An eye toggle button reveals the actual value — identical UX to the API key field in Settings
- **Note variables** — a new "Note" type renders as a multi-line textarea instead of a single-line input, perfect for context, instructions, or documentation
- **Shared VariableEditor component** — all editors (Team, Agent, Pipeline, Root) now use a unified variable editing component with consistent behavior
- **Quick-add buttons** — instead of a generic "+ Add Variable", there are now four buttons: `+ Text`, `+ API Key`, `+ Password`, `+ Note` for fast type-specific creation

### New Feature: Variables on Pipeline and Root Nodes
- **Pipeline variables** — Project Manager nodes now have a Variables section between Steps and Deploy. Variables are included in every step's deployment primer
- **Global variables** — the root "You" node now has a "Global Variables" section. These variables are passed to every team and pipeline during deployment, making them ideal for org-wide API keys, endpoints, or config
- **Deploy primer enrichment** — all primers (team deploy, pipeline deploy, skill exports) now include typed variable annotations like `[api-key] OPENAI_KEY: sk-...` for clarity

### New Feature: Version Display in Settings
- **Settings panel now shows the current ATM version** (e.g., "ATM v0.6.0") at the top of the panel, so users always know which version they're running

### Technical
- New `VariableKind` type: `"text" | "api-key" | "password" | "note"`
- `NodeVariable` interface now has a `type: VariableKind` field
- New shared component: `src/components/inspector/VariableEditor.tsx`
- Backwards-compatible migration: old variables without a `type` field default to `"text"` on load
- All primer generation (team, pipeline, skill export) updated to include variable types
- SettingsPanel shows version info badge

---

## v0.5.1 — February 25, 2026

### New Features
- **"Move to..." context menu** — right-click any node on the canvas to see a "Move to..." submenu listing all valid parent targets (Root, teams, and pipelines). Quickly reparent nodes without drag-and-drop. Excludes the node's current parent and its own descendants to prevent circular hierarchies

### Technical
- Added submenu support to `ContextMenu` component — items with a `children` array render as hover-expandable submenus with smooth open/close transitions
- Context menu "Move to Root" replaced with dynamic "Move to..." submenu that lists all groups and pipelines as reparenting targets

---

## v0.5.0 — February 25, 2026

### Rebrand: AUI → ATM (Agent Team Manager)
- **App renamed to ATM** — "Agent Team Manager" replaces "Agent UI" across the entire app
- **Window title** — now reads "ATM — Agent Team Manager"
- **Toolbar logo** — shows "ATM" with "Agent Team Manager" subtitle
- **Welcome screen** — updated to "Welcome to ATM"
- **Tauri config** — product name, identifier, and description updated
- **Package name** — `aui` → `atm` in package.json and Cargo.toml
- Note: `.aui/` config directory unchanged for backward compatibility

### New Feature: Project Manager (Pipeline Nodes)
- **New node type: Pipeline** — a sequential pipeline that runs teams one after another, with each step having its own deploy prompt
- **Magenta visual identity** — pipeline nodes appear in magenta (#d946ef) with dashed borders and a "PROJECT MGR" badge
- **Step count display** — pipeline nodes show "N steps" on the canvas, similar to how teams show agent count
- **PipelineEditor** — full inspector panel editor with:
  - Name and description fields (auto-save)
  - Ordered step list with numbered badges
  - Team dropdown per step (same team can appear multiple times)
  - Per-step deploy prompt textarea
  - Move Up/Down, Duplicate, and Delete controls per step
  - "Play All" button to deploy the entire pipeline sequentially
  - "Schedule" button to set up recurring pipeline runs
- **Sequential deployment** — "Play All" generates a primer for each step and creates a single script that runs each team's Claude session in sequence (step 1 finishes → step 2 starts → ...)
- **Pipeline scheduling** — pipelines appear in the Schedule panel's team selector with a "[Pipeline]" prefix; per-step prompts are used instead of a single deploy prompt
- **Canvas context menu** — right-click on empty canvas now shows "New Team" and "New Project Manager" (Skill option removed)
- **Create dialog** — root-level options are now "Team", "Agent", "Project Manager" (Skill removed from root); inside a team: "Agent" only

### Technical
- New `PipelineStep` interface: `{ id, teamId, prompt }`
- Added `pipelineSteps: PipelineStep[]` field to `AuiNode`
- New `NodeKind` value: `"pipeline"`
- Tree metadata groups array now stores `kind` and `pipelineSteps` for pipeline nodes
- New store methods: `createPipelineNode`, `updatePipelineSteps`, `deployPipeline`
- New component: `src/components/inspector/PipelineEditor.tsx`
- Deploy script generation produces `.ps1` (Windows) and `.sh` (macOS/Linux) scripts in `.aui/pipeline-{slug}/`

---

## v0.4.2 — February 25, 2026

### Bug Fixes
- **Fixed "Failed to fetch" on Generate Teams** — API fetch errors now have proper try-catch handling with distinct messages for network errors, invalid API keys (401), and rate limits (429) instead of a generic "Failed to fetch" TypeError
- **Fixed collapsed group drag breaking child positions** — when a collapsed team is dragged, hidden children's saved positions are now offset by the drag delta so they maintain their relative positions when expanded. Previously, children would snap back to their old absolute positions
- **Fixed Generate not respecting team/agent counts** — the AI prompt now uses "EXACTLY N teams" and "EXACTLY N agents" language with strict requirements instead of "Max N" which let the LLM return fewer

### Improvements
- **Updated welcome message** — new blank layouts now show "Click the You node to get started" instead of the outdated "Double-click the canvas" instruction, and auto-selects the root node so the inspector opens immediately
- **README "At a Glance" table** — added a compact feature summary table for quick scanning by GitHub visitors

---

## v0.4.1 — February 25, 2026

### New Features
- **Node position persistence** — drag nodes to custom positions and they stay. Positions are saved per-layout and survive collapse/uncollapse, app restarts, and layout switches. Group drags save all children positions too
- **Removed duplicate generate button** — consolidated the "Generate NxN" and "Generate from Description" buttons into a single "Generate Teams" button that uses the smarter description-aware prompt
- **Removed Save buttons** — all editors now rely on autosave (from v0.4.0). Save buttons removed from RootEditor, AgentEditor, SkillEditor, and GroupEditor. Validate and Discard buttons remain where applicable

### Technical
- New tree store methods: `saveNodePosition`, `saveNodePositions`, `clearNodePosition` for position CRUD
- `layout.ts` `layoutNodes` now accepts `savedPositions` parameter — prefers saved positions over dagre-calculated defaults
- `TreeCanvas.tsx` uses ref pattern for saved positions to avoid re-layout loops on position saves
- `onNodeDragStop` saves positions for single nodes and group drags, clears on reparent
- Position cleanup in `removeNodeFromCanvas` when deleting nodes
- Removed `savedAt` state and `setSavedAt` calls from all autosave editors (dead code after button removal)

---

## v0.4.0 — February 25, 2026

### New Features
- **Autosave across all editors** — changes to any node (You, Team, Agent, Skill) now save automatically after 800ms of idle typing and on click-away. No more losing changes because you forgot to hit Save. Manual Save buttons remain for explicit saves
- **Blank layout creation** — the Layouts dropdown now has a "+ New Blank Layout" button that creates a fresh canvas with only the "You" node, perfect for building a new org structure from scratch without existing clutter
- **Edge insert button** — hover over any edge (connection line) between two nodes to reveal a "+" button. Click it to insert a new node at that position in the hierarchy, making it easy to add nodes between existing parent-child pairs

### Bug Fixes
- **Fixed team deletion spawning random nodes** — removing a team node from the canvas (via the X button) no longer causes its child agents to appear at root level. Children are now recursively removed with the team, keeping the canvas clean
- **Fixed blank layout inheriting previous description** — new blank layouts now start with a truly fresh root node instead of carrying over the previous layout's "You" node description

### Technical
- New `src/hooks/useAutosave.ts` — reusable hook with debounce, skip-on-init, and flush-on-unmount for all editor components
- New `src/components/tree/InsertEdge.tsx` — custom React Flow edge component with hover-activated insert button
- `removeNodeFromCanvas` now recursively removes all descendants when removing a group node (teams), while preserving the reparent behavior for individual nodes
- `createBlankLayout` added to tree store — saves current layout, creates empty metadata, switches to blank canvas
- All 4 editor components (RootEditor, AgentEditor, SkillEditor, GroupEditor) wired with `useAutosave` hook

---

## v0.3.9 — February 24, 2026

### QA & Polish
- **Full QA audit** — comprehensive 6-area quality audit covering canvas nodes, inspector panel, layouts system, toolbar/navigation, schedule/settings, and data/build integrity. 82/83 checks passed
- **SchedulePanel toolbar overlap fixed** — panel now uses `var(--toolbar-height)` for top offset, consistent with Settings and Catalog panels
- **Consistent `@/` path aliases** — converted all remaining relative `../` imports in services and utilities to use the `@/` path alias for codebase consistency (agent-parser, file-scanner, file-watcher, file-writer, settings-parser, skill-parser, skill-scanner, validation)

### Verified
- Canvas: all 12 visual checks pass (badges, colors, tints, sub-agent detection, hover actions, collapse/expand, glow/shadow)
- Inspector: all 11 editor checks pass (routing, deploy section, schedule button, sub-agent badges, save/discard, skills, variables)
- Layouts: all 22 CRUD + edge-case checks pass (types, service, store, dropdown UI, rename, delete guards)
- Toolbar: all 11 navigation checks pass (3-section layout, button order, panel mutual exclusivity, z-index)
- Schedule: all 23 cron/schtasks/settings checks pass (Rust commands, repeat mapping, time formats, script generation, toggle/delete)
- Data layer: all 13 store/type/build checks pass (interfaces match implementations, no circular imports, tsc + vite build clean)

---

## v0.3.8 — February 24, 2026

### New Features
- **Multiple layouts** — save, switch, rename, and delete named canvas layouts. Each layout preserves the full tree hierarchy, groups, and node positions independently
- **Layouts dropdown in toolbar** — a new dropdown in the toolbar center lets you switch between saved layouts, create new ones with a name input, rename via inline editing, and delete layouts on hover
- **Layout persistence** — layout data stored as individual JSON files in `.aui/layouts/` with an `index.json` manifest tracking the active layout and metadata
- **Auto-default layout** — on first load, the current tree state is automatically saved as a "Default" layout so the system is always initialized

### Enhancements
- **Toolbar button reorder** — right-side buttons now read Catalog, Schedules, Settings (left to right) for better workflow priority. Create (+) and Layouts dropdown are centered

### Technical
- New `Layout` and `LayoutIndex` types in `src/types/aui-node.ts`
- New `src/services/layout-service.ts` — full CRUD for layout files via `@tauri-apps/plugin-fs`
- New `src/components/common/LayoutsDropdown.tsx` — dropdown UI with rename, delete, and save-as-new
- Tree store extended with `loadLayouts`, `saveCurrentAsLayout`, `switchLayout`, `deleteLayout`, `renameLayout` actions
- Layout switching auto-saves the current layout before restoring the target layout's tree metadata

---

## v0.3.7 — February 24, 2026

### Documentation
- **README overhaul** — rewrote the hero section with a clear value proposition emphasizing token efficiency and zero-overhead deployment
- **Claude Code URL install** — Quick Start now leads with a one-line paste-the-URL install option for Claude Code users, with manual clone as the alternative
- **Updated feature sections** — Interactive Org-Chart Canvas and Cron Job Scheduler sections rewritten with accurate details, node type table, and OS-level scheduling docs
- **Sub-agent documentation** — added sub-agent node type to the canvas feature section with color and badge details
- **Project structure updated** — added missing files (scheduler.ts, skill-scanner.ts) and reorganized to match the current codebase
- **Content cleanup** — removed outdated sections and polished overall structure for consistency

---

## v0.3.6 — February 24, 2026

### New Features
- **Real task scheduler backend** — schedule jobs now create actual OS-level scheduled tasks via Rust commands: Windows Task Scheduler (`schtasks.exe`) on Windows, crontab on macOS/Linux. Three new Tauri commands: `create_scheduled_task`, `list_scheduled_tasks`, `delete_scheduled_task`
- **Repeat options for schedules** — replaced raw cron expression input with a user-friendly repeat picker (Once, Hourly, Daily, Weekly, Custom cron). Time picker for selecting run time. Schedules panel shows all jobs with human-readable repeat labels
- **Custom AUI app icon** — replaced the default Tauri icon with a custom-designed AUI logo across all icon sizes (ICO, ICNS, PNG) for Windows, macOS, and Linux

### Enhancements
- **Root node badge shows "YOU"** — the root node on the canvas now displays a "YOU" badge instead of the generic kind label, making the org tree more intuitive
- **Lighter sub-agent color** — sub-agent nodes now use a softer blue (`#a5d6ff`) for better visual contrast against parent agents
- **One-command install in README** — Quick Start section now leads with a four-line clone-to-running-app snippet, plus collapsible platform-specific setup guides for Windows, macOS, and Linux

### Technical
- Added `create_scheduled_task`, `list_scheduled_tasks`, `delete_scheduled_task` Rust commands in `src-tauri/src/lib.rs`
- New `src/services/scheduler.ts` service for schedule persistence and OS task management
- SchedulePanel rewritten with repeat picker, time selector, and live job listing from OS

---

## v0.3.5 — February 24, 2026

### Enhancements
- **Export/Import moved to Settings panel** — the Export Tree and Import Tree buttons are now in a new "Data" section inside the Settings panel (between Preferences and Advanced), keeping the toolbar clean
- **Schedule button on team editor** — replaced the Export and Generate Skill Files buttons in the team Deploy section with a single "Schedule" button that opens the SchedulePanel directly
- **Sub-agent visual distinction** — agents nested under other agents (sub-agents) now display with a lighter blue color (`#58a6ff`), "SUB-AGENT" badge, and distinct background tint on the canvas, making the hierarchy visually clear at a glance
- **Sub-agent badges in inspector** — the agent list inside the team editor now shows "sub-agent" badges (lighter blue) for children of member-agents

### Cleanup
- Removed standalone "Export" and "Generate Skill Files" buttons from team editor (Deploy already calls `generateTeamSkillFiles` internally)
- Removed Export/Import buttons and related handlers from the Toolbar
- Toolbar reverted to clean button set: +, Settings, Schedules, Catalog

---

## v0.3.4 — February 24, 2026

### Bug Fixes
- **Deploy terminal stays open** — switched to `cmd /c start` with `raw_arg` for fully independent process detachment, so the deploy terminal no longer closes unexpectedly
- **Cleared CLAUDECODE env var in deploy scripts** — prevents nested session detection error when deploying from within an existing Claude Code session
- **Primer passed as file-read instruction** — deploy primer is now read from file instead of being passed as a 9.3KB CLI argument, fixing PowerShell argument corruption from 50 unescaped double quotes shattering the primer into 94 separate arguments
- **Node name single-quote escaping** — deploy scripts (both PS1 and bash) now properly escape single quotes in node names
- **Skill names resolve correctly in deploy primer** — primer now uses skillNameCache to resolve display names instead of falling back to raw hash IDs
- **Added Skill tool invocation instructions to primer** — deployment primer now includes instructions for agents to invoke skills

### Enhancements
- **Richer generated skill files** — skill file generation now produces thorough, opinionated content with domain-specific guidelines, quality standards, and detailed protocols (benchmarked against frontend-design quality)
- **Reordered team editor** — sections now flow: Name/Description, Deploy, Skills & Variables, Agents, Save
- **Canvas X button soft-removes nodes** — the X button on canvas nodes now removes them from the canvas without deleting files from disk (renamed to "Remove from Canvas")
- **Combined Skills & Variables** — Skills and Variables merged into a single collapsible section in the team editor
- **Generate with AI moved inside Agents section** — reduces top-level clutter in the team editor

---

## v0.3.2 — February 24, 2026

### Bug Fixes
- **Deploy terminal stays open** — fixed PowerShell `-File` flag silently ignoring `-NoExit`, causing the deploy terminal to flash and close. Switched to `-Command` invocation so the terminal persists and shows output/errors.
- **Assigning skills no longer creates phantom nodes** — fixed bug where assigning a skill to a team or root node created a visible orphan node on the canvas. Skills are now tracked in a lightweight name cache instead of being added as tree nodes.

### Enhancements
- **Collapsible sections on team editor** — the team/agent inspector now matches the root node's collapsible organization. Deploy stays prominent at the top; Variables, Assigned Skills, Generate with AI, and Agents are each collapsible sections with disclosure triangles and item counts.

### Technical
- Added `skillNameCache` to tree store for resolving skill display names without adding visible nodes
- OrgNode skill name resolution now checks: tree nodes → name cache → raw ID fallback
- Rust `open_terminal` uses `-Command` instead of `-File` on Windows for proper `-NoExit` behavior

---

## v0.3.1 — February 24, 2026

### Bug Fixes
- **Deploy now opens a visible terminal** — replaced Tauri shell plugin approach (which hardcodes `CREATE_NO_WINDOW`) with a Rust-side `open_terminal` command using `CREATE_NEW_CONSOLE`. Deploy now reliably opens a visible PowerShell window on Windows, Terminal on macOS, or any available emulator on Linux.
- **Import from GitHub URL works** — fixed "Failed to fetch" error by routing URL imports through a Rust-side `fetch_url` command, bypassing webview CORS/CSP restrictions.
- **Skill names display correctly on nodes** — fixed issue where skill tags on canvas nodes showed hash IDs instead of human-readable names. Skills are now auto-added to the tree store when assigned (#7).

### Enhancements
- **Sub-agent labels** — agent nodes nested inside teams now show "sub-agents" instead of "agents" in their child count label (#8)
- **Restructured root node inspector** — "Owner" section renamed to "Company / Project Name" with better placeholder text. Global Skills and Teams are now collapsible sections with disclosure triangles. Generate with AI moved inside the Teams section (#9)
- **Removed Chat panel** — the non-functional Chat feature has been removed from the toolbar and app since CLI-based chat cannot run inside Tauri's webview (#10)
- **Removed AI gradients** — all purple-to-blue and orange gradient buttons replaced with flat solid colors (`var(--accent-purple)`, `var(--accent-orange)`) per the frontend-design skill's guidance against generic AI aesthetics
- **39 skills installed** — downloaded and installed the full Anthropic skills pack plus community skills (algorithmic-art, canvas-design, frontend-design, mcp-builder, skill-creator, ios-simulator, playwright, d3js, web-asset-generator, and more)

### Technical
- Added `open_terminal` Rust command with platform-specific terminal launching (CREATE_NEW_CONSOLE on Windows)
- Added `fetch_url` Rust command for server-side HTTP fetching (bypasses webview restrictions)
- Overlay panels (Settings, Schedules, Catalog) are now mutually exclusive — opening one closes the others
- Toolbar reorganized: Settings, Schedules, Catalog now directly accessible (Chat removed)

---

## v0.3.0 — February 24, 2026

### UI Overhaul
- **Refined color palette** — blue-tinted dark backgrounds (#0d1117, #151b23, #1c2333) replace the old purplish tones for a more professional, modern look
- **Desaturated accents** — orange (#f0883e), green (#3fb950), purple (#8b5cf6), gold (#d29922), red (#f85149) are all slightly desaturated for less visual noise
- **Unified AI gradient** — all AI-powered buttons now use a consistent purple-to-blue gradient (`#8b5cf6 → #4a9eff`) instead of the old purple-only gradient
- **Consistent input styling** — all input fields now use CSS variables with `border-radius: 6px` and smooth `transition: border-color 0.15s`
- **Toolbar subtitle** — "Agent UI" subtitle appears next to the AUI logo for clarity
- **Better welcome screen** — improved empty state with keyboard shortcut hints and a subtitle

### UX Improvements
- **Deploy moved to top** — the Deploy section now appears at the top of the team inspector panel for faster access (was buried at the bottom)
- **Renamed "Auto-Fill"** to **"Generate with AI"** across all editors for clearer intent
- **Export button** redesigned as an outlined secondary button (was a filled gradient) to reduce visual competition with Deploy
- **Refined button hierarchy** — primary actions (Deploy, Save) are filled, secondary actions (Export, Discard) are outlined, tertiary actions (Generate Skill Files) are dashed
- **Chat, Settings, Schedules promoted to toolbar** — direct 1-click access from the toolbar instead of buried in the Menu (now renamed "Catalog")
- **"Menu" renamed to "Catalog"** — the ContextHub overlay now opens via a "Catalog" button, better reflecting its purpose as a skill/agent/team browser
- **Mutual-exclusive overlays** — opening Chat, Settings, Schedules, or Catalog automatically closes any other open overlay to prevent stacking
- **Cleaner Catalog header** — removed redundant Chat/Settings/Schedules buttons from the Catalog utility row; only Refresh and Save Plan remain
- **Inspector panel widened** to 480px (was 420px) for more comfortable editing

### Keyboard Shortcuts
- `Ctrl+Shift+D` — deploy the currently selected team
- `Ctrl+Enter` — deploy from the deploy prompt textarea
- `Ctrl+I` — toggle the inspector panel
- Shortcuts are suppressed when typing in input fields

### Technical
- Added new CSS variables: `--bg-elevated`, `--text-tertiary`, `--border-hover`, `--accent-danger`, and radius tokens (`--radius-sm/md/lg/xl`)
- Updated team colors in grouping utility to match the new desaturated palette
- All hardcoded color values replaced with CSS variables where applicable

---

## v0.2.2 — February 23, 2026

### Bug Fixes
- Fixed deploy failing with "Make sure 'claude' is in your PATH" — root cause was Tauri v2's shell plugin hardcoding `CREATE_NO_WINDOW` on all spawned processes, making every terminal invisible. Deploy now uses `ShellExecuteExW` via the shell `open()` API with a `.bat` launcher, which correctly opens a visible PowerShell window.
- Fixed Windows path handling in deploy scripts — paths now use backslashes in generated `.ps1` and `.bat` files for proper PowerShell and cmd.exe compatibility.

### Improvements
- Moved Collapse/Expand toggle from the toolbar to the floating search bar for a cleaner, more subtle placement.
- Improved deploy error messages — errors now show actual failure details instead of generic "Failed" text.

---

## v0.2.1 — February 23, 2026

### Improvements
- Added "Collapse All" / "Expand All" button in the toolbar for quick team management
- Made the entire agent count row on team nodes clickable for expand/collapse (not just the tiny arrow)
- Moved "Open Settings File" from the main menu into the Settings panel under a new "Advanced" section
- Fixed deploy to open a visible terminal window (was spawning invisible child processes)
- Cleaned up leftover references to removed features

### Documentation
- Added comprehensive USAGE.md user guide (479 lines)
- Added CONTRIBUTING.md for open-source contributors
- Added MIT LICENSE
- Enhanced README with badges, "Why AUI?" section, and contributing link
- Created 6 roadmap issues on GitHub
- Added 15 GitHub topics for search discoverability

---

## v0.2.0 — February 23, 2026

### Major Features

#### Variables System
- Added key-value variable pairs (API keys, URLs, configs) to both teams and agents
- Variables are saved with your project data and persist across sessions
- Full editing UI in both team and agent editors with name/value fields
- Variables are included in skill exports and deployment primers

#### Claude API Integration
- Connects to the Anthropic Messages API for AI-powered features
- API key is configured via the Settings panel
- Powers: Generate Description, Auto-Fill Teams, and Auto-Fill Agents
- Uses Claude Haiku for fast, cost-effective generation

#### AI-Powered Generate Description
- Purple "Generate" button on every agent and team description field
- Uses Claude API to generate a contextual description based on the node's name
- Understands whether it's a team or an agent within a team

#### Auto-Fill with AI
- **Root node:** Select number of teams and agents-per-team, click "Auto-Fill" to have Claude generate the entire org structure
- **Team nodes:** "Auto-Fill Agents" button with count selector generates agents for that specific team
- AI generates contextually appropriate names and descriptions

#### Deploy Team (Revamped)
- Deploy prompt textarea alongside the deploy button — tell the team what to accomplish
- Deploy generates missing skill files (skips existing) and builds a comprehensive primer with all skill file contents included
- **Auto-opens an external terminal** (PowerShell on Windows, Terminal on Mac/Linux) and launches Claude with the full primer already submitted
- Primer includes company context, team overview, global skills, sibling teams, and every agent's full skill file content
- API costs are only for generating descriptions and skill files — deployed team sessions run on the user's own Claude subscription
- Team node gets a "senior manager" skill file; each agent gets their own specialist skill file
- "Generate Individual Skill Files" button for on-demand skill file creation
- Primer saved to `.aui/deploy-primer.md` for reference

#### Comprehensive Skill Export
- Completely rewritten skill export — now generates fully-detailed SKILL.md files
- Includes: company context, global skills, team skills (with inline content), team variables table, detailed agent profiles (model, tools, permissions, skills, variables, sub-agents), coordination rules, deployment instructions, and success criteria
- Proper Claude Code team mode deployment instructions

#### Settings Panel
- API key input with show/hide toggle
- Color pickers for Team, Agent, and Accent colors
- Auto-save preference toggle
- Settings persist across sessions; accent color applies to the UI in real time

#### Delete Node on Canvas
- Subtle gray X button on every node (team, agent, skill, etc.)
- Appears on hover, opens delete confirmation dialog
- The root (Human) node cannot be deleted

#### Cron Job Manager
- Schedule teams for recurring deployment
- Cron expression editor with prompt field
- View/delete scheduled jobs
- Schedules persist across sessions

#### Multi-Select Generate Description
- Hold Ctrl and click multiple nodes to select them
- "Generate All Descriptions" button appears when multiple nodes selected
- Generates descriptions for all selected nodes in parallel

#### Smart Team Generation
- Fill in your root node description with your company/project goals
- Set global skills and team/agent counts
- "Generate Teams to Meet Goals" creates teams specifically designed to achieve your described objectives

### UI Changes

#### Toolbar Simplified
- Toolbar now shows only: AUI logo, + button, Menu button, node count
- Chat, Refresh, Save Plan, and Settings buttons moved into the Menu

#### Menu Enhanced
- Added utility row: Refresh, Save Plan, Settings, Schedules buttons
- Added Chat button to open Claude CLI chat
- Added "Open Settings File" option

#### Multi-Select Visual Feedback
- Ctrl+click nodes to multi-select (purple border highlight)
- Floating action bar shows selected count with "Generate All Descriptions" button
- Clear selection with X button or click empty canvas

#### Color Scheme
- Teams are blue (#4a9eff), Agents are orange (#ff9800)
- Consistent across all views: canvas nodes, editors, menu, and mini-map

#### Naming
- "Member" renamed to "Agent" everywhere
- "Context Hub" renamed to "Menu" in toolbar

### Technical

#### New Files
- `src/services/claude-api.ts` — Anthropic Messages API client
- `src/components/schedule/SchedulePanel.tsx` — Cron job manager UI

#### New Store Actions
- `generateTeamSkillFiles(teamId)` — creates individual SKILL.md for team manager + each agent
- `toggleMultiSelect(nodeId)` / `clearMultiSelect()` — multi-select state management
- `toggleSchedule()` — schedule panel toggle

#### Type Changes
- `AuiNode` now has `variables: NodeVariable[]`
- `TreeMetadata.groups` now persists `variables`
- New `NodeVariable` interface: `{ name: string; value: string }`
- `UiState` now has `multiSelectedNodeIds: Set<string>` and `scheduleOpen: boolean`

#### Shell Configuration
- Tauri shell permissions scoped to: `claude`, `powershell`, `cmd`, `bash`, `open`
- Deploy opens an external terminal automatically (PowerShell on Windows, Terminal on Mac/Linux)
- Note: Deploy and CLI features require the Tauri runtime (not browser-only mode)

### Bug Fixes
- Settings no longer appears as a node in the tree
- Fixed CLI availability detection with clearer error messages
- Fixed auto-fill not triggering correctly in certain conditions
- Inspector panel now has a close button when no node is selected
- Skill file generation skips files that already exist (no overwriting)

---

## v0.1.0 — Initial Release

### Core Features

- **Project scaffold** — Tauri + React + TypeScript application structure with Vite bundling
- **Type system** — Core data types for teams, agents, skills, and organizational trees
- **Services layer** — File I/O and tree persistence services for loading and saving project data
- **State management** — Zustand-based stores for application state, tree data, and UI state
- **Tree canvas** — Interactive node-based canvas for visualizing and arranging teams and agents
- **Inspector panel** — Side panel for viewing and editing properties of the selected node
- **Menu** — Centralized hub for accessing project context, global skills, and navigation
- **Basic file parsing** — Read and parse skill files from the local filesystem
