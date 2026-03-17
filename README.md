[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Built with Tauri](https://img.shields.io/badge/Built_with-Tauri_v2-blue?logo=tauri)](https://v2.tauri.app/)
[![React 19](https://img.shields.io/badge/React-19-61DAFB?logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![Claude AI](https://img.shields.io/badge/Powered_by-Claude_AI-6B4FBB)](https://www.anthropic.com/claude)

# ATM -- Agent Team Manager

**Your Claude agents are scattered across dozens of markdown files and you can't remember which one writes Python tests.**

ATM turns your `.claude/` folder from a graveyard of forgotten agent definitions into an org chart you can actually use. Drag-drop to build teams, click once to deploy 100+ agents in parallel, schedule them to run on cron. It's the missing UI layer between "I wrote some agent configs" and "I have an AI team that runs while I'm away."

---
### Video Demo
https://youtu.be/YhwVby25sJ8
---

## What You're Doing Right Now

You've got 15 Claude agents scattered across `.claude/agents/`. Every time you need to run them:

1. **Open the markdown file** in your editor
2. **Hand-edit the YAML frontmatter** -- was it `apiKey` or `api_key`? Did you close the quotes?
3. **Copy-paste the same API keys** into three different agent configs
4. **Write a 2000-word deployment primer** from scratch because you're running a team and Claude needs context
5. **Hope you described your org structure clearly enough** that the team lead interprets it correctly
6. **Manually kick off the run** from the terminal
7. **Realize you need daily runs** -- spend 30 minutes fighting with cron or Windows Task Scheduler
8. **Want to chain teams together?** Write another deployment primer explaining what the previous team did

You know the config works because you've run it before. But there's no reusable template. No visual overview. No automation. Just you, your text editor, and a growing collection of agent markdown files you're terrified to touch.

### What ATM Does Instead

- **Drag-drop visual org chart** -- see your entire agent hierarchy at a glance
- **One-click agent creation** -- templates autofill the YAML, you just name it
- **Shared API key management** -- edit once at root, applies everywhere
- **Save deployment configs** -- run the same team setup tomorrow with one click
- **Schedule runs** -- daily SOC reports at 6am, weekly content pipelines on Monday morning, no manual cron
- **Chain pipelines** -- Team A feeds into Team B feeds into Team C, automatically
- **Auto-generated deployment primers** -- ATM writes the 2000-word primer for you

Stop editing YAML at 11pm. Start deploying.

---

## What You Can Do

### Generate Entire Organizations from a Paragraph

Describe your company goals and specify how many teams you need. ATM generates the complete org chart: names, roles, detailed descriptions, proper hierarchy. Generate one agent at a time or batch-generate dozens. Skip the tedious boilerplate and iterate on team composition instead.

### The Org Chart IS Your Team Structure

<img width="1909" height="997" alt="ATM visual org chart" src="https://github.com/user-attachments/assets/40981b99-6cc8-4875-a1b6-ee1817c86df7" />

This isn't a visualization -- it's the real thing. Drag nodes to reparent agents, right-click to move between departments, hover connection lines to insert new roles. Nodes color-code by type: gold for you, blue for teams, orange for agents, magenta for project managers, green for skills. When you deploy, this exact hierarchy deploys.

### Deploy Entire AI Teams in Seconds

Write a one-sentence objective, click Deploy. ATM generates any missing skill files, compiles a complete deployment primer with company context, team structure, skill contents, resolved variables, and coordination rules, then opens your terminal with the Claude CLI already running. No manual file editing, no forgotten context, no copy-paste.

### Run Teams on Autopilot

Schedule any team or pipeline with OS-level scheduling (Windows Task Scheduler or cron on macOS/Linux). Daily, weekly, hourly, or custom intervals. Each execution spawns a fresh terminal with the full deployment primer, even when ATM is closed. Your content pipeline runs at 6am. Your SOC team checks systems every hour. You sleep.

### Chain Teams into Multi-Step Workflows

Project Manager Pipelines let you sequence teams: Research team -> Analysis team -> Writing team, each with its own objective. Play the entire pipeline manually or schedule it. Each step completes before the next begins, with full context handoff.

---

## Real Teams, Running Today

### Crypto Investment Research

A solo crypto investor built a 6-agent research team -- market analysts, risk assessors, portfolio optimizers, and a manager coordinating them. The team processes overnight market movements and delivers a unified investment brief every morning.

<img width="506" height="682" alt="Crypto investment org chart" src="https://github.com/user-attachments/assets/522461e4-9833-43d6-92e5-d19e96bed3ea" />
<img width="1858" height="695" alt="Crypto team canvas" src="https://github.com/user-attachments/assets/80f670af-89fe-40ed-b8ae-09b42856fafa" />

### IT Security Operations (SOC)

A one-person IT consultancy runs an 8-agent SOC team that triages Bitdefender alerts every morning at 6am. Includes a devil's advocate agent that challenges every recommendation before it reaches clients. One person, the analysis depth of a full security team.

<img width="1914" height="1000" alt="SOC team overview" src="https://github.com/user-attachments/assets/6086b73d-632a-4381-8277-d87328460009" />
<img width="1909" height="997" alt="SOC agent details" src="https://github.com/user-attachments/assets/d2d61d82-db38-4dfa-9dc6-e7769aa489f7" />

### Social Media Content Pipeline

A content creator's 7-agent team handles the full lifecycle: Reddit scouts find trending discussions, writers draft posts, tone calibrators ensure brand voice. The pipeline runs weekly on a schedule -- ready-to-publish content every Monday morning, no human intervention.

<img width="468" height="965" alt="Schedule panel" src="https://github.com/user-attachments/assets/5c355b1d-0744-46db-af89-09506693d31c" />

---

### Work on your agent team anywhere!
v0.8 introduces remote capabilities!

<img width="406" height="750" alt="update v0 8 1" src="https://github.com/user-attachments/assets/6fa0167b-1432-4291-afeb-55eae271a05e" />


## Get Running in 60 Seconds

**Download the installer:**

- **Windows**: **[Download ATM-Setup.exe](https://github.com/DatafyingTech/AUI/releases/latest)**
- **macOS**: **[Download ATM.dmg](https://github.com/DatafyingTech/AUI/releases/latest)**

> **macOS users**: ATM is unsigned. Right-click the app and select "Open" the first time, or go to System Settings > Privacy & Security > "Open Anyway."

**First run:**

1. Launch ATM -- it auto-detects your existing Claude Code agents and skills
2. Browse your agent hierarchy on the visual canvas
3. Drag agents into teams, assign skills, set variables
4. Write a short objective, click Deploy, and watch your team go

That's it. No configuration files, no setup wizards.

<details>
<summary><strong>Build from source</strong> (for developers)</summary>

**Fastest way**: Paste this repo URL into Claude Code and let it handle the setup:
```
https://github.com/DatafyingTech/AUI
```

**Manual setup**:
```bash
git clone https://github.com/DatafyingTech/AUI.git
cd AUI
pnpm install
pnpm tauri dev
```

**Prerequisites**:

| Requirement | Version |
|------------|---------|
| Node.js | 18+ |
| pnpm | 9+ |
| Rust | stable |

<details>
<summary>Platform-specific setup</summary>

**Windows**:
- Install [Visual Studio Build Tools 2022](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with "Desktop development with C++" workload
- Install Rust via [rustup-init.exe](https://rustup.rs/)

**macOS**:
```bash
xcode-select --install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**Linux** (Debian/Ubuntu):
```bash
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**Linux** (Fedora/RPM):
```bash
sudo dnf install -y \
  webkit2gtk4.1-devel \
  openssl-devel \
  gtk3-devel \
  libayatana-appindicator-gtk3-devel \
  librsvg2-devel \
  curl wget file gcc make

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Enable cron scheduling support
sudo dnf install -y cronie
sudo systemctl enable --now crond
```

> **Fedora note:** If `libayatana-appindicator-gtk3-devel` is not found, try `libappindicator-gtk3-devel`. If `webkit2gtk4.1-devel` is missing, also install `libsoup3-devel`.

> **Wayland:** ATM supports Wayland natively via gnome-terminal or konsole. If you are running a pure Wayland session (no XWayland), ensure one of these is installed.

</details>

**Build for production**:
```bash
pnpm tauri build
```

**Note**: `pnpm dev` runs frontend only. Use `pnpm tauri dev` for the full desktop app with file access, deployment, and terminal spawning.

</details>

---

## How It Works

1. **Design** -- Build your org chart by dragging agents into position and assigning skills
2. **Configure** -- Click any node to set API keys, passwords, descriptions, and skills in the inspector
3. **Deploy** -- Write your objective, click Deploy, and ATM compiles the full primer then launches Claude in your terminal
4. **Run** -- Claude executes with complete context from message one. No manual setup, no missing config

---

## At a Glance

| Capability | Details |
|------------|---------|
| **Org Chart** | Drag-and-drop canvas with collapse, reparenting, edge insert |
| **One-Click Deploy** | Auto-generated primer + terminal launch |
| **Pipelines** | Chain teams into sequential multi-step workflows |
| **Scheduling** | OS-level scheduling (Task Scheduler / cron) with repeat options |
| **AI Generation** | Generate full org structures from natural language |
| **Typed Variables** | API Key, Password, Note, Text types with masking and root-to-agent inheritance |
| **Layouts** | Save and switch between named configurations |
| **Node Duplication** | Ctrl+C/V/D to copy entire team subtrees |
| **Autosave** | Editors save automatically after 800ms idle |
| **Export/Import** | Full org to JSON, import on another machine |
| **Zero Lock-In** | Standard Claude Code config files -- no proprietary formats |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Desktop | [Tauri v2](https://v2.tauri.app/) (Rust backend) |
| Frontend | [React 19](https://react.dev/) + TypeScript |
| Bundler | [Vite 7](https://vite.dev/) |
| Canvas | [@xyflow/react](https://reactflow.dev/) (React Flow v12) + [dagre](https://github.com/dagrejs/dagre) |
| State | [Zustand v5](https://zustand.docs.pmnd.rs/) |
| Editor | [Monaco Editor](https://microsoft.github.io/monaco-editor/) |
| Parsing | [gray-matter](https://github.com/jonschlinkert/gray-matter) + [yaml](https://eemeli.org/yaml/) |
| Validation | [Zod](https://zod.dev/) |
| Native APIs | Tauri FS, Dialog, and Shell plugins |

## Platform Support

| Platform | Status | Terminal |
|----------|--------|---------|
| Windows | Full support | PowerShell |
| macOS | Full support | bash (Terminal.app) |
| Linux (Debian/Ubuntu) | Supported | gnome-terminal, xterm, or any installed emulator |
| Linux (Fedora/RPM) | Supported | konsole, gnome-terminal, alacritty, kitty, xterm |

---

## Changelog

### v0.7.0 (2026-02-27)
- **Added:** macOS support -- DMG installer now available alongside Windows EXE/MSI
- **Added:** GitHub Actions workflow to build macOS DMG on tagged releases
- **Fixed:** macOS terminal launch uses osascript instead of `open -a Terminal` (scripts now execute instead of opening as documents)
- **Fixed:** Scheduled shell scripts are now `chmod +x` on macOS/Linux so cron jobs can execute them
- **Fixed:** Project load errors now log details to console instead of being silently swallowed
- **Improved:** Platform detection uses `navigator.userAgent` via shared utility instead of deprecated `navigator.platform`
- **Improved:** Tauri bundle config includes macOS category and minimum system version

### v0.6.5 (2026-02-26)
- **Fixed:** AI-generated descriptions now auto-save when clicking to another node
- **Fixed:** New nodes appear directly below their parent instead of at a random distant position
- **Fixed:** Skill name resolution uses comprehensive lookup map
- **Added:** Node duplication via Ctrl+C/V/D and right-click context menu

### v0.6.4
- **Added:** Copy/paste/duplicate entire team subtrees
- **Fixed:** Pipeline schedules run deploy script directly
- **Fixed:** PowerShell deploy scripts use UTF-8 BOM encoding

### v0.6.3
- **Fixed:** Pipeline deploy.ps1 encoding issues
- **Added:** Dynamic version display in UI

---

## License

[MIT](LICENSE)

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

Built by one person who got tired of managing 30 agents in vim. If it helps you too, a star lets others find it.
