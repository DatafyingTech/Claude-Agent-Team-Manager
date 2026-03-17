import { useState, useEffect, useMemo, useCallback, type CSSProperties, type ReactNode } from "react";
import { readTextFile, writeTextFile, exists, mkdir } from "@tauri-apps/plugin-fs";
import { invoke } from "@tauri-apps/api/core";
import { useTreeStore } from "@/store/tree-store";
import { useUiStore } from "@/store/ui-store";
import { useAutosave } from "@/hooks/useAutosave";
import { scanAllSkills, type SkillInfo } from "@/services/skill-scanner";
import { getApiKey, generateText } from "@/services/claude-api";
import { toast } from "@/components/common/Toast";
import { join } from "@/utils/paths";
import { isWindows, isMac } from "@/utils/platform";
import type { AuiNode, NodeVariable } from "@/types/aui-node";
import { VariableEditor } from "./VariableEditor";

const labelStyle: CSSProperties = {
  fontSize: 12,
  textTransform: "uppercase",
  color: "var(--text-secondary)",
  marginBottom: 4,
  display: "block",
  letterSpacing: "0.5px",
};

const inputStyle: CSSProperties = {
  background: "var(--bg-primary, #0d1117)",
  border: "1px solid var(--border-color, #21262d)",
  color: "var(--text-primary, #e6edf3)",
  padding: 8,
  borderRadius: 6,
  width: "100%",
  fontSize: 13,
  outline: "none",
  transition: "border-color 0.15s",
};

const fieldStyle: CSSProperties = {
  marginBottom: 16,
};

const sectionHeaderStyle: CSSProperties = {
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: "1px",
  color: "var(--text-secondary)",
  borderBottom: "1px solid var(--border-color)",
  paddingBottom: 6,
  marginTop: 20,
  marginBottom: 12,
  fontWeight: 600,
};

const kindBadgeColors: Record<string, string> = {
  agent: "var(--accent-orange)",
  skill: "var(--accent-green)",
  group: "var(--accent-blue)",
  context: "var(--accent-purple)",
  settings: "var(--accent-gray)",
  human: "var(--accent-gold)",
};

function CollapsibleSection({
  title,
  count,
  defaultOpen = true,
  children,
}: {
  title: string;
  count?: number;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ marginBottom: 4 }}>
      <div
        onClick={() => setOpen(!open)}
        style={{
          ...sectionHeaderStyle,
          cursor: "pointer",
          userSelect: "none",
          display: "flex",
          alignItems: "center",
          gap: 6,
        }}
      >
        <span style={{ fontSize: 10, transition: "transform 0.15s", display: "inline-block", transform: open ? "rotate(90deg)" : "rotate(0)" }}>
          {"\u25B6"}
        </span>
        {title}{count !== undefined ? ` (${count})` : ""}
      </div>
      {open && <div style={{ paddingTop: 4 }}>{children}</div>}
    </div>
  );
}

interface GroupEditorProps {
  node: AuiNode;
}

export function GroupEditor({ node }: GroupEditorProps) {
  const updateNode = useTreeStore((s) => s.updateNode);
  const nodes = useTreeStore((s) => s.nodes);
  const projectPath = useTreeStore((s) => s.projectPath);
  const assignSkillToNode = useTreeStore((s) => s.assignSkillToNode);
  const removeSkillFromNode = useTreeStore((s) => s.removeSkillFromNode);
  const saveTreeMetadata = useTreeStore((s) => s.saveTreeMetadata);
  const createSkillNode = useTreeStore((s) => s.createSkillNode);
  const cacheSkillName = useTreeStore((s) => s.cacheSkillName);
  const skillNameCache = useTreeStore((s) => s.skillNameCache);
  const generateTeamSkillFiles = useTreeStore((s) => s.generateTeamSkillFiles);
  const selectNode = useUiStore((s) => s.selectNode);
  const openCreateDialog = useUiStore((s) => s.openCreateDialog);

  const [name, setName] = useState(node.name);
  const [description, setDescription] = useState(node.promptBody);
  const [variables, setVariables] = useState(node.variables);
  const [addSkillId, setAddSkillId] = useState("");
  const [deploying, setDeploying] = useState(false);
  const [deployOutput, setDeployOutput] = useState<string[]>([]);
  const [generating, setGenerating] = useState(false);
  const [autoFillCount, setAutoFillCount] = useState(3);
  const [autoFilling, setAutoFilling] = useState(false);
  const [deployPrompt, setDeployPrompt] = useState("");

  // Create-new-skill inline form state
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newSkillName, setNewSkillName] = useState("");
  const [newSkillDesc, setNewSkillDesc] = useState("");
  const [creating, setCreating] = useState(false);

  // Filesystem-scanned skills
  const [fsSkills, setFsSkills] = useState<SkillInfo[]>([]);

  // Re-init when node changes
  useEffect(() => {
    setName(node.name);
    setDescription(node.promptBody);
    setVariables(node.variables);
    setAddSkillId("");
    setShowCreateForm(false);
  }, [node.id, node.name, node.promptBody, node.variables]);

  // Scan filesystem for all skills on mount and when node/projectPath changes
  useEffect(() => {
    if (!projectPath) return;
    let cancelled = false;
    scanAllSkills(projectPath).then((skills) => {
      if (!cancelled) setFsSkills(skills);
    });
    return () => { cancelled = true; };
  }, [projectPath, node.id, nodes]);

  // All skill nodes available in the tree
  const treeSkills = useMemo(() => {
    const skills: AuiNode[] = [];
    for (const n of nodes.values()) {
      if (n.kind === "skill") skills.push(n);
    }
    return skills;
  }, [nodes]);

  // Build a description map: skill id -> description (from FS scan or promptBody)
  const skillDescriptions = useMemo(() => {
    const map = new Map<string, string>();
    for (const fs of fsSkills) {
      if (fs.description) map.set(fs.id, fs.description);
    }
    for (const s of treeSkills) {
      if (!map.has(s.id) && s.promptBody) {
        // Extract first meaningful line as description
        const firstLine = s.promptBody.split("\n").find(
          (l) => l.trim() && !l.startsWith("#") && !l.startsWith("---"),
        );
        if (firstLine) map.set(s.id, firstLine.trim().slice(0, 120));
      }
    }
    return map;
  }, [fsSkills, treeSkills]);

  // Merged list: tree skills + any FS-only skills (not already in tree)
  const allSkills = useMemo(() => {
    const treeIds = new Set(treeSkills.map((s) => s.id));
    const merged: Array<{ id: string; name: string; description: string }> = treeSkills.map((s) => ({
      id: s.id,
      name: s.name,
      description: skillDescriptions.get(s.id) ?? "",
    }));
    for (const fs of fsSkills) {
      if (!treeIds.has(fs.id)) {
        merged.push({ id: fs.id, name: fs.name, description: fs.description });
      }
    }
    return merged.sort((a, b) => a.name.localeCompare(b.name));
  }, [treeSkills, fsSkills, skillDescriptions]);

  // Skills currently assigned to this group
  const assignedSkills = useMemo(() => {
    return node.assignedSkills
      .map((id) => {
        const treeNode = nodes.get(id);
        if (treeNode) return { id: treeNode.id, name: treeNode.name, description: skillDescriptions.get(treeNode.id) ?? "" };
        const fsMatch = fsSkills.find((f) => f.id === id);
        if (fsMatch) return { id: fsMatch.id, name: fsMatch.name, description: fsMatch.description };
        return null;
      })
      .filter((n): n is { id: string; name: string; description: string } => n !== null);
  }, [node.assignedSkills, nodes, fsSkills, skillDescriptions]);

  // Skills not yet assigned (available to add)
  const availableSkills = useMemo(() => {
    const assigned = new Set(node.assignedSkills);
    return allSkills.filter((s) => !assigned.has(s.id));
  }, [allSkills, node.assignedSkills]);

  // Handle creating a new skill inline
  const handleCreateSkill = useCallback(async () => {
    const trimmedName = newSkillName.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
    if (!trimmedName) return;
    setCreating(true);
    try {
      await createSkillNode(trimmedName, newSkillDesc.trim());
      // Find the newly created skill node and assign it
      const { nodes: updatedNodes } = useTreeStore.getState();
      for (const [id, n] of updatedNodes) {
        if (n.kind === "skill" && n.name.toLowerCase().replace(/\s+/g, "-") === trimmedName) {
          assignSkillToNode(node.id, id);
          break;
        }
      }
      toast("Skill created and assigned", "success");
      setNewSkillName("");
      setNewSkillDesc("");
      setShowCreateForm(false);
    } catch {
      toast("Failed to create skill", "error");
    }
    setCreating(false);
  }, [newSkillName, newSkillDesc, createSkillNode, assignSkillToNode, node.id]);

  // Child nodes (nodes whose parentId matches this group)
  const children = useMemo(() => {
    const result: AuiNode[] = [];
    for (const n of nodes.values()) {
      if (n.parentId === node.id) result.push(n);
    }
    return result;
  }, [nodes, node.id]);

  const handleSave = () => {
    updateNode(node.id, {
      name,
      promptBody: description,
      variables: variables.filter((v) => v.name.trim()),
      lastModified: Date.now(),
    });
    saveTreeMetadata();
  };

  // Autosave on changes
  useAutosave(handleSave, [name, description, variables], node.id);

  const resetForm = () => {
    setName(node.name);
    setDescription(node.promptBody);
    setVariables(node.variables);
  };

  const handleAddSkill = () => {
    if (!addSkillId) return;
    // Cache the skill name so OrgNode can display it (without adding a visible node)
    const match = allSkills.find((s) => s.id === addSkillId);
    if (match) {
      cacheSkillName(addSkillId, match.name);
    }
    assignSkillToNode(node.id, addSkillId);
    setAddSkillId("");
  };

  const handleRemoveSkill = (skillId: string) => {
    removeSkillFromNode(node.id, skillId);
  };

  const handleAutoFillAgents = useCallback(async () => {
    if (!projectPath || !name.trim()) return;
    setAutoFilling(true);
    try {
      const apiKey = await getApiKey(projectPath);
      if (!apiKey) {
        toast("No API key configured. Go to Settings to add one.", "error");
        setAutoFilling(false);
        return;
      }

      const parentN = node.parentId ? nodes.get(node.parentId) : null;
      const isMemberNode = parentN?.kind === "group";
      const context = isMemberNode
        ? `an agent named "${name}" in team "${parentN?.name ?? "unknown"}"`
        : `a team named "${name}" with description: "${description}"`;

      const prompt = `Generate exactly ${autoFillCount} AI agent team members for ${context}.

Return ONLY valid JSON (no markdown, no explanation):
{
  "agents": [
    { "name": "Agent Name", "description": "What this agent does - 1 sentence" }
  ]
}

Make names descriptive and specific. Use title case.`;

      const result = await generateText(apiKey, prompt, { maxTokens: 1024 });
      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error("No valid JSON in response");
      const parsed = JSON.parse(jsonMatch[0]);

      if (!Array.isArray(parsed.agents)) throw new Error("Invalid format");

      const { createGroupNode: createGroup } = useTreeStore.getState();
      for (const agent of parsed.agents) {
        createGroup(agent.name, agent.description, node.id);
      }

      toast(`Added ${parsed.agents.length} agents`, "success");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Auto-fill failed", "error");
    }
    setAutoFilling(false);
  }, [projectPath, name, description, autoFillCount, node.id, node.parentId, nodes]);

  const handleGenerate = useCallback(async () => {
    if (!projectPath || !name.trim()) return;
    setGenerating(true);
    try {
      const apiKey = await getApiKey(projectPath);
      if (!apiKey) {
        toast("No API key configured. Go to Settings to add one.", "error");
        setGenerating(false);
        return;
      }
      const parentNode = node.parentId ? nodes.get(node.parentId) : null;
      const isMemberNode = parentNode?.kind === "group";
      const context = isMemberNode
        ? `This is an agent named "${name}" that is part of the team "${parentNode?.name ?? "unknown"}".`
        : `This is a team named "${name}" that manages AI agents.`;
      const result = await generateText(apiKey, `${context}\n\nWrite a concise 1-2 sentence description for this ${isMemberNode ? "agent" : "team"} based on its name. Be specific about what it does. Only output the description text, nothing else.`);
      if (result.trim()) {
        setDescription(result.trim());
        toast("Description generated", "success");
      }
    } catch (err) {
      toast(err instanceof Error ? err.message : "Generation failed", "error");
    }
    setGenerating(false);
  }, [projectPath, name, node.parentId, nodes]);

  // Read a skill file from disk given a slug
  const readSkillFile = useCallback(async (slug: string): Promise<string> => {
    if (!projectPath) return "";
    try {
      const path = join(projectPath, ".claude", "skills", slug, "SKILL.md");
      if (await exists(path)) return await readTextFile(path);
    } catch { /* ignore */ }
    return "";
  }, [projectPath]);

  // Build comprehensive primer text with all skill contents inline
  const buildFullPrimer = useCallback(async () => {
    const teamSlug = node.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
    const objective = deployPrompt || "Complete the tasks assigned to this team.";

    // Resolve a skill ID to its display name using nodes map, then skillNameCache fallback
    const resolveSkillName = (sid: string): string | null => {
      const n = nodes.get(sid);
      if (n?.name) return n.name;
      const cached = skillNameCache.get(sid);
      if (cached) return cached;
      return null;
    };

    // Get root/company context
    const rootNode = nodes.get("root");
    const rootName = rootNode?.name ?? "Unknown";
    const rootDesc = rootNode?.promptBody ?? "";
    const globalSkillNames = (rootNode?.assignedSkills ?? [])
      .map((sid) => resolveSkillName(sid))
      .filter((n): n is string => n !== null);
    const globalVars = (rootNode?.variables ?? []).filter((v) => v.name.trim());

    // Sibling teams for context
    const siblingTeams: string[] = [];
    for (const n of nodes.values()) {
      if (n.kind === "group" && n.parentId === "root" && n.id !== node.id) {
        siblingTeams.push(n.name);
      }
    }

    // Read the manager skill file
    const managerSkillContent = await readSkillFile(`${teamSlug}-manager`);

    // Build agent blocks with their full skill content
    const agentBlocks: string[] = [];
    for (const agent of children) {
      const agentSlug = agent.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
      const skillContent = await readSkillFile(`${teamSlug}-${agentSlug}`);

      let block = `\n### Agent: ${agent.name} (slug: "${agentSlug}")\n`;
      if (agent.promptBody) block += `Role: ${agent.promptBody}\n`;
      if (agent.variables.length > 0) {
        block += `Variables:\n${agent.variables.map((v) => `  - [${v.type ?? "text"}] ${v.name}: ${v.value || "(not set)"}`).join("\n")}\n`;
      }

      if (skillContent) {
        block += `\n<skill-file name="${teamSlug}-${agentSlug}">\n${skillContent}\n</skill-file>\n`;
      }

      agentBlocks.push(block);
    }

    // Team-level assigned skills
    const teamSkillBlocks: string[] = [];
    for (const sid of node.assignedSkills) {
      const sName = resolveSkillName(sid);
      if (sName) teamSkillBlocks.push(`- /${sName}`);
    }

    let primer = `You are being deployed as the senior team manager for "${node.name}".

## Company / Organization Context
- **Owner:** ${rootName}
${rootDesc ? `- **Description:** ${rootDesc}` : ""}
${globalSkillNames.length > 0 ? `- **Global Skills:** ${globalSkillNames.join(", ")}` : ""}
${siblingTeams.length > 0 ? `- **Other Teams:** ${siblingTeams.join(", ")}` : ""}
${globalVars.length > 0 ? `\n### Global Variables\n${globalVars.map((v) => `- [${v.type ?? "text"}] ${v.name}: ${v.value || "(not set)"}`).join("\n")}` : ""}

## Team: ${node.name}
${node.promptBody || "(no description)"}
${node.variables.length > 0 ? `\n### Team Variables\n${node.variables.map((v) => `- [${v.type ?? "text"}] ${v.name}: ${v.value || "(not set)"}`).join("\n")}` : ""}
${teamSkillBlocks.length > 0 ? `\n### Team Skills\n${teamSkillBlocks.join("\n")}` : ""}

## Your Manager Skill File
${managerSkillContent ? `<skill-file name="${teamSlug}-manager">\n${managerSkillContent}\n</skill-file>` : "(no manager skill file found — you'll coordinate based on the team info above)"}

## Team Roster (${children.length} agents)
${agentBlocks.join("\n")}

## OBJECTIVE
${objective}

## DEPLOYMENT INSTRUCTIONS
You MUST follow these steps exactly:

1. **Create the team** — Use \`TeamCreate\` with team name \`${teamSlug}\`
2. **Spawn each agent** — For each agent listed above, use the \`Task\` tool with:
   - \`team_name: "${teamSlug}"\`
   - \`subagent_type: "general-purpose"\`
   - \`name: "<agent-slug>"\` (slugs listed above per agent)
   - Include their FULL skill file content in the prompt so they have all context needed to work immediately
3. **Create and assign tasks** — Use \`TaskCreate\` to break the objective into tasks, then \`TaskUpdate\` with \`owner\` to assign each task to the right agent by name
4. **Coordinate** — Monitor progress via \`TaskList\`, resolve conflicts, answer agent questions via \`SendMessage\`
5. **Complete** — When all tasks are done, compile a summary report and shut down the team
${teamSkillBlocks.length > 0 || globalSkillNames.length > 0 ? `
## SKILLS
Skills listed above (prefixed with \`/\`) can be invoked using the \`Skill\` tool. For example: \`Skill(skill: "skill-name")\`. Pass skills to agents by including the skill name in their spawn prompt so they know to invoke them.` : ""}
IMPORTANT: Each agent already has their full skill file content above. Pass it directly in their spawn prompt so they can start working immediately without needing to research or discover anything. They should hit the ground running.
`;

    return primer;
  }, [children, node, nodes, deployPrompt, readSkillFile, projectPath, skillNameCache]);

  const handleDeploy = useCallback(async () => {
    setDeploying(true);
    setDeployOutput(["Generating missing skill files..."]);

    try {
      const paths = await generateTeamSkillFiles(node.id);
      setDeployOutput((prev) => [...prev, `${paths.length} skill files ready.`]);
    } catch {
      setDeployOutput((prev) => [...prev, "Warning: Could not generate skill files."]);
    }

    setDeployOutput((prev) => [...prev, "Building deployment primer..."]);

    try {
      const primer = await buildFullPrimer();

      // Save primer to .aui/deploy-primer.md
      const auiDir = join(projectPath!, ".aui");
      if (!(await exists(auiDir))) await mkdir(auiDir, { recursive: true });
      const primerPath = join(auiDir, "deploy-primer.md");
      await writeTextFile(primerPath, primer);

      setDeployOutput((prev) => [...prev, `Primer saved to ${primerPath}`, "Opening terminal..."]);

      // Use Rust-side open_terminal command which uses CREATE_NEW_CONSOLE on Windows
      // to guarantee a visible terminal window (bypasses Tauri's CREATE_NO_WINDOW).

      if (isWindows) {
        const winPrimerPath = primerPath.replace(/\//g, "\\");
        const scriptPath = join(auiDir, "deploy.ps1");
        const winScriptPath = scriptPath.replace(/\//g, "\\");
        const escapedPrimerPath = winPrimerPath.replace(/'/g, "''");
        const escapedName = node.name.replace(/'/g, "''");
        const ps1Content = [
          `Remove-Item Env:CLAUDECODE -ErrorAction SilentlyContinue`,
          `Write-Host 'Deploying team: ${escapedName}' -ForegroundColor Cyan`,
          `Write-Host 'Primer: ${escapedPrimerPath}' -ForegroundColor Yellow`,
          `Write-Host 'Starting Claude...' -ForegroundColor Green`,
          `try {`,
          `  claude --dangerously-skip-permissions "Read the deployment primer at '${escapedPrimerPath}' using the Read tool and follow ALL instructions in it exactly. Start immediately."`,
          `} catch {`,
          `  Write-Host "Error: $_" -ForegroundColor Red`,
          `}`,
          `Write-Host ''`,
          `Read-Host 'Press Enter to close'`,
        ].join("\r\n");
        await writeTextFile(scriptPath, "\uFEFF" + ps1Content);
        await invoke("open_terminal", { scriptPath: winScriptPath });
      } else {
        // macOS / Linux: write a shell script
        const scriptPath = join(auiDir, "deploy.sh");
        const escapedPrimerPathUnix = primerPath.replace(/'/g, "'\\''");
        const shContent = [
          "#!/bin/bash",
          "unset CLAUDECODE",
          `echo 'Deploying team: ${node.name.replace(/'/g, "'\\''")}'`,
          `echo 'Starting Claude...'`,
          `claude --dangerously-skip-permissions "Read the deployment primer at '${escapedPrimerPathUnix}' using the Read tool and follow ALL instructions in it exactly. Start immediately."`,
          "exec bash",
        ].join("\n");
        await writeTextFile(scriptPath, shContent);

        // Make executable, then open in terminal via Rust command
        const { Command } = await import("@tauri-apps/plugin-shell");
        const chmod = Command.create("bash", ["-c", `chmod +x '${scriptPath}'`]);
        await chmod.execute();
        await invoke("open_terminal", { scriptPath });
      }

      setDeployOutput((prev) => [
        ...prev,
        "",
        "Claude session launched in external terminal!",
        "The primer has been sent to start your team deployment.",
        "",
        "--- Primer Preview ---",
        primer.slice(0, 600) + (primer.length > 600 ? "\n..." : ""),
      ]);

      toast("Team deployment launched in terminal!", "success");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setDeployOutput((prev) => [...prev, `Error: ${msg}`]);
      toast(`Deploy failed: ${msg}`, "error");
    }
    setDeploying(false);
  }, [buildFullPrimer, generateTeamSkillFiles, node.id, projectPath]);

  // Determine if this is a member (nested inside another group) or a top-level team
  const parentNode = node.parentId ? nodes.get(node.parentId) : null;
  const isMember = parentNode?.kind === "group";

  return (
    <div>
      {/* 1. Name + Description (always visible, at top) */}
      <div style={{ marginBottom: 16 }}>
        <label style={labelStyle}>Name</label>
        <input
          style={inputStyle}
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>

      <div style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
          <label style={{ ...labelStyle, marginBottom: 0 }}>Description</label>
          <button
            onClick={handleGenerate}
            disabled={generating || !name.trim()}
            style={{
              padding: "2px 10px",
              fontSize: 10,
              fontWeight: 600,
              background: generating ? "var(--border-color)" : "var(--accent-purple)",
              color: "white",
              border: "none",
              borderRadius: 10,
              cursor: generating || !name.trim() ? "default" : "pointer",
              opacity: generating || !name.trim() ? 0.5 : 1,
              transition: "opacity 0.15s",
            }}
          >
            {generating ? "Generating..." : "Generate"}
          </button>
        </div>
        <textarea
          rows={3}
          style={{ ...inputStyle, resize: "vertical" }}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>

      {/* 2. Deploy — only for top-level teams */}
      {!isMember && (
        <div style={{ marginBottom: 16 }}>
          <div style={sectionHeaderStyle}>Deploy</div>

          {/* Deploy prompt box */}
          <div style={{ marginBottom: 10 }}>
            <label style={{ ...labelStyle, fontSize: 10 }}>Deploy Prompt</label>
            <textarea
              rows={2}
              style={{ ...inputStyle, resize: "vertical" }}
              value={deployPrompt}
              onChange={(e) => setDeployPrompt(e.target.value)}
              onKeyDown={(e) => {
                if (e.ctrlKey && e.key === "Enter" && !deploying) {
                  e.preventDefault();
                  handleDeploy();
                }
              }}
              placeholder="Tell the team what to accomplish... (Ctrl+Enter to deploy)"
            />
          </div>

          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <button
              onClick={handleDeploy}
              disabled={deploying}
              style={{
                flex: 2,
                padding: "10px 16px",
                background: deploying
                  ? "var(--border-color)"
                  : "var(--accent-orange)",
                color: "white",
                border: "none",
                borderRadius: 6,
                cursor: deploying ? "default" : "pointer",
                fontSize: 13,
                fontWeight: 600,
                transition: "opacity 0.15s",
              }}
            >
              {deploying ? "Preparing..." : "Deploy Team"}
            </button>
            <button
              onClick={() => useUiStore.getState().toggleSchedule(node.id)}
              style={{
                flex: 1,
                padding: "10px 16px",
                background: "transparent",
                color: "var(--accent-purple)",
                border: "1px solid var(--accent-purple)",
                borderRadius: 6,
                cursor: "pointer",
                fontSize: 13,
                fontWeight: 600,
                transition: "all 0.15s",
              }}
            >
              Schedule
            </button>
          </div>

          <div
            style={{
              fontSize: 10,
              color: "var(--text-secondary)",
              marginBottom: 4,
              lineHeight: 1.4,
            }}
          >
            <b>Deploy</b> opens a terminal with the full primer. <b>Schedule</b> sets up recurring runs.
          </div>

          {/* Deploy output terminal */}
          {deployOutput.length > 0 && (
            <div
              style={{
                maxHeight: 160,
                overflow: "auto",
                background: "var(--bg-primary)",
                border: "1px solid var(--border-color)",
                borderRadius: 6,
                padding: 10,
                marginTop: 4,
                fontFamily: "'Consolas', 'Monaco', monospace",
                fontSize: 11,
                lineHeight: 1.5,
                color: "var(--text-secondary)",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
              }}
            >
              {deployOutput.map((line, i) => (
                <div key={i} style={{ color: line.startsWith("[error]") ? "var(--accent-danger, #f85149)" : line.startsWith("[stderr]") ? "var(--accent-gold)" : "#a0ffa0" }}>
                  {line}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 3. Skills & Variables — combined collapsible section */}
      <CollapsibleSection title="Skills & Variables" count={assignedSkills.length + variables.filter((v) => v.name.trim()).length} defaultOpen={assignedSkills.length > 0 || variables.length > 0}>
        {/* Assigned Skills */}
        <div style={{ ...labelStyle, marginBottom: 8 }}>Assigned Skills</div>

        {assignedSkills.length === 0 && (
          <div
            style={{
              color: "var(--text-secondary)",
              fontSize: 12,
              marginBottom: 12,
              fontStyle: "italic",
            }}
          >
            No skills assigned
          </div>
        )}

        {assignedSkills.map((skill) => (
          <div
            key={skill.id}
            style={{
              display: "flex",
              alignItems: "flex-start",
              justifyContent: "space-between",
              padding: "6px 8px",
              background: "var(--tint-green)",
              border: "1px solid var(--border-color)",
              borderRadius: 4,
              marginBottom: 4,
            }}
          >
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 13, color: "var(--text-primary)" }}>
                {skill.name}
              </div>
              {skill.description && (
                <div
                  style={{
                    fontSize: 11,
                    color: "var(--text-secondary)",
                    marginTop: 2,
                    lineHeight: 1.3,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {skill.description}
                </div>
              )}
            </div>
            <button
              type="button"
              onClick={() => handleRemoveSkill(skill.id)}
              style={{
                background: "none",
                border: "none",
                color: "var(--text-secondary)",
                cursor: "pointer",
                padding: "0 4px",
                fontSize: 14,
                lineHeight: 1,
                flexShrink: 0,
                marginTop: 2,
              }}
              title="Remove skill"
            >
              x
            </button>
          </div>
        ))}

        <div style={{ display: "flex", gap: 6, marginTop: 6, marginBottom: 6 }}>
          <select
            style={{ ...inputStyle, flex: 1 }}
            value={addSkillId}
            onChange={(e) => {
              if (e.target.value === "__create_new__") {
                setShowCreateForm(true);
                setAddSkillId("");
              } else {
                setAddSkillId(e.target.value);
                setShowCreateForm(false);
              }
            }}
          >
            <option value="">Select a skill...</option>
            <option value="__create_new__" style={{ fontWeight: 600 }}>
              + Create New Skill...
            </option>
            {availableSkills.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}{s.description ? ` — ${s.description.slice(0, 60)}` : ""}
              </option>
            ))}
          </select>
          <button
            onClick={handleAddSkill}
            disabled={!addSkillId}
            style={{
              padding: "8px 12px",
              background: addSkillId
                ? "var(--accent-green)"
                : "var(--border-color)",
              color: "white",
              border: "none",
              borderRadius: 4,
              cursor: addSkillId ? "pointer" : "default",
              fontSize: 12,
              fontWeight: 600,
              whiteSpace: "nowrap",
              opacity: addSkillId ? 1 : 0.5,
            }}
          >
            Add
          </button>
        </div>

        {showCreateForm && (
          <div
            style={{
              padding: 10,
              background: "#1a1a2e",
              border: "1px solid var(--accent-green)",
              borderRadius: 6,
              marginBottom: 4,
            }}
          >
            <div style={{ fontSize: 11, fontWeight: 600, color: "var(--accent-green)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Create New Skill
            </div>
            <input
              style={{ ...inputStyle, marginBottom: 6 }}
              placeholder="Skill name (e.g. deploy-app)"
              value={newSkillName}
              onChange={(e) => setNewSkillName(e.target.value)}
            />
            <textarea
              style={{ ...inputStyle, resize: "vertical", marginBottom: 8 }}
              rows={2}
              placeholder="Short description..."
              value={newSkillDesc}
              onChange={(e) => setNewSkillDesc(e.target.value)}
            />
            <div style={{ display: "flex", gap: 6 }}>
              <button
                onClick={handleCreateSkill}
                disabled={!newSkillName.trim() || creating}
                style={{
                  flex: 1,
                  padding: "6px 12px",
                  background: newSkillName.trim() && !creating ? "var(--accent-green)" : "var(--border-color)",
                  color: "white",
                  border: "none",
                  borderRadius: 4,
                  cursor: newSkillName.trim() && !creating ? "pointer" : "default",
                  fontSize: 12,
                  fontWeight: 600,
                  opacity: newSkillName.trim() && !creating ? 1 : 0.5,
                }}
              >
                {creating ? "Creating..." : "Create & Assign"}
              </button>
              <button
                onClick={() => { setShowCreateForm(false); setNewSkillName(""); setNewSkillDesc(""); }}
                style={{
                  padding: "6px 12px",
                  background: "transparent",
                  color: "var(--text-secondary)",
                  border: "1px solid var(--border-color)",
                  borderRadius: 4,
                  cursor: "pointer",
                  fontSize: 12,
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Variables */}
        <div style={{ ...labelStyle, marginTop: 16, marginBottom: 8 }}>Variables</div>

        <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 10, lineHeight: 1.4 }}>
          API keys, passwords, notes, and config values available to this {isMember ? "agent" : "team"}.
        </div>

        <VariableEditor variables={variables} onChange={setVariables} />
      </CollapsibleSection>

      {/* 4. Agents — collapsible, includes Generate with AI controls */}
      <CollapsibleSection title="Agents" count={children.length}>
        {/* Generate with AI controls */}
        <div style={{ display: "flex", gap: 8, marginBottom: 10, alignItems: "flex-end" }}>
          <div style={{ width: 70 }}>
            <label style={{ ...labelStyle, fontSize: 10 }}>Count</label>
            <input
              type="number"
              min={1}
              max={10}
              value={autoFillCount}
              onChange={(e) => setAutoFillCount(Math.max(1, Math.min(10, Number(e.target.value))))}
              style={{ ...inputStyle, textAlign: "center" }}
            />
          </div>
          <button
            onClick={handleAutoFillAgents}
            disabled={autoFilling || !name.trim()}
            style={{
              flex: 1,
              padding: "8px 12px",
              background: autoFilling ? "var(--border-color)" : "var(--accent-purple)",
              color: "white",
              border: "none",
              borderRadius: 6,
              cursor: autoFilling || !name.trim() ? "default" : "pointer",
              fontSize: 12,
              fontWeight: 600,
              opacity: autoFilling || !name.trim() ? 0.5 : 1,
              transition: "opacity 0.15s",
            }}
          >
            {autoFilling ? "Generating..." : "Generate Agents"}
          </button>
        </div>

        {/* Agent list */}
        {children.length === 0 && (
          <div
            style={{
              color: "var(--text-secondary)",
              fontSize: 12,
              marginBottom: 12,
              fontStyle: "italic",
            }}
          >
            No agents yet
          </div>
        )}

        {children.map((child) => {
          // Determine if this child is a sub-agent (its parent is an agent-in-team, not a top-level team)
          const isChildSubAgent = isMember && child.kind === "group";
          const badgeLabel = isChildSubAgent ? "sub-agent" : child.kind;
          const badgeColor = isChildSubAgent ? "#a5d6ff" : (kindBadgeColors[child.kind] ?? "var(--text-secondary)");

          return (
            <div
              key={child.id}
              onClick={() => selectNode(child.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "6px 8px",
                background: "var(--tint-blue)",
                border: "1px solid var(--border-color)",
                borderRadius: 4,
                marginBottom: 4,
                cursor: "pointer",
                transition: "background 0.15s",
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLDivElement).style.background =
                  "var(--tint-blue-hover)";
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLDivElement).style.background =
                  "var(--tint-blue)";
              }}
            >
              <span
                style={{
                  display: "inline-block",
                  padding: "1px 6px",
                  borderRadius: 8,
                  fontSize: 10,
                  fontWeight: 600,
                  textTransform: "uppercase",
                  color: "white",
                  background: badgeColor,
                }}
              >
                {badgeLabel}
              </span>
              <span style={{ fontSize: 13, color: "var(--text-primary)" }}>
                {child.name}
              </span>
            </div>
          );
        })}

        <button
          onClick={() => openCreateDialog(node.id)}
          style={{
            width: "100%",
            padding: "8px 12px",
            marginTop: 6,
            background: "transparent",
            color: "var(--accent-blue)",
            border: "1px dashed var(--accent-blue)",
            borderRadius: 4,
            cursor: "pointer",
            fontSize: 12,
            fontWeight: 600,
          }}
        >
          + Add Agent
        </button>
      </CollapsibleSection>

      {/* Discard */}
      <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 24 }}>
        <button
          onClick={resetForm}
          style={{
            padding: "8px 16px",
            background: "transparent",
            color: "var(--text-secondary)",
            border: "1px solid var(--border-color)",
            borderRadius: 4,
            cursor: "pointer",
            fontSize: 13,
            fontWeight: 600,
          }}
        >
          Discard
        </button>
      </div>

    </div>
  );
}
