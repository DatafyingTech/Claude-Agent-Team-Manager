import { useState, useEffect, useCallback, type CSSProperties } from "react";
import { readTextFile, exists } from "@tauri-apps/plugin-fs";
import { useTreeStore } from "@/store/tree-store";
import { useUiStore } from "@/store/ui-store";
import { join } from "@/utils/paths";
import { isWindows } from "@/utils/platform";
import { toast } from "@/components/common/Toast";
import {
  loadSchedules as loadSchedulesFromDisk,
  createSchedule,
  deleteSchedule,
  toggleSchedule,
  type ScheduleRecord,
} from "@/services/scheduler";
import type { AuiNode } from "@/types/aui-node";

/* ── Shared styles ───────────────────────────────────── */

const panelStyle: CSSProperties = {
  position: "fixed",
  top: "var(--toolbar-height)",
  right: 0,
  width: 420,
  height: "calc(100% - var(--toolbar-height))",
  background: "var(--bg-secondary)",
  borderLeft: "1px solid var(--border-color)",
  zIndex: 50,
  display: "flex",
  flexDirection: "column",
  boxShadow: "-4px 0 24px rgba(0, 0, 0, 0.3)",
};

const inputStyle: CSSProperties = {
  background: "var(--bg-input)",
  border: "1px solid var(--border-input)",
  color: "var(--text-primary)",
  padding: 8,
  borderRadius: 4,
  width: "100%",
  fontSize: 13,
  outline: "none",
};

const labelStyle: CSSProperties = {
  fontSize: 11,
  textTransform: "uppercase",
  color: "var(--text-secondary)",
  marginBottom: 4,
  display: "block",
  letterSpacing: "0.5px",
};

const REPEAT_OPTIONS = [
  { label: "Once", value: "once" },
  { label: "Every hour", value: "hourly" },
  { label: "Every day", value: "daily" },
  { label: "Every week", value: "weekly" },
  { label: "Custom cron expression", value: "custom" },
];

interface SchedulePanelProps {
  onClose: () => void;
}

/** Build a cron expression from repeat type + time. */
function buildCron(repeat: string, hour: string, minute: string): string {
  const h = hour || "9";
  const m = minute || "0";
  switch (repeat) {
    case "hourly":
      return "0 * * * *";
    case "daily":
      return `${m} ${h} * * *`;
    case "weekly":
      return `${m} ${h} * * 1`;
    case "once":
    default:
      return `${m} ${h} * * *`;
  }
}

/** Describe a repeat value as human-readable. */
function describeRepeat(repeat: string, cron: string): string {
  switch (repeat) {
    case "once":
      return "One-time";
    case "hourly":
      return "Every hour";
    case "daily":
      return "Daily";
    case "weekly":
      return "Weekly";
    case "monthly":
      return "Monthly";
    case "custom":
      return cron;
    default:
      return repeat;
  }
}

/** Extract HH:MM from a cron expression (best-effort). */
function cronToTime(cron: string): string {
  const parts = cron.trim().split(/\s+/);
  if (parts.length < 2) return "";
  const m = parts[0] === "*" ? "0" : parts[0].replace(/\*\//, "");
  const h = parts[1] === "*" ? "" : parts[1].replace(/\*\//, "");
  if (!h) return "";
  return `${h.padStart(2, "0")}:${m.padStart(2, "0")}`;
}

/** Format a timestamp as a short date string. */
function formatDate(ts: number): string {
  return new Date(ts).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function SchedulePanel({ onClose }: SchedulePanelProps) {
  const projectPath = useTreeStore((s) => s.projectPath);
  const nodes = useTreeStore((s) => s.nodes);
  const skillNameCache = useTreeStore((s) => s.skillNameCache);
  const generateTeamSkillFiles = useTreeStore((s) => s.generateTeamSkillFiles);
  const preselectedTeamId = useUiStore((s) => s.schedulePreselectedTeamId);

  const [jobs, setJobs] = useState<ScheduleRecord[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [selectedTeamId, setSelectedTeamId] = useState("");
  const [repeatType, setRepeatType] = useState("once");
  const [schedHour, setSchedHour] = useState("09");
  const [schedMinute, setSchedMinute] = useState("00");
  const [customCron, setCustomCron] = useState("");
  const [prompt, setPrompt] = useState("");
  const [creating, setCreating] = useState(false);

  // Get top-level teams and pipelines
  const teams: AuiNode[] = [];
  for (const n of nodes.values()) {
    if ((n.kind === "group" || n.kind === "pipeline") && n.parentId === "root") teams.push(n);
  }

  // Check if selected is a pipeline
  const selectedNode = selectedTeamId ? nodes.get(selectedTeamId) : null;
  const isPipelineSelected = selectedNode?.kind === "pipeline";

  // Auto-select team when opened from GroupEditor's Schedule button
  useEffect(() => {
    if (preselectedTeamId) {
      setSelectedTeamId(preselectedTeamId);
      setShowCreate(true);
    }
  }, [preselectedTeamId]);

  // Load schedules on mount
  useEffect(() => {
    if (!projectPath) return;
    loadJobs();
  }, [projectPath]);

  const loadJobs = useCallback(async () => {
    if (!projectPath) return;
    try {
      const records = await loadSchedulesFromDisk(projectPath);
      setJobs(records);
    } catch {
      // ignore
    }
  }, [projectPath]);

  // Read a skill file from disk given a slug
  const readSkillFile = useCallback(
    async (slug: string): Promise<string> => {
      if (!projectPath) return "";
      try {
        const path = join(projectPath, ".claude", "skills", slug, "SKILL.md");
        if (await exists(path)) return await readTextFile(path);
      } catch {
        /* ignore */
      }
      return "";
    },
    [projectPath],
  );

  // Build primer (mirrors GroupEditor.buildFullPrimer)
  const buildPrimer = useCallback(
    async (teamNode: AuiNode, objective: string) => {
      const teamSlug = teamNode.name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/(^-|-$)/g, "");

      const resolveSkillName = (sid: string): string | null => {
        const n = nodes.get(sid);
        if (n?.name) return n.name;
        const cached = skillNameCache.get(sid);
        if (cached) return cached;
        return null;
      };

      const rootNode = nodes.get("root");
      const rootName = rootNode?.name ?? "Unknown";
      const rootDesc = rootNode?.promptBody ?? "";
      const globalSkillNames = (rootNode?.assignedSkills ?? [])
        .map((sid) => resolveSkillName(sid))
        .filter((n): n is string => n !== null);

      const siblingTeams: string[] = [];
      for (const n of nodes.values()) {
        if (n.kind === "group" && n.parentId === "root" && n.id !== teamNode.id) {
          siblingTeams.push(n.name);
        }
      }

      const children: AuiNode[] = [];
      for (const n of nodes.values()) {
        if (n.parentId === teamNode.id) children.push(n);
      }

      const managerSkillContent = await readSkillFile(`${teamSlug}-manager`);

      const agentBlocks: string[] = [];
      for (const agent of children) {
        const agentSlug = agent.name
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/(^-|-$)/g, "");
        const skillContent = await readSkillFile(`${teamSlug}-${agentSlug}`);

        let block = `\n### Agent: ${agent.name} (slug: "${agentSlug}")\n`;
        if (agent.promptBody) block += `Role: ${agent.promptBody}\n`;
        if (agent.variables.length > 0) {
          block += `Variables: ${agent.variables.map((v) => `${v.name}=${v.value || "..."}`).join(", ")}\n`;
        }
        if (skillContent) {
          block += `\n<skill-file name="${teamSlug}-${agentSlug}">\n${skillContent}\n</skill-file>\n`;
        }
        agentBlocks.push(block);
      }

      const teamSkillBlocks: string[] = [];
      for (const sid of teamNode.assignedSkills) {
        const sName = resolveSkillName(sid);
        if (sName) teamSkillBlocks.push(`- /${sName}`);
      }

      return `You are being deployed as the senior team manager for "${teamNode.name}".

## Company / Organization Context
- **Owner:** ${rootName}
${rootDesc ? `- **Description:** ${rootDesc}` : ""}
${globalSkillNames.length > 0 ? `- **Global Skills:** ${globalSkillNames.join(", ")}` : ""}
${siblingTeams.length > 0 ? `- **Other Teams:** ${siblingTeams.join(", ")}` : ""}

## Team: ${teamNode.name}
${teamNode.promptBody || "(no description)"}
${teamNode.variables.length > 0 ? `\n### Team Variables\n${teamNode.variables.map((v) => `- ${v.name}: ${v.value || "(not set)"}`).join("\n")}` : ""}
${teamSkillBlocks.length > 0 ? `\n### Team Skills\n${teamSkillBlocks.join("\n")}` : ""}

## Your Manager Skill File
${managerSkillContent ? `<skill-file name="${teamSlug}-manager">\n${managerSkillContent}\n</skill-file>` : "(no manager skill file found)"}

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
   - Include their FULL skill file content in the prompt so they have all context needed
3. **Create and assign tasks** — Use \`TaskCreate\` to break the objective into tasks, then \`TaskUpdate\` with \`owner\` to assign
4. **Coordinate** — Monitor progress via \`TaskList\`, resolve conflicts, answer agent questions
5. **Complete** — When all tasks are done, compile a summary report and shut down the team
${teamSkillBlocks.length > 0 || globalSkillNames.length > 0 ? `\n## SKILLS\nSkills listed above can be invoked using the \`Skill\` tool.` : ""}
IMPORTANT: Each agent already has their full skill file content above. Pass it directly in their spawn prompt.
`;
    },
    [nodes, skillNameCache, readSkillFile, projectPath],
  );

  const handleCreate = useCallback(async () => {
    if (!selectedTeamId || !projectPath || creating) return;
    const team = nodes.get(selectedTeamId);
    if (!team) return;

    setCreating(true);
    try {
      // Build cron and repeat
      let cron: string;
      const repeat = repeatType;
      if (repeatType === "custom") {
        cron = customCron.trim() || "0 9 * * *";
      } else {
        cron = buildCron(repeatType, schedHour, schedMinute);
      }

      let primerContent: string;
      let deployScriptPath: string | undefined;

      if (team.kind === "pipeline") {
        // Generate pipeline deploy artifacts (primers + deploy script) without opening terminal
        await useTreeStore.getState().deployPipeline(selectedTeamId, { skipLaunch: true });
        const slug = team.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
        deployScriptPath = join(projectPath, ".aui", `pipeline-${slug}`, isWindows ? "deploy.ps1" : "deploy.sh");
        primerContent = `Pipeline: ${team.name}\nDeploy script: ${deployScriptPath}`;
      } else {
        // Generate skill files first (non-fatal if it fails)
        try {
          await generateTeamSkillFiles(selectedTeamId);
        } catch {
          // continue
        }
        // Build primer for teams
        const objective = prompt.trim() || "Complete the tasks assigned to this team.";
        primerContent = await buildPrimer(team, objective);
      }

      // Create OS-level scheduled task
      await createSchedule(
        projectPath,
        selectedTeamId,
        team.name,
        cron,
        repeat,
        primerContent,
        prompt.trim(),
        deployScriptPath,
      );

      await loadJobs();

      // Reset form
      setShowCreate(false);
      setSelectedTeamId("");
      setRepeatType("once");
      setSchedHour("09");
      setSchedMinute("00");
      setCustomCron("");
      setPrompt("");
      toast("Schedule created (OS task registered)", "success");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      toast(`Failed to create schedule: ${msg}`, "error");
    }
    setCreating(false);
  }, [
    selectedTeamId,
    repeatType,
    schedHour,
    schedMinute,
    customCron,
    prompt,
    projectPath,
    nodes,
    creating,
    buildPrimer,
    generateTeamSkillFiles,
    loadJobs,
  ]);

  const handleToggle = useCallback(
    async (jobId: string) => {
      if (!projectPath) return;
      try {
        const updated = await toggleSchedule(projectPath, jobId);
        setJobs(updated);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        toast(`Failed to toggle schedule: ${msg}`, "error");
      }
    },
    [projectPath],
  );

  const handleDelete = useCallback(
    async (jobId: string) => {
      if (!projectPath) return;
      try {
        await deleteSchedule(projectPath, jobId);
        await loadJobs();
        toast("Schedule removed (OS task deleted)", "success");
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        toast(`Failed to delete schedule: ${msg}`, "error");
      }
    },
    [projectPath, loadJobs],
  );

  const canCreate =
    !!selectedTeamId &&
    (repeatType !== "custom" || !!customCron.trim()) &&
    !creating;

  return (
    <div style={panelStyle}>
      {/* Header */}
      <div
        style={{
          padding: "16px 20px",
          borderBottom: "1px solid var(--border-color)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <div
          style={{ fontWeight: 700, fontSize: 16, color: "var(--text-primary)" }}
        >
          Scheduled Deployments
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            onClick={() => setShowCreate(!showCreate)}
            style={{
              padding: "4px 12px",
              background: "var(--accent-purple)",
              color: "white",
              border: "none",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            + New
          </button>
          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: "var(--text-secondary)",
              cursor: "pointer",
              fontSize: 18,
              padding: "0 4px",
            }}
          >
            x
          </button>
        </div>
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflow: "auto", padding: 16 }}>
        {/* Create form */}
        {showCreate && (
          <div
            style={{
              padding: 14,
              background: "var(--bg-elevated)",
              border: "1px solid var(--accent-purple)",
              borderRadius: 8,
              marginBottom: 16,
            }}
          >
            <div
              style={{
                fontSize: 12,
                fontWeight: 600,
                color: "var(--accent-purple)",
                marginBottom: 12,
                textTransform: "uppercase",
                letterSpacing: "0.5px",
              }}
            >
              New Schedule
            </div>

            {/* Team/Pipeline selector */}
            <div style={{ marginBottom: 10 }}>
              <label style={labelStyle}>Team / Pipeline</label>
              <select
                style={inputStyle}
                value={selectedTeamId}
                onChange={(e) => setSelectedTeamId(e.target.value)}
              >
                <option value="">Select a team or pipeline...</option>
                {teams.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.kind === "pipeline" ? `[Pipeline] ${t.name}` : t.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Repeat frequency */}
            <div style={{ marginBottom: 10 }}>
              <label style={labelStyle}>Repeat</label>
              <select
                style={inputStyle}
                value={repeatType}
                onChange={(e) => setRepeatType(e.target.value)}
              >
                {REPEAT_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Time picker — shown for once / daily / weekly */}
            {repeatType !== "hourly" && repeatType !== "custom" && (
              <div style={{ marginBottom: 10 }}>
                <label style={labelStyle}>Run at</label>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <select
                    style={{ ...inputStyle, width: 72 }}
                    value={schedHour}
                    onChange={(e) => setSchedHour(e.target.value)}
                  >
                    {Array.from({ length: 24 }, (_, i) => {
                      const v = String(i).padStart(2, "0");
                      return (
                        <option key={v} value={v}>
                          {v}
                        </option>
                      );
                    })}
                  </select>
                  <span
                    style={{
                      color: "var(--text-secondary)",
                      fontWeight: 700,
                      fontSize: 14,
                    }}
                  >
                    :
                  </span>
                  <select
                    style={{ ...inputStyle, width: 72 }}
                    value={schedMinute}
                    onChange={(e) => setSchedMinute(e.target.value)}
                  >
                    {["00", "15", "30", "45"].map((v) => (
                      <option key={v} value={v}>
                        {v}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            )}

            {/* Custom cron input */}
            {repeatType === "custom" && (
              <div style={{ marginBottom: 10 }}>
                <label style={labelStyle}>Cron Expression</label>
                <input
                  style={{
                    ...inputStyle,
                    fontFamily: "monospace",
                    fontSize: 12,
                  }}
                  value={customCron}
                  onChange={(e) => setCustomCron(e.target.value)}
                  placeholder="* * * * * (min hour day month weekday)"
                />
                <div
                  style={{
                    fontSize: 10,
                    color: "var(--text-secondary)",
                    marginTop: 4,
                  }}
                >
                  E.g. "0 9 * * 1-5" = weekdays at 9am
                </div>
              </div>
            )}

            {/* Deploy prompt — hidden for pipelines (prompts are per-step) */}
            {!isPipelineSelected && (
              <div style={{ marginBottom: 12 }}>
                <label style={labelStyle}>Deploy Prompt</label>
                <textarea
                  rows={3}
                  style={{ ...inputStyle, resize: "vertical" }}
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  placeholder="What should this team accomplish on each run?"
                />
              </div>
            )}
            {isPipelineSelected && (
              <div style={{ marginBottom: 12, fontSize: 11, color: "var(--text-secondary)", fontStyle: "italic" }}>
                Pipeline prompts are configured per-step in the Project Manager editor.
              </div>
            )}

            {/* Actions */}
            <div style={{ display: "flex", gap: 6 }}>
              <button
                onClick={handleCreate}
                disabled={!canCreate}
                style={{
                  flex: 1,
                  padding: "8px 12px",
                  background: canCreate
                    ? "var(--accent-purple)"
                    : "var(--border-color)",
                  color: "white",
                  border: "none",
                  borderRadius: 4,
                  cursor: canCreate ? "pointer" : "default",
                  fontSize: 12,
                  fontWeight: 600,
                  opacity: canCreate ? 1 : 0.5,
                }}
              >
                {creating ? "Creating..." : "Create Schedule"}
              </button>
              <button
                onClick={() => setShowCreate(false)}
                style={{
                  padding: "8px 12px",
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

        {/* Empty state */}
        {jobs.length === 0 && !showCreate && (
          <div
            style={{
              textAlign: "center",
              color: "var(--text-secondary)",
              padding: "40px 20px",
              fontSize: 13,
            }}
          >
            <div style={{ fontSize: 24, marginBottom: 12 }}>
              No scheduled deployments
            </div>
            <div>
              Click <b>+ New</b> to schedule a team for recurring deployment.
            </div>
            <div
              style={{
                marginTop: 8,
                fontSize: 11,
                color: "var(--text-tertiary, var(--text-secondary))",
              }}
            >
              Schedules register real OS tasks (Windows Task Scheduler / cron).
            </div>
          </div>
        )}

        {/* Job list */}
        {jobs.map((job) => (
          <div
            key={job.id}
            style={{
              padding: 12,
              background: job.enabled
                ? "rgba(139, 92, 246, 0.05)"
                : "rgba(255,255,255,0.02)",
              border: `1px solid ${
                job.enabled
                  ? "rgba(139, 92, 246, 0.2)"
                  : "rgba(255,255,255,0.05)"
              }`,
              borderRadius: 8,
              marginBottom: 8,
              opacity: job.enabled ? 1 : 0.6,
            }}
          >
            {/* Row 1: Team name + controls */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: 6,
              }}
            >
              <div
                style={{
                  fontWeight: 600,
                  fontSize: 14,
                  color: "var(--text-primary)",
                }}
              >
                {job.teamName}
              </div>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <button
                  onClick={() => handleToggle(job.id)}
                  style={{
                    padding: "2px 8px",
                    fontSize: 10,
                    fontWeight: 600,
                    background: job.enabled
                      ? "rgba(63,185,80,0.15)"
                      : "rgba(255,255,255,0.1)",
                    color: job.enabled ? "#3fb950" : "var(--text-secondary)",
                    border: `1px solid ${
                      job.enabled
                        ? "rgba(63,185,80,0.3)"
                        : "var(--border-color)"
                    }`,
                    borderRadius: 10,
                    cursor: "pointer",
                  }}
                >
                  {job.enabled ? "ON" : "OFF"}
                </button>
                <button
                  onClick={() => handleDelete(job.id)}
                  style={{
                    background: "none",
                    border: "none",
                    color: "var(--text-secondary)",
                    cursor: "pointer",
                    fontSize: 14,
                    padding: "0 4px",
                  }}
                  title="Delete schedule and OS task"
                >
                  x
                </button>
              </div>
            </div>

            {/* Row 2: Badges — repeat type, time, raw cron */}
            <div
              style={{
                display: "flex",
                gap: 8,
                marginBottom: 4,
                flexWrap: "wrap",
                alignItems: "center",
              }}
            >
              <span
                style={{
                  fontSize: 10,
                  fontWeight: 600,
                  padding: "1px 6px",
                  borderRadius: 8,
                  background: "rgba(139, 92, 246, 0.15)",
                  color: "var(--accent-purple)",
                  textTransform: "uppercase",
                }}
              >
                {describeRepeat(job.repeat, job.cron)}
              </span>
              {cronToTime(job.cron) && (
                <span
                  style={{
                    fontSize: 10,
                    fontWeight: 600,
                    padding: "1px 6px",
                    borderRadius: 8,
                    background: "rgba(74,158,255,0.1)",
                    color: "var(--accent-blue)",
                  }}
                >
                  {cronToTime(job.cron)}
                </span>
              )}
              <span
                style={{
                  fontSize: 10,
                  fontFamily: "monospace",
                  color: "var(--text-secondary)",
                }}
              >
                {job.cron}
              </span>
            </div>

            {/* Row 3: Created date */}
            <div
              style={{
                fontSize: 10,
                color: "var(--text-secondary)",
                marginBottom: 2,
              }}
            >
              Created {formatDate(job.createdAt)}
            </div>

            {/* Row 4: Prompt (truncated) */}
            {job.prompt && (
              <div
                style={{
                  fontSize: 12,
                  color: "var(--text-secondary)",
                  marginTop: 4,
                  lineHeight: 1.3,
                  overflow: "hidden",
                  display: "-webkit-box",
                  WebkitLineClamp: 2,
                  WebkitBoxOrient: "vertical",
                }}
              >
                {job.prompt}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Footer */}
      <div
        style={{
          padding: "12px 16px",
          borderTop: "1px solid var(--border-color)",
          fontSize: 11,
          color: "var(--text-secondary)",
          lineHeight: 1.4,
        }}
      >
        Schedules register real OS tasks via{" "}
        <code style={{ color: "var(--accent-purple)" }}>schtasks</code>{" "}
        (Windows) or{" "}
        <code style={{ color: "var(--accent-purple)" }}>crontab</code>{" "}
        (macOS/Linux). Toggle OFF to pause without deleting.
      </div>
    </div>
  );
}
