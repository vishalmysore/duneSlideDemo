/**
 * planes.js — classify files as instruction plane or control plane.
 *
 * Instruction plane: text the MODEL interprets. It can persuade, but it
 *   cannot act on its own.
 * Control plane: config the HARNESS executes deterministically, without
 *   asking the model or the user again.
 */

const CONTROL_PATTERNS = [
  { re: /(^|\/)\.cursor\/mcp\.json$/,              kind: 'MCP server config' },
  { re: /(^|\/)\.mcp\.json$/,                       kind: 'MCP server config' },
  { re: /(^|\/)\.agent\/hooks\.json$/,              kind: 'Lifecycle hooks' },
  { re: /(^|\/)\.agent\/skills\/[^/]+\/skill\.json$/, kind: 'Skill manifest' },
  { re: /(^|\/)\.devcontainer\/devcontainer\.json$/, kind: 'Devcontainer config' },
  { re: /(^|\/)\.vscode\/tasks\.json$/,             kind: 'Editor task runner' },
]

const INSTRUCTION_PATTERNS = [
  { re: /(^|\/)AGENTS\.md$/,  kind: 'Agent instructions' },
  { re: /(^|\/)CLAUDE\.md$/,  kind: 'Agent instructions' },
  { re: /(^|\/)\.cursorrules$/, kind: 'Agent instructions' },
  { re: /\.md$/,              kind: 'Documentation' },
]

export function classify(path) {
  for (const p of CONTROL_PATTERNS)     if (p.re.test(path)) return { plane: 'control', kind: p.kind }
  for (const p of INSTRUCTION_PATTERNS) if (p.re.test(path)) return { plane: 'instruction', kind: p.kind }
  return { plane: 'data', kind: 'Source / data' }
}

/** Control-plane files the harness auto-loads at session start. */
export function isAutoLoaded(path) {
  return classify(path).plane === 'control'
}
