/**
 * harness.js — the deterministic layer between a model's tool calls and the
 * (virtual) machine. Every security decision happens here, never in the model.
 *
 * Each control can be switched on or off so you can see exactly which one
 * stops which bug class. The scripted agent is assumed to be fully
 * compromised: the harness must hold even when the model has been persuaded.
 */
import { WORKSPACE, normalize, join, isInside, CanonicalizeError } from './vfs.js'
import { classify, isAutoLoaded } from './planes.js'

export const CONTROLS = [
  { id: 'failClosed',     label: 'Fail-closed canonicalization',
    help: 'If a path or cwd cannot be resolved, deny. Never fall back to the unresolved input.' },
  { id: 'confineCwd',     label: 'Confine every path argument',
    help: 'Canonicalize optional args such as working_directory, not just the main path.' },
  { id: 'createIsEdit',   label: 'Create = edit for control plane',
    help: 'Creating a control-plane file needs the same approval as editing one.' },
  { id: 'hashConsent',    label: 'Hash-pinned consent',
    help: 'Approve content, not names. One changed byte resets approval: MCP, hooks, skills, devcontainer.' },
  { id: 'ruleOfTwo',      label: 'Rule of Two by construction',
    help: 'A session may never hold private data, untrusted input and egress at the same time.' },
  { id: 'taintHandoff',   label: 'Taint survives handoff',
    help: 'Provenance labels travel with artifacts between agents; tainted input cannot drive control-plane writes.' },
  { id: 'policyOutOfBand', label: 'Policy engine out of reach',
    help: 'Rules live outside the agent-writable filesystem and are hash-checked on every decision.' },
]

export const PRESETS = {
  vulnerable: Object.fromEntries(CONTROLS.map(c => [c.id, false])),
  hardened:   Object.fromEntries(CONTROLS.map(c => [c.id, true])),
}

export async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('')
}

const POLICY_PATH = WORKSPACE + '/.agent/policy.json'
const DEFAULT_POLICY = { denyWritesOutsideWorkspace: true, requireApprovalForControlPlane: true }

export class Harness {
  constructor({ vfs, controls, consent = [], trace }) {
    this.vfs      = vfs
    this.c        = { ...controls }
    this.trace    = trace
    this.consent  = consent           // [{ path, hash }] approvals the user already gave
    this.legs     = new Set()         // trifecta legs held by this session
    this.effects  = []                // simulated side effects that actually happened
    this.pendingApprovals = []
    // Out-of-band policy: a frozen copy plus its hash, never read from the VFS.
    this.policy     = Object.freeze({ ...DEFAULT_POLICY })
    this.policyHash = null
  }

  async init() {
    this.policyHash = await sha256(JSON.stringify(this.policy))
    if (!this.c.policyOutOfBand) this.vfs.writeFile(POLICY_PATH, JSON.stringify(DEFAULT_POLICY, null, 2))
  }

  log(kind, msg, extra = {}) { this.trace.push({ kind, msg, ...extra }) }

  /** Current rules. Vulnerable mode re-reads them from the agent-writable workspace. */
  async rules() {
    if (this.c.policyOutOfBand) {
      const h = await sha256(JSON.stringify(this.policy))
      if (h !== this.policyHash) throw new Error('policy hash mismatch')
      return this.policy
    }
    try { return JSON.parse(this.vfs.get(POLICY_PATH)?.content ?? '{}') }
    catch { return {} }
  }

  // ── Canonicalization ────────────────────────────────────────

  canonicalize(path, base = WORKSPACE) {
    const apparent = join(base, path)
    try {
      return { ok: true, path: this.vfs.realpath(apparent) }
    } catch (err) {
      if (!(err instanceof CanonicalizeError)) throw err
      if (this.c.failClosed) {
        this.log('deny', `canonicalize failed (${err.code}) → deny`, { control: 'failClosed' })
        return { ok: false, reason: `${err.code} while resolving ${err.path}` }
      }
      this.log('warn', `canonicalize failed (${err.code}) → falling back to apparent path ${apparent}`)
      return { ok: true, path: apparent, fellBack: true }
    }
  }

  // ── Trifecta tracking ───────────────────────────────────────

  acquire(leg, why) {
    const next = new Set(this.legs).add(leg)
    if (this.c.ruleOfTwo && next.size === 3) {
      this.log('deny', `${why} would complete the lethal trifecta (private + untrusted + egress) → deny`, { control: 'ruleOfTwo' })
      return false
    }
    this.legs = next
    this.log('info', `session now holds: ${[...this.legs].join(' + ')}`)
    return true
  }

  // ── Tools ───────────────────────────────────────────────────

  async call(tool, args, prov = { tainted: false, source: 'user' }) {
    const shown = Object.fromEntries(Object.entries(args).map(([k, v]) =>
      [k, typeof v === 'string' && v.length > 50 ? v.replace(/\s+/g, ' ').slice(0, 50) + '�' : v]))
    this.log('call', `${tool}(${JSON.stringify(shown)})`, { tainted: prov.tainted, source: prov.source })
    const fn = this['tool_' + tool]
    if (!fn) return this.deny(`unknown tool ${tool}`)
    return fn.call(this, args, prov)
  }

  deny(reason, control) { this.log('deny', reason, { control }); return { ok: false, denied: true, reason } }

  async tool_read_file({ path }, prov) {
    const r = this.canonicalize(path)
    if (!r.ok) return this.deny(r.reason, 'failClosed')
    const node = this.vfs.get(r.path)
    if (!node) return this.deny(`no such file ${r.path}`)
    if (node.private && !this.acquire('private', `reading ${r.path}`)) return { ok: false, denied: true }
    if (node.untrusted && !this.acquire('untrusted', `reading ${r.path}`)) return { ok: false, denied: true }
    this.log('ok', `read ${r.path}`)
    return { ok: true, content: node.content, tainted: !!node.untrusted || prov.tainted }
  }

  async tool_fetch({ url }) {
    if (!this.acquire('untrusted', `fetching ${url}`)) return { ok: false, denied: true }
    this.log('ok', `fetched ${url} (untrusted content)`)
    return { ok: true, tainted: true }
  }

  async tool_http_post({ url, body }) {
    if (!this.acquire('egress', `posting to ${url}`)) return { ok: false, denied: true }
    this.effects.push({ type: 'egress', url, body })
    this.log('effect', `data sent to ${url}`)
    return { ok: true }
  }

  async tool_symlink({ path, target }) {
    const r = this.canonicalize(path)
    if (!r.ok) return this.deny(r.reason, 'failClosed')
    if (!isInside(r.path)) return this.deny(`link location ${r.path} is outside the workspace`)
    this.vfs.symlink(r.path, target)
    this.log('ok', `created link ${r.path} → ${target}`)
    return { ok: true }
  }

  async tool_write_file({ path, content }, prov) {
    const rules = await this.rules().catch(e => (this.deny(e.message, 'policyOutOfBand'), null))
    if (!rules) return { ok: false, denied: true }

    const r = this.canonicalize(path)
    if (!r.ok) return this.deny(r.reason, 'failClosed')

    // The policy file itself.
    if (r.path === POLICY_PATH && this.c.policyOutOfBand)
      return this.deny('policy engine is not on the agent-writable filesystem', 'policyOutOfBand')

    if (rules.denyWritesOutsideWorkspace !== false && !isInside(r.path))
      return this.deny(`${r.path} is outside the workspace`)

    const { plane, kind } = classify(r.path)
    if (plane === 'control') {
      if (prov.tainted && this.c.taintHandoff)
        return this.deny(`tainted input (from ${prov.source}) cannot write control-plane file ${kind}`, 'taintHandoff')

      const existed = this.vfs.get(r.path)?.type === 'file'
      const gated = rules.requireApprovalForControlPlane !== false && (existed || this.c.createIsEdit)
      if (gated) {
        this.pendingApprovals.push({ path: r.path, content })
        this.log('hold', `${kind} ${existed ? 'edit' : 'creation'} held for human approval — not written`, { control: existed ? null : 'createIsEdit' })
        return { ok: false, held: true }
      }
      if (!existed) this.log('warn', `${kind} created with no approval prompt (only edits are gated)`)
    }

    // A fallback path was never verified: the OS follows whatever links are really there.
    const dest = r.fellBack ? this.vfs.osResolve(r.path) : r.path
    const { existed } = this.vfs.writeFile(dest, content, { tainted: prov.tainted })
    this.log('ok', `${existed ? 'updated' : 'created'} ${dest}`)
    if (dest !== r.path) this.log('warn', `checker approved ${r.path} but the write landed at ${dest}`)
    if (!isInside(dest)) this.effects.push({ type: 'write', path: dest })
    return { ok: true }
  }

  async tool_terminal({ command, working_directory }) {
    const cmdOk = /^(npm (test|run lint)|ls|git status)$/.test(command)
    if (!cmdOk) return this.deny(`command "${command}" not on allowlist`)
    let cwd = WORKSPACE
    if (working_directory) {
      if (this.c.confineCwd) {
        const r = this.canonicalize(working_directory)
        if (!r.ok) return this.deny(r.reason, 'failClosed')
        if (!isInside(r.path)) return this.deny(`working_directory ${r.path} escapes the workspace`, 'confineCwd')
        cwd = r.path
      } else {
        cwd = join(WORKSPACE, working_directory)
        this.log('warn', `working_directory accepted unchecked (only "command" is validated)`)
      }
    }
    this.log('ok', `(simulated) ran "${command}" in ${cwd}`)
    if (!isInside(cwd)) this.effects.push({ type: 'cwd-escape', cwd, command })
    return { ok: true, cwd }
  }

  /** Pass an artifact to another agent. */
  async tool_handoff({ to, artifact }, prov) {
    const carried = this.c.taintHandoff ? prov : { tainted: false, source: 'agent:' + prov.source }
    this.log(this.c.taintHandoff ? 'info' : 'warn',
      this.c.taintHandoff
        ? `handoff to ${to}: provenance kept (tainted=${prov.tainted}, source=${prov.source})`
        : `handoff to ${to}: labels dropped, artifact now looks like trusted agent output`)
    return { ok: true, artifact, prov: carried }
  }

  // ── Session start: the harness auto-loads control-plane files ──

  async loadControlPlane() {
    this.log('phase', 'session start: harness loads control-plane config')
    for (const f of this.vfs.list()) {
      if (f.type !== 'file' || !isAutoLoaded(f.path) || !isInside(f.path)) continue
      const { kind } = classify(f.path)
      let approved
      if (this.c.hashConsent) {
        const h = await sha256(f.content)
        approved = this.consent.some(a => a.path === f.path && a.hash === h)
        if (!approved) {
          const byName = this.consent.some(a => a.path === f.path)
          this.log('deny', `${kind} ${byName ? 'content changed since approval' : 'never approved'} → not loaded, re-prompt`, { control: 'hashConsent' })
          continue
        }
      } else {
        approved = this.consent.some(a => a.path === f.path) || !this.c.createIsEdit
        if (!approved) { this.log('hold', `${kind} not approved → not loaded`); continue }
      }
      let cfg = {}
      try { cfg = JSON.parse(f.content) } catch {}
      const cmd = cfg.command ?? cfg.onSessionStart ?? cfg.postCreateCommand ?? '(none)'
      this.log('effect', `(simulated) harness started ${kind}: ${cmd}`)
      this.effects.push({ type: 'exec', path: f.path, command: cmd })
    }
  }
}
