/**
 * runner.js — replays a scenario through a fresh harness and decides whether
 * the run ended in a breach. Pure logic, no DOM: also used by scripts/check.mjs.
 */
import { VFS, isInside } from './vfs.js'
import { Harness } from './harness.js'
import { PAYLOAD_MARKER } from '../scenarios/index.js'

export async function runScenario(scenario, controls) {
  const vfs   = new VFS()
  const trace = []
  const consent = (await scenario.setup(vfs)) || []
  const h = new Harness({ vfs, controls, consent, trace })
  await h.init()

  let handoffProv = null
  for (const [i, step] of scenario.steps.entries()) {
    trace.push({ kind: 'step', msg: step.note, step: i + 1, actor: step.actor || (step.kind === 'agent' ? 'agent' : step.kind) })
    if (step.injection) trace.push({ kind: 'inject', msg: step.injection.text, source: step.injection.source })

    if (step.kind === 'external') { step.apply(vfs); trace.push({ kind: 'info', msg: 'repo updated outside the agent' }); continue }
    if (step.kind === 'session')  { await h.loadControlPlane(); continue }

    const prov = step.useHandoffProv && handoffProv
      ? handoffProv
      : step.injection ? { tainted: true, source: step.injection.source } : { tainted: false, source: 'user' }
    const res = await h.call(step.tool, step.args, prov)
    if (step.tool === 'handoff' && res.ok) handoffProv = res.prov
  }

  const breaches = h.effects.filter(e =>
    (e.type === 'write' && !isInside(e.path)) ||
    (e.type === 'exec' && String(e.command).includes(PAYLOAD_MARKER)) ||
    e.type === 'egress' ||
    e.type === 'cwd-escape')

  const blockedBy = [...new Set(trace.filter(t => t.control && (t.kind === 'deny' || t.kind === 'hold')).map(t => t.control))]
  return { trace, effects: h.effects, breaches, breached: breaches.length > 0, blockedBy, vfs, pending: h.pendingApprovals }
}

export function describeBreach(e) {
  switch (e.type) {
    case 'write':      return `file written outside workspace: ${e.path}`
    case 'exec':       return `harness executed payload from ${e.path}`
    case 'egress':     return `private data sent to ${e.url}`
    case 'cwd-escape': return `"${e.command}" ran in ${e.cwd}`
    default:           return e.type
  }
}
