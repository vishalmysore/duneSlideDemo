import { SCENARIOS } from './scenarios/index.js'
import { runScenario, describeBreach } from './harness/runner.js'
import { CONTROLS, PRESETS } from './harness/harness.js'
import { classify } from './harness/planes.js'
import { WEBLLM_MODELS, loadModel, generate, modelReady } from './llm/llm.js'

const $ = (id) => document.getElementById(id)
const esc = (s) => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))

let current  = SCENARIOS[0]
let controls = { ...PRESETS.vulnerable, [current.control]: true }
let lastRun  = null

// ── Scenario list ─────────────────────────────────────────────

function renderList() {
  $('scenarioList').innerHTML = SCENARIOS.map(s => `
    <li><button class="${s === current ? 'active' : ''}" data-id="${s.id}">
      <span class="s-title">${esc(s.title)}</span>
      <span class="s-ref">${esc(s.ref)}</span>
    </button></li>`).join('')
}

$('scenarioList').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-id]')
  if (!b) return
  current = SCENARIOS.find(s => s.id === b.dataset.id)
  controls = { ...PRESETS.vulnerable, [current.control]: true }
  refresh()
})

function renderCard() {
  const ctl = CONTROLS.find(c => c.id === current.control)
  $('scenarioCard').innerHTML = `
    <div class="card-meta"><span class="pill">${esc(current.plane)}</span><span class="ref">${esc(current.ref)}</span></div>
    <h2>${esc(current.title)}</h2>
    <p>${esc(current.summary)}</p>
    <p class="lesson"><b>Harness rule:</b> ${esc(current.lesson)}</p>
    <p class="fix">Control that closes it: <b>${esc(ctl.label)}</b></p>`
}

// ── Controls ──────────────────────────────────────────────────

function renderControls() {
  $('controlList').innerHTML = CONTROLS.map(c => `
    <label class="control ${c.id === current.control ? 'relevant' : ''}">
      <input type="checkbox" data-ctl="${c.id}" ${controls[c.id] ? 'checked' : ''} />
      <span><b>${esc(c.label)}</b><small>${esc(c.help)}</small></span>
    </label>`).join('')
}

$('controlList').addEventListener('change', (e) => {
  const id = e.target.dataset.ctl
  if (!id) return
  controls[id] = e.target.checked
  runBoth()
})

document.querySelector('.presets').addEventListener('click', (e) => {
  const p = e.target.dataset.preset
  if (!p) return
  controls = p === 'only' ? { ...PRESETS.vulnerable, [current.control]: true } : { ...PRESETS[p] }
  renderControls()
  runBoth()
})

// ── Runs ──────────────────────────────────────────────────────

const ICON = { step: '▸', inject: '☣', call: '→', ok: '✓', deny: '⛔', hold: '⏸', warn: '⚠', effect: '💥', info: 'ℹ', phase: '◆' }

function renderRun(el, run) {
  const v = el.querySelector('.verdict')
  v.textContent = run.breached ? 'BREACHED' : 'HELD'
  v.className = 'verdict ' + (run.breached ? 'bad' : 'good')
  const items = run.trace.map(t => {
    const isPayloadEffect = t.kind === 'effect' && /simulated-payload|data sent/.test(t.msg)
    const kind = isPayloadEffect ? 'effect bad' : t.kind
    const label = t.kind === 'step' ? `<span class="actor">${esc(t.actor)}</span>` : ''
    const extra = t.kind === 'inject' ? ` <span class="src">${esc(t.source)}</span>`
                : t.kind === 'call' && t.tainted ? ` <span class="src">tainted · ${esc(t.source)}</span>`
                : t.control ? ` <span class="ctl">${esc(CONTROLS.find(c => c.id === t.control)?.label || t.control)}</span>` : ''
    const icon = t.kind === 'effect' && !isPayloadEffect ? '▶' : ICON[t.kind] || '·'
    return `<li class="t-${kind.replace(' ', ' t-')}"><span class="ic">${icon}</span>${label}<span class="msg">${esc(t.msg)}</span>${extra}</li>`
  })
  if (run.breached) items.push(...run.breaches.map(b => `<li class="t-breach"><span class="ic">✖</span><span class="msg">${esc(describeBreach(b))}</span></li>`))
  el.querySelector('.trace').innerHTML = items.join('')
}

function renderFs(run) {
  $('fsBody').innerHTML = run.vfs.list().map(f => {
    const policy = /\/\.agent\/policy\.json$/.test(f.path)
    const { plane, kind } = policy ? { plane: 'control', kind: 'Policy engine rules' } : classify(f.path)
    const outside = !f.path.startsWith('/workspace/')
    const hit = outside && /simulated-payload/.test(f.content || '')
    const labels = [
      f.type === 'link' ? `link → ${f.target}` : '',
      f.private ? 'private' : '',
      f.tainted ? 'tainted' : '',
      hit ? 'written by agent, outside workspace' : outside ? 'outside workspace' : '',
    ].filter(Boolean).join(' · ')
    return `<tr class="${hit ? 'outside' : ''}"><td><code>${esc(f.path)}</code></td>
      <td><span class="tag ${plane}">${plane}</span> <small>${esc(kind)}</small></td><td>${esc(labels)}</td></tr>`
  }).join('')
}

async function runBoth() {
  const [vuln, mine] = await Promise.all([
    runScenario(current, PRESETS.vulnerable),
    runScenario(current, controls),
  ])
  lastRun = mine
  renderRun($('runVuln'), vuln)
  renderRun($('runYours'), mine)
  renderFs(mine)
  $('explanation').textContent = ''
}

// ── Matrix ────────────────────────────────────────────────────

async function renderMatrix() {
  const head = `<tr><th></th>${CONTROLS.map(c => `<th title="${esc(c.help)}">${esc(c.label)}</th>`).join('')}<th>All on</th></tr>`
  const rows = []
  for (const s of SCENARIOS) {
    const cells = []
    for (const c of CONTROLS) {
      const r = await runScenario(s, { ...PRESETS.vulnerable, [c.id]: true })
      cells.push(`<td class="${r.breached ? 'no' : 'yes'}">${r.breached ? '·' : '✔'}</td>`)
    }
    const all = await runScenario(s, PRESETS.hardened)
    cells.push(`<td class="${all.breached ? 'no' : 'yes'}">${all.breached ? '·' : '✔'}</td>`)
    rows.push(`<tr><th>${esc(s.title)}</th>${cells.join('')}</tr>`)
  }
  $('matrix').innerHTML = head + rows.join('')
}

// ── Reviewer ──────────────────────────────────────────────────

$('modelSelect').innerHTML = WEBLLM_MODELS.map(m => `<option value="${m.id}">${esc(m.name)}</option>`).join('')

$('loadModel').addEventListener('click', async () => {
  const btn = $('loadModel')
  btn.disabled = true
  $('modelStatus').textContent = 'Starting…'
  try {
    await loadModel($('modelSelect').value, (ev) => {
      if (ev.type === 'downloading') $('modelStatus').textContent = `Downloading… ${ev.progress}%`
      if (ev.type === 'phase' && ev.phase === 'compile') $('modelStatus').textContent = 'Compiling WebGPU shaders (cached after first load)…'
    })
    $('modelStatus').textContent = 'Model ready.'
    $('explain').disabled = false
  } catch (err) {
    $('modelStatus').textContent = `Could not load: ${err.message}`
  } finally {
    btn.disabled = false
  }
})

$('explain').addEventListener('click', async () => {
  if (!lastRun || !modelReady()) return
  const on = CONTROLS.filter(c => controls[c.id]).map(c => c.label).join(', ') || 'none'
  const trace = lastRun.trace.map(t => `${t.kind}: ${t.msg}`).join('\n')
  const prompt = `Scenario: ${current.title}\nControls enabled: ${on}\nOutcome: ${lastRun.breached ? 'BREACHED' : 'HELD'}\n\nTrace:\n${trace}`
  $('explanation').textContent = 'Thinking…'
  try {
    $('explanation').textContent = await generate(
      'You are a security reviewer for AI coding-agent harnesses. In 4-6 short sentences, explain what happened in this simulated run, which harness control mattered, and what a team should check in their own harness. Plain language, no markdown headings.',
      prompt)
  } catch (err) {
    $('explanation').textContent = err.message
  }
})

// ── Boot ──────────────────────────────────────────────────────

function refresh() {
  renderList()
  renderCard()
  renderControls()
  runBoth()
}

refresh()
renderMatrix()
