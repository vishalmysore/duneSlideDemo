// Headless check: every scenario must breach the vulnerable harness, be
// stopped by the hardened one, and be stopped by its own named control alone.
import { SCENARIOS } from '../src/scenarios/index.js'
import { runScenario } from '../src/harness/runner.js'
import { PRESETS } from '../src/harness/harness.js'

let failed = 0
for (const s of SCENARIOS) {
  const vuln = await runScenario(s, PRESETS.vulnerable)
  const hard = await runScenario(s, PRESETS.hardened)
  const only = await runScenario(s, { ...PRESETS.vulnerable, [s.control]: true })
  const ok = vuln.breached && !hard.breached && !only.breached
  if (!ok) failed++
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${s.id.padEnd(10)} vulnerable=${vuln.breached ? 'breach' : 'safe'}  hardened=${hard.breached ? 'breach' : 'safe'}  only ${s.control}=${only.breached ? 'breach' : 'safe'}`)
  if (!ok) for (const t of [...vuln.trace, ...only.trace]) console.log('   ', t.kind, t.msg)
}
process.exit(failed ? 1 : 0)
