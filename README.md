# DuneSlide Harness Lab

**The model can be talked into anything. Can your harness hold?**

A browser-only lab that replays recent AI coding-agent bug classes against a
small agent harness, with every defensive control on a switch. Turn controls
on and off and watch the same compromised agent either breach the
(simulated) machine or get stopped.

It builds on the [Harness Engineering demo](https://vishalmysore.github.io/harnessEngineeringDemo/):
there, the harness makes a model *useful*. Here, the harness keeps a
persuaded model *harmless*.

## The idea: two planes

| Plane | Who reads it | Examples | Risk |
|---|---|---|---|
| **Instruction plane** | the model interprets it | `AGENTS.md`, docs, tool results, web pages | persuasion |
| **Control plane** | the harness executes it, without asking | `mcp.json`, hooks, skills, devcontainer, task runners | execution |

Prompt injection only has to win once on the instruction plane, by getting the
model to write one control-plane file. After that, deterministic harness
behaviour does the rest. So the lab assumes the model is already compromised
and asks only one question: does the harness hold?

## Scenarios

| # | Bug class | Reference | Control that closes it |
|---|---|---|---|
| 1 | Symlink resolver falls back to the unverified path | DuneSlide, CVE-2026-50549 | Fail-closed canonicalization |
| 2 | Optional `working_directory` argument not validated | DuneSlide, CVE-2026-50548 | Confine every path argument |
| 3 | Creating `mcp.json` skips the approval that editing needs | CurXecute, CVE-2025-54135 | Create = edit for control plane |
| 4 | Consent keyed by name survives a content swap (MCP + hooks) | MCPoison, CVE-2025-54136 | Hash-pinned consent |
| 5 | Private data + untrusted input + egress in one session | Lethal trifecta / Rule of Two | Rule of Two by construction |
| 6 | Provenance labels dropped at a multi-agent handoff | Taint tracking | Taint survives handoff |
| 7 | Policy engine reads rules the agent can write | Policy placement | Policy engine out of reach |

A matrix on the page replays every scenario with exactly one control on, so
you can see which control stops which bug, and which ones overlap.

## Safety

Everything runs against an in-memory filesystem. Payloads are inert marker
strings, and "execution" is a log line. Nothing touches your disk or network.
The optional WebLLM reviewer only explains a finished trace; it never makes a
security decision.

## Run

```bash
npm install
npm run dev
```

```bash
npm test
```

`npm test` replays every scenario headlessly and checks three things: the
baseline breaches, the fully hardened harness holds, and the scenario's own
control holds by itself.

## Layout

```
src/harness/vfs.js      in-memory filesystem with symlinks and failing canonicalization
src/harness/planes.js   instruction / control / data classification
src/harness/harness.js  tool executor + the seven controls
src/harness/runner.js   replays a scenario, decides breach vs held
src/scenarios/index.js  the seven bug classes
src/llm/                optional local WebLLM incident reviewer
```

## References

- Cato AI Labs, *DuneSlide: two critical RCE vulnerabilities* (Cursor, fixed in 3.0)
- Aim Labs, *CurXecute* (CVE-2025-54135) · Check Point Research, *MCPoison* (CVE-2025-54136)
- Simon Willison, *The lethal trifecta* · Meta, *Agents Rule of Two*

MIT License.
