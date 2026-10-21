---
title: "Your Coding Agent Will Be Persuaded. Seven Harness Controls for That Day"
published: false
description: "A browser lab that replays DuneSlide, CurXecute, MCPoison, the lethal trifecta and multi-agent taint bugs against an agent harness with every defence on a switch."
tags: security, ai, agents, webdev
cover_image: https://raw.githubusercontent.com/vishalmysore/duneSlideDemo/main/docs/images/01-overview.jpg
canonical_url: https://github.com/vishalmysore/duneSlideDemo
---

Coding agents read a lot of text nobody on the team chose: search results, MCP tool responses, issue comments, dependency READMEs, web pages. Any of it can carry instructions. Models are getting harder to persuade, but "harder" is not "impossible".

So the useful question is not *"will the model follow injected text?"* It is *"what happens next if it does?"*

The answer lives in the **harness**: the deterministic code between the model's tool calls and the machine. To make that concrete I built **DuneSlide Harness Lab**, a small browser app that replays seven recent bug classes against a single harness. Every defence is a switch, and the model is assumed to be already compromised.

👉 **Live demo:** https://vishalmysore.github.io/duneSlideDemo/
👉 **Code:** https://github.com/vishalmysore/duneSlideDemo

Everything runs in your browser against an in-memory filesystem. Payloads are inert marker strings and "execution" is a log line, so nothing touches your disk or network.

---

## The idea that ties it together: two planes

Most teams review `AGENTS.md` and `.cursor/mcp.json` the same way, as "agent config". They are not the same kind of file.

| Plane | Who reads it | Examples | What can go wrong |
|---|---|---|---|
| **Instruction plane** | The **model** interprets it | `AGENTS.md`, docs, tool results, web pages | Persuasion |
| **Control plane** | The **harness** executes it, without asking anyone | `mcp.json`, hooks, skills, devcontainer, task runners | Execution |

That split explains most of the incidents below. An attacker only has to win once on the instruction plane, by talking the model into writing **one** control-plane file. After that, perfectly deterministic harness behaviour does the dangerous part, every session, with no further persuasion needed.

So the lab never asks whether the model resisted. It scripts the agent as already persuaded and asks only one question: **does the harness hold?**

---

## How the lab works

Pick a bug class on the left. The page runs the same scripted, compromised agent twice, side by side:

- **Baseline harness:** every control off.
- **Your harness:** whichever controls you switch on. By default, only the one that closes the selected bug.

Each trace shows:

- ☣ the injected text and where it came from (`mcp:search`, `web:page`, …)
- → the tool call the agent made, tagged **tainted** when it was driven by untrusted input
- the harness decision: ✓ allowed, ⛔ denied, ⏸ held for a human, ⚠ a warning the baseline silently ignored
- ✖ the breach, if one happened

Below the runs, a **virtual filesystem** view labels every file as instruction plane, control plane or data, and flags anything the agent wrote outside the workspace.

The harness itself is about 250 lines of plain JavaScript. Every tool call goes through one entry point (snippets in this post are lightly simplified):

```js
async call(tool, args, prov = { tainted: false, source: 'user' }) {
  this.log('call', `${tool}(...)`, { tainted: prov.tainted, source: prov.source })
  return this['tool_' + tool](args, prov)
}
```

`prov` is provenance: did this call come from the user, or from text the agent read somewhere? That label matters in three of the seven scenarios.

---

## 1. DuneSlide: the check that turns itself off

**Reference:** CVE-2026-50549, reported by Cato AI Labs, fixed in Cursor 3.0.

A symlink inside the project points somewhere the safety check cannot resolve. A *fail-open* resolver gives up and approves the path **as it looks**, inside the workspace. The operating system, which does not care what the checker could see, then follows the link outside the project.

![Symlink fallback: baseline breached, fail-closed harness holds](https://raw.githubusercontent.com/vishalmysore/duneSlideDemo/main/docs/images/02-symlink-runs.jpg)

Look at the left trace: *checker approved `/workspace/vendor/cache/autostart.sh` but the write landed at `/home/dev/.config/autostart.sh`.* That one line is the whole bug class. The filesystem view makes the result obvious:

![File written outside the workspace](https://raw.githubusercontent.com/vishalmysore/duneSlideDemo/main/docs/images/03-symlink-filesystem.jpg)

The fix is one branch in the canonicalizer:

```js
canonicalize(path, base = WORKSPACE) {
  const apparent = join(base, path)
  try {
    return { ok: true, path: this.vfs.realpath(apparent) }
  } catch (err) {
    if (this.c.failClosed) return { ok: false, reason: `${err.code} while resolving ${err.path}` }
    return { ok: true, path: apparent, fellBack: true }   // ← the bug: trust what you could not verify
  }
}
```

**Harness rule:** every canonicalization, signature or provenance check **denies on error**. It never falls back to the original input.

This is the pattern I worry about most, because it is invisible in normal use. The fallback only fires on the weird paths an attacker chooses.

---

## 2. DuneSlide: the argument nobody checked

**Reference:** CVE-2026-50548, same report, same fix.

The terminal tool validated the **command** against an allowlist, but not its optional **`working_directory`** argument. `npm test` is on the allowlist. `npm test` run from outside the project is a different thing entirely.

![working_directory escape: baseline runs in /home/dev, hardened denies](https://raw.githubusercontent.com/vishalmysore/duneSlideDemo/main/docs/images/04-working-directory.jpg)

**Harness rule:** canonicalize and confine **every** argument that names a location, not just the obvious `path` parameter. Optional arguments are where reviews stop looking.

---

## 3. CurXecute: create is not edit

**Reference:** CVE-2025-54135, reported by Aim Labs.

Editing `.cursor/mcp.json` needed approval. **Creating** it did not, and the harness started whatever server the new file described. The model only had to be talked into writing one new file.

![CurXecute: baseline auto-starts the new MCP server, hardened holds the creation for approval](https://raw.githubusercontent.com/vishalmysore/duneSlideDemo/main/docs/images/05-curxecute.jpg)

In the lab the gate is a single condition:

```js
const existed = this.vfs.get(r.path)?.type === 'file'
const gated = existed || this.c.createIsEdit   // baseline: only edits are gated
```

**Harness rule:** for control-plane files, creation needs the same approval as an edit. More generally, treat **create-vs-edit approval asymmetry as a bug class to hunt for deliberately**. Look for it in every place where your harness has an "existing file" fast path.

---

## 4. MCPoison: approving names instead of content

**Reference:** CVE-2025-54136, reported by Check Point Research.

The user approves a harmless MCP server once. A later commit to the shared repo swaps its command. Because consent was keyed by **name**, the approval silently still applies.

The lab extends this to a lifecycle **hook** as well, because the same mistake applies to every control-plane file:

![MCPoison: day-2 swap runs on baseline, hash-pinned consent re-prompts](https://raw.githubusercontent.com/vishalmysore/duneSlideDemo/main/docs/images/06-mcpoison.jpg)

Day 1 is identical on both sides. On day 2 the baseline happily starts both swapped commands. The hardened harness notices that the content changed since approval and refuses to load either file until a human looks again.

```js
const h = await sha256(f.content)
approved = this.consent.some(a => a.path === f.path && a.hash === h)
```

**Harness rule:** approve **content, not names**. One changed character resets approval, and that applies to hooks, skills and devcontainer configs too, not only `mcp.json`.

---

## 5. The lethal trifecta, closed by construction

**Reference:** Simon Willison's *lethal trifecta*; Meta's *Agents Rule of Two*.

Private data, untrusted content, and a way to send data out. A session holding all three can be steered into leaking the first through the third. Here the agent reads `.env` to debug a test, opens a linked issue (attacker-controlled text), and is then asked to "report diagnostics".

![Trifecta: the third leg is denied by construction](https://raw.githubusercontent.com/vishalmysore/duneSlideDemo/main/docs/images/07-trifecta.jpg)

The harness tracks which legs the session holds and refuses the call that would complete the set:

```js
acquire(leg, why) {
  const next = new Set(this.legs).add(leg)
  if (this.c.ruleOfTwo && next.size === 3) return deny(`${why} would complete the lethal trifecta`)
  this.legs = next
  return true
}
```

**Harness rule:** use the trifecta as a per-session checklist, and make domain agents narrow enough that most sessions never hold all three legs at all. *Rule of Two by construction, not by a sentence in the system prompt.*

---

## 6. Multi-agent: labels lost at the handoff

This is the hard one, and the open question that started this project. In multi-agent setups, where does provenance go when one agent hands an artifact to another?

A **researcher** agent reads a blog post (untrusted) and hands its notes to a **coder** agent. If the "this came from the web" label is dropped at the boundary, the coder sees what looks like trusted agent output, and writes a control-plane hook.

![Handoff: dropped labels let the coder write a hook; kept labels block it](https://raw.githubusercontent.com/vishalmysore/duneSlideDemo/main/docs/images/08-handoff.jpg)

On the right, provenance survives the handoff (`tainted=true, source=web:blog`), and the coder's write is refused:

```js
if (plane === 'control' && prov.tainted && this.c.taintHandoff)
  return deny(`tainted input (from ${prov.source}) cannot write control-plane file`)
```

**Harness rule:** provenance labels travel **with the artifact**, not with the agent. Tainted input may inform data changes; it never drives control-plane changes.

---

## 7. Who guards the guard?

If the policy engine reads its rules from a file the agent can write, the first injected step relaxes the rules and the second step does the damage.

![Policy tamper: baseline rewrites its own rules, hardened keeps the policy out of reach](https://raw.githubusercontent.com/vishalmysore/duneSlideDemo/main/docs/images/09-policy.jpg)

In the hardened harness the rules are a frozen object that never lives on the agent-writable filesystem, and their hash is re-checked on every decision:

```js
async rules() {
  const h = await sha256(JSON.stringify(this.policy))
  if (h !== this.policyHash) throw new Error('policy hash mismatch')
  return this.policy
}
```

**Harness rule:** keep the policy engine off the agent-writable filesystem. On a laptop that can be a read-only mount; in a multi-agent system it should be a separate process the agents cannot address at all.

---

## Which control stops which bug?

The last panel replays **every** scenario with **exactly one** control switched on:

![Control-by-bug matrix](https://raw.githubusercontent.com/vishalmysore/duneSlideDemo/main/docs/images/10-matrix.jpg)

The diagonal is what you would expect: each bug has the control designed for it. The off-diagonal ticks are the interesting part:

- **Create = edit** also stops the multi-agent case, because the coder's tainted hook is held for approval before it ever reaches disk.
- **Hash-pinned consent** also stops CurXecute and the handoff case. A brand-new control-plane file has no approved hash, so the harness refuses to load it.
- **Taint survives handoff** also stops CurXecute, because the injected `mcp.json` write is tainted.

That overlap is defence in depth you can actually see. It is also a warning: the symlink, working-directory, MCPoison, trifecta and policy rows each have **only one** tick. Remove that one control and nothing else catches it.

---

## Optional: a local model as incident reviewer

At the bottom of the page you can load a small model locally with WebLLM (WebGPU, no server, no API key) and ask it to explain your run in plain words.

Note what the model does **not** do: it never makes a security decision. It reads a finished trace. Every allow, deny and hold above came from plain, testable code, which is the point of the whole exercise.

---

## Using this on your own harness

You do not need the demo to apply the ideas. A checklist that falls straight out of it:

1. **Classify every path your agent can touch** as instruction plane, control plane or data. Control-plane files deserve the strictest review, even though they are usually the smallest.
2. **Grep for fallbacks.** Every `catch` around canonicalization, signature or provenance checks should end in a deny.
3. **List every argument that names a location** in every tool, including the optional ones, and confirm each one is confined.
4. **Hunt create-vs-edit asymmetries** wherever an "already exists" check changes the approval path.
5. **Pin consent to content hashes** for MCP config, hooks, skills, devcontainers and task runners.
6. **Write down which trifecta legs each agent profile can hold.** If a profile can hold all three, split it.
7. **Carry provenance across every agent boundary**, and refuse control-plane writes from tainted input.
8. **Put the policy engine somewhere the agent cannot write**, and verify it on every decision.

The repo includes a headless check (`npm test`) that replays every scenario and asserts three things: the baseline breaches, the fully hardened harness holds, and each scenario's own control holds by itself. It is a small pattern worth copying for your own harness tests: one test per bug class, run with the control both on and off.

---

## Try it

- **Live demo:** https://vishalmysore.github.io/duneSlideDemo/
- **Code:** https://github.com/vishalmysore/duneSlideDemo
- **The companion demo** on how a harness makes a model *useful*: https://vishalmysore.github.io/harnessEngineeringDemo/

Assume your model will be persuaded on some day. The goal of harness engineering is to make that day boring.

### References

- Cato AI Labs: [DuneSlide, two critical RCE vulnerabilities in Cursor](https://www.catonetworks.com/blog/duneslide-two-critical-rce-vulnerabilities)
- Tenable: [FAQ on CurXecute and MCPoison (CVE-2025-54135, CVE-2025-54136)](https://kr.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)
- The Hacker News: [Cursor AI code editor fixed flaw](https://thehackernews.com/2025/08/cursor-ai-code-editor-fixed-flaw.html)
- Simon Willison: [The lethal trifecta for AI agents](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
