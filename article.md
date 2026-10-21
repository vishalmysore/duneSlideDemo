# Your Model Will Be Persuaded. Build the Harness for That Day.

Coding agents read a lot of text they did not choose: search results, MCP tool
responses, issue comments, README files in dependencies. Any of it can carry
instructions. We can make models harder to persuade, but not impossible to
persuade. So the useful question is not "will the model follow the injected
text?" It is "what happens next if it does?"

The answer lives in the harness: the deterministic code between the model's
tool calls and the machine. DuneSlide Harness Lab is a small browser demo that
makes this concrete. It replays seven recent bug classes against one harness,
puts every defence on a switch, and assumes the model is already compromised.

## Two kinds of files

Teams usually review `AGENTS.md` and `mcp.json` the same way. They are not the
same kind of file.

- **Instruction plane.** `AGENTS.md`, docs and tool output are read by the
  model. They can persuade, but they cannot act on their own.
- **Control plane.** `mcp.json`, hooks, skills and devcontainer configs are
  executed by the harness. Nobody is asked again.

That split explains most of the incidents. An attacker only needs to talk the
model into writing *one* control-plane file. From then on, the harness does
the dangerous part reliably, every session.

## Seven bug classes, seven controls

**1. A check that turns itself off (DuneSlide symlink).** A link inside the
project points somewhere the safety check cannot resolve. A fail-open resolver
gives up and approves the path as it looks. The operating system then follows
the link outside the project. *Rule:* every canonicalization, signature or
provenance check denies on error. It never falls back to the original input.

**2. The argument nobody checked (DuneSlide working directory).** The terminal
tool checked the command against an allowlist but not the optional working
directory. An allowed command run from the wrong place is no longer safe.
*Rule:* validate every argument that names a location.

**3. Create is not edit (CurXecute).** Editing the MCP config needed approval.
Creating it did not, and the harness started whatever server it described.
*Rule:* for control-plane files, creation needs the same approval as an edit.
This asymmetry is a bug class worth hunting deliberately.

**4. Approving names instead of content (MCPoison).** A user approved a harmless
server once. A later commit swapped its command, and the approval still held.
*Rule:* pin consent to a content hash. One changed character resets approval.
That applies to hooks, skills and devcontainer configs, not only MCP.

**5. Three legs in one session (lethal trifecta).** Private data, untrusted
input and a way to send data out. A session holding all three can be steered
into leaking. *Rule:* build domain agents narrow enough that the third leg is
denied by construction, not by a sentence in the prompt.

**6. Labels lost at the handoff (multi-agent taint).** A research agent reads a
web page and hands notes to a coding agent. If the "this came from the web"
label is dropped at the boundary, the coder treats injected text as trusted.
*Rule:* provenance travels with the artifact. Tainted input can inform data
changes, never control-plane changes.

**7. Who guards the guard (policy placement).** If the policy engine reads its
rules from a file the agent can write, the first injected step relaxes the
rules and the second does the damage. *Rule:* keep the policy engine off the
agent-writable filesystem and verify its hash on every decision.

## What the demo shows

Each scenario runs twice side by side: a baseline harness with every control
off, and your harness with the switches you choose. The trace shows each tool
call, where the injected text came from, and the exact decision the harness
made. A matrix replays every scenario with only one control on, so you can see
which control stops which bug and where they overlap. For example, "create =
edit" also blunts the multi-agent case, because the tainted write gets held
for approval.

Everything runs in the browser against an in-memory filesystem. The payloads
are inert markers. An optional local model (WebLLM) can read a finished trace
and explain it in plain words, but it never makes a security decision. That is
the point of the whole exercise.

## Why this is useful

- **A review checklist.** Classify every file the agent can touch as
  instruction, control or data. Then ask the seven questions above of each
  control-plane path.
- **A shared vocabulary.** "Fail-open fallback", "create-vs-edit asymmetry" and
  "name-keyed consent" are easier to find once they have names.
- **A design target.** Assume the model will be persuaded on some day, and make
  sure that day is boring.

Try it: https://vishalmysore.github.io/duneSlideDemo/
