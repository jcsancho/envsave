# EnvSave — skills.sh launch copy

Drafts you can paste into each channel. Pick whichever you want to post; nothing
here is sent automatically.

Repo: https://github.com/jcsancho/envsave
Install command: `npx skills add jcsancho/envsave`
Non-interactive: `npx skills add jcsancho/envsave -g -y --agent claude-code`

---

## 1. Tweet / X (single post, ~270 chars)

```
New: envsave is now installable as a Claude Code skill.

It hands your agent opaque ids like `es_7a3f2b1e9c...` instead of real
API keys. The agent can read your code, your .env, your transcripts —
it still can't exfiltrate anything useful.

  npx skills add jcsancho/envsave

github.com/jcsancho/envsave
```

### Tweet thread variant (3 tweets)

**1/3**
```
Hot take: every "AI agent reads my repo" workflow leaks a credential
eventually. The fix isn't smarter agents — it's never giving them the
real secret in the first place.
```

**2/3**
```
envsave stores your keys in a local encrypted vault and exposes them
to agents as opaque ids: `es_7a3f2b1e9c8d4f6b`. The id is an HMAC hash
— useless outside your machine, can't be reversed or enumerated.

  const key = get("es_7a3f2b1e9c8d4f6b")
```

**3/3**
```
Now installable as a Claude Code skill — the agent will auto-migrate
hardcoded secrets and process.env reads to envsave.get() calls.

  npx skills add jcsancho/envsave

github.com/jcsancho/envsave
```

---

## 2. Show HN

**Title:** `Show HN: EnvSave – give AI coding agents opaque keys instead of real secrets`

**Body:**
```
Hi HN — I built EnvSave because I kept watching coding agents (Claude
Code, Cursor, etc.) cheerfully read .env files into their context
windows. Once a real OpenAI / Stripe / AWS key is in a transcript,
you've lost control of it: it can be logged, cached, embedded, or
prompt-injected back out.

EnvSave stores secrets in a local AES-256-GCM vault and replaces them
with opaque ids of the form `es_7a3f2b1e9c8d4f6b` — HMAC hashes with
no recoverable mapping to the original name. Your code becomes:

    import { get } from "@envsave/cli";
    const openai = new OpenAI({ apiKey: get("es_7a3f2b1e9c8d4f6b") });

The agent reads "es_7a3f...", which is useless to anyone without the
vault and master password. It can't enumerate other secrets, brute-
force the id, or reverse it.

Day-to-day workflow:
- `envsave init` — set master password, create ~/.envsave/vault.enc
- `envsave set OPENAI_API_KEY sk-...` — stores it, prints opaque id
- `envsave scan` — finds hardcoded secrets and process.env in your repo
- `envsave vercel <KEY>` — pushes to a Vercel project (under both the
  opaque id and the clean name, so prod runtime keeps working)

Local use is free and unlimited. There's a paid tier for cloud backup
/ multi-machine sync — the server only ever sees encrypted bytes.

The new piece I want to share: EnvSave is now distributed as a Claude
Code skill via skills.sh. One command and your agent will auto-migrate
secrets going forward:

    npx skills add jcsancho/envsave

Repo, including the skill content: https://github.com/jcsancho/envsave

Happy to talk about the threat model, opaque-key derivation, or how
the skill triggers in the comments.
```

---

## 3. GitHub Discussion on vercel-labs/skills

**Where:** https://github.com/vercel-labs/skills/discussions (Show & tell category)

**Title:** `envsave – local secret vault that keeps real keys out of agent context`

**Body:**
```markdown
Sharing a skill I just published: **envsave**.

The problem it targets is specific to coding agents: any agent with
shell + file access will eventually read `.env`, paste a secret into
its transcript, or get prompt-injected into exfiltrating one. The
fix here isn't to harden the agent — it's to never give the agent
the real secret.

`envsave` stores secrets in a local AES-256-GCM vault and exposes
them to code via opaque ids:

```ts
import { get } from "@envsave/cli";
const openai = new OpenAI({ apiKey: get("es_7a3f2b1e9c8d4f6b") });
```

The opaque id is an HMAC-SHA256 of the key name — fully one-way, no
trace of the original. The agent sees `es_7a3f...`, which is useless
without the vault and master password.

The skill itself instructs Claude to:
1. Grep the project for hardcoded secrets, `process.env.*`, and `.env`
   reads.
2. Migrate each hit to `envsave.get("es_...")`.
3. Walk the user through `envsave set` for any new keys it finds.

Install:

    npx skills add jcsancho/envsave

Repo (CLI + skill): https://github.com/jcsancho/envsave

Feedback welcome — particularly on the skill prompt design, since
that's the part that benefits most from real-world wear.
```

---

## 4. Reddit — r/ClaudeAI

**Title:** `I built a Claude Code skill that prevents Claude from ever seeing your real API keys`

**Body:**
```
Quick share — I got tired of watching Claude Code read .env files
straight into its context window every time it touched a project.
Once a real OpenAI / Stripe / Anthropic key lands in a transcript
it's effectively leaked: it can be logged, cached, embedded, or
prompt-injected back out by a malicious page or PR description.

So I built **envsave**: a local encrypted vault (AES-256-GCM, master
password) that gives Claude **opaque ids** instead of the real value:

    // Before — Claude sees the key
    const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

    // After — Claude only sees "es_7a3f..."
    import { get } from "@envsave/cli";
    const openai = new OpenAI({ apiKey: get("es_7a3f2b1e9c8d4f6b") });

The opaque id is an HMAC hash of the key name. It's one-way — Claude
can't reverse it, enumerate other ids, or learn what `OPENAI_API_KEY`
was named originally. Without the vault file + master password the
id is useless.

It's now a Claude skill, so installing it teaches Claude to:
- grep your repo for hardcoded secrets, `process.env`, and `.env` reads
- migrate each one to `envsave.get("es_...")`
- prompt you to add any new keys it finds via `envsave set`

Install:

    npx skills add jcsancho/envsave

Local use is free and unlimited. Code's open: github.com/jcsancho/envsave

Curious whether others here have hit the same problem — and how
you're handling secrets in agent loops today.
```

---

## 5. Reddit — r/LocalLLaMA (variant)

Same title and body as r/ClaudeAI, but reframe the intro to be agent-
agnostic since LocalLLaMA covers more than Claude:

**Title:** `Local-vault secret manager that gives coding agents opaque keys instead of real ones`

Replace the first paragraph of the r/ClaudeAI body with:

```
Quick share — I got tired of watching coding agents (Claude Code,
Cursor, Aider, you name it) read .env files straight into their
context windows. Once a real OpenAI / Stripe / Anthropic key lands
in a transcript it's effectively leaked: it can be logged, cached,
embedded, or prompt-injected back out by a malicious page or PR.
```

Rest of the body is identical.

---

## Posting checklist

- [ ] Tweet (or thread)
- [ ] Show HN
- [ ] GitHub Discussion on vercel-labs/skills
- [ ] r/ClaudeAI post
- [ ] r/LocalLLaMA post (optional — same content, different intro)
- [ ] After ~24h: check skills.sh leaderboard for envsave appearing
      via telemetry from real installs
