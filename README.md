# Ottto

Ottto is one tool to see what is right and what is wrong with your coding agents.

It works with multiple coding agents, such as Claude Code and Codex (ChatGPT).

- **What should you optimize:** where your cost goes and which setup problems hold your agents
  back, based on your own sessions, setup and repository structure, so you fix what matters first.
- **Spend less without losing quality:** the biggest savings first, with changes that keep or
  improve how well your agents work, and a before-and-after view to check them.
- **Everyday work:** usage, plan limits and cost across your agents, logins and Macs, at a glance.

This repository is Ottto's local service, written in Rust. It runs on your Mac, reads what your
agents write and keeps your usage there. The Mac app and the web dashboard build on it.

<!-- Product visual: coming soon -->

## What you get

- **Ottto for Mac:** your plan limits and credits, and a clear view of your current sessions'
  usage.
- **The Ottto web app:** usage, analysis and recommendations across all your agents, sessions,
  Macs and repositories, including cloud agents. Requires an Ottto account.
- **Ottto for Claude and ChatGPT:** a connector that brings the same insights into the chat you
  already use. Requires an Ottto account.

## Get started

**With the Mac app** (Apple silicon, macOS 14 or later; signed and notarized):

1. [**Download Ottto for Mac**](https://install.ottto.net/ottto-local-platform/releases/stable/latest/Ottto-macos-arm64.dmg).
2. Sign in to your Ottto account in the app. This connects your Mac.

Prefer Homebrew? This installs the same app:

```bash
brew install --cask ottto-ai/tap/ottto-app
```

**Command line only, without the app** (the `ottto` CLI and background service):

```bash
brew install ottto-ai/tap/ottto && brew services start ottto
```

Then run `ottto setup` to sign in and connect your Mac.

Never install both on one Mac: they share one background service, and `brew services` takes it
over from the app. More options, updates and uninstall: [docs/install.md](docs/install.md).

## Everyday work

| | What you get |
| --- | --- |
| **Every agent in one view** | Multiple agents and AI providers side by side, for example Claude Code and Codex · subscription or API key · Bedrock and Vertex AI billing (org admins) |
| **Plans and limits** | Several subscriptions, also for the same provider: up to 10 Claude Code and 10 Codex logins per Mac · 5-hour, weekly and other plan limits, and credits |
| **Cost breakdowns** | By agent, model, repository, machine, subscription and token type · day, week or month · CSV export |
| **Sessions and sub-agents** | Timeline, tokens and models per run · which agent started which sub-agent, and the distribution of work and cost across them |
| **Many Macs, one account** | Every Mac you connect adds up in one account · logins stay separate, never pooled or rotated |

## What should you optimize

After you sign in, Ottto imports recent sessions in the background, so findings start from history
you already have. It shows clear paths to make your agents more efficient, do better work and cost
less without compromise: not only where you can save, but where the biggest savings are.

| | What you get |
| --- | --- |
| **Where to save most** | Findings from your own sessions and setup, biggest first, with evidence · a prompt you can paste into your agent |
| **Recommendations** | A Recommendations page with prioritized suggestions for your account |
| **Setup that holds agents back** | Nested AGENTS.md Claude Code does not load on its own · a CLAUDE.md too large to load · MEMORY.md past its limit |
| **What fills the context window** | Instruction and memory files, skills and MCP tools at start · files read, search and tool output while working |
| **Before and after** | Cost per request before and after you change the default model, reasoning effort or fast mode · a comparison, not proof of cause |
| **Hidden and repeated runs** | Full view of scheduled tasks, automations and repeated work, what they cost, and how to optimize them |

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/how-it-works-dark.svg">
    <img alt="Claude Code, Codex and other coding agents write session files and telemetry on your Macs; the Ottto service on each Mac reads them and sends only usage metadata and optional labels to your Ottto account, while prompts, code, transcripts and sign-in tokens never leave the Mac; the same service also runs on your servers, for coding agents or any AI agent in production, and your org admin can connect Amazon Bedrock or Google Vertex AI billing and usage directly to the account, which prices your usage and shows it in the web app (costs, plan limits, session optimizations, families, graphs and automations), recommendations to save money and improve agent quality, and a plugin for Claude and any AI agent." src="docs/assets/readme/how-it-works-light.svg" width="860">
  </picture>
</p>

Ottto is not a proxy or an AI gateway: it does not reroute model requests or change API keys or
base URLs. This repository has four parts:

- **`ottto-service`:** the background service. It reads your agents' session files, keeps your
  usage on the Mac and, once you connect, uploads usage metadata.
- **`ottto`:** the command-line tool for setup, status and updates. Its commands have `--json`
  output and documented exit codes, so scripts and your agents can use it, including over
  SSH, with the [agent skills](docs/agent-adapters.md). The Mac app doesn't add it to PATH.
- **Agent readers:** one per coding agent, turning its session files into usage records.
- **Connector SDK:** for adding a new agent ([connectors/README.md](connectors/README.md)).

## What Ottto does on your Mac

- **Does the private work locally.** Your transcripts are read and added up on your Mac. Only
  usage metadata and the short labels below leave it, and only to show your usage and
  recommendations. Your conversations stay on the Mac; you can turn the labels off.
- **Reads** the session files the coding agents write (for example `~/.claude/projects` for
  Claude Code and `~/.codex/sessions` for Codex) and a few named settings from their config.
- **Uploads nothing about your usage until you connect** this Mac to an Ottto account. Then it
  sends usage metadata, never your transcripts, code, tool output or sign-in tokens
  ([what is sent](#privacy)).
- **Sends session titles, repository names and MCP tool details by default.** Every few hours it
  starts the local MCP servers your agents use, lists their tools, and sends each tool's name,
  description and input schema. Remote MCP servers are listed by name only and never contacted.
  In the web dashboard, **Readable labels** turns all of these off,
  and **MCP inventory harvesting** only the MCP part.
- **Keeps track of your plan limits** for every login, if you want it to: through Claude Code for
  Anthropic and through the Codex CLI for Codex, using the sign-ins those tools already have. Ottto
  never signs in for you. Each can be turned off.
- **Runs short agent commands.** To keep your Claude logins signed in, it runs `claude -p /usage`
  near token expiry; this sends no prompt and uses no plan limits, and **Keep my Claude accounts
  signed in** turns it off. When you set up an app or press Verify, it sends one short test prompt,
  and retries it in the background while a check is failing. These runs don't count as your usage.
- **Collects Claude Code's telemetry on your Mac** for a complete picture of your usage. Setup
  points Claude Code's telemetry to a receiver on 127.0.0.1 (in `~/.claude/settings.json` only)
  and adds Ottto's status line, which shows how full the context window
  is and gives fresher limits while you work. The raw telemetry never goes to Ottto's servers; only its content-free numbers (model,
  effort, speed, reported cost, token counts) feed the usage Ottto uploads.

The Mac app is a client of this service: it doesn't read transcripts or agent credentials and
uploads no usage itself. Details: [docs/privacy.md](docs/privacy.md).

## Privacy

**What Ottto never uploads:** your transcripts and full conversations, including your agents'
responses; code, file contents, and tool and command output; your agents' sign-in tokens, API keys,
cookies and passwords; instruction, memory and skill text, and absolute file paths (except text an
MCP server itself puts in a tool description or input schema).

**What is sent, only once you connect this Mac:** usage metadata, so Ottto can price your usage:
token counts, session timing and activity counts, plan limit usage, account and workspace metadata
(such as login emails, plans and ids), agent settings, one-way hashes of paths and repeated prompts,
and basic details about the Mac. Diagnostics are a separate upload, sent only when you approve it.
They are redacted before you see or send them: local paths, secret tokens, account and machine
ids, raw prompts and command output are removed.

**Readable labels** (on by default) also sends session titles or a short prompt start, project and
repository names, skill, agent and MCP names, and MCP tool details; turning it off stops all of
those. **Session links** (off by default) sends pull request, issue and commit links. Your Claude
Code sign-in is used only with Anthropic, to read your usage and its account, and never sent to Ottto.
Full detail: [docs/privacy.md](docs/privacy.md) and the [privacy policy](https://app.ottto.net/privacy).

## Open source

This repository holds Ottto's local service in Rust: the `ottto` CLI, the `ottto-service` service,
the connector SDK and the agent readers. Ottto.app and the hosted dashboard are not here. Build and
test: [CONTRIBUTING.md](CONTRIBUTING.md). Add an agent: [connectors/README.md](connectors/README.md).

[Docs](docs/README.md) · [Install](docs/install.md) · [Troubleshooting](docs/troubleshooting.md) ·
[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md) ·
Apache-2.0 [license](LICENSE)

<p align="center"><sub><i>Three t's: one for every agent you forgot was still running.</i></sub></p>
