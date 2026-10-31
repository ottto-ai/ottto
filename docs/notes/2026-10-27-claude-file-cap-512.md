# Claude transcript admission at 512 MiB

Claude Code JSONL files up to 512 MiB can enter the existing native streaming
parser. Pi stays at 256 MiB; Codex stays at 2 GiB. The 16 MiB physical-line cap,
1 GiB history-page budget, RAM-cache limits, and heap-visit limit are unchanged.

Files above the Claude cap retain explicit oversized loss, incomplete census,
content-driven retries and the six-hour recovery floor. Shrinking below the cap
allows a native read; discovery alone never grants read authority. Full audits,
reproof, scheduling and path-twin behavior remain unchanged.

Regression coverage checks discovery and opened-descriptor admission at 300 MiB
for Claude versus Pi, exact source boundaries, and oversized/shrink/grow loss.
The existing oversized pipeline cases now use sparse files above 512 MiB.
A macOS-only test populates approximately 500 MiB with unique usage records,
text and tool results, parses/finalizes in a fresh child process, verifies exact
request/token totals and prints RSS/physical-footprint peaks. Those observations
establish no additional memory limit or budget; they exclude the daemon baseline,
telemetry joins, uploads and cache pressure.

This admission-only change adds no persisted field and changes no upload body,
ACK, fingerprint, identity, checkpoint or proof algorithm. More previously
oversized Claude content becomes eligible for the same native proof path.
