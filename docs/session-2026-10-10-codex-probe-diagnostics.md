# Precise failure messages for the Codex rate-limit probe

When the local Codex app-server rate-limit probe failed, the existing
`codex_usage_probe_failed` diagnostic said only "account/quota read failed" or
"rate-limit read timed out". That message did not say which request failed,
whether Codex answered with an error or simply went away, or whether the
deadline was really reached. This change makes the fixed producer text precise.
The diagnostic code, wire shape, severity and polling schedule are unchanged.

## Messages

- **JSON-RPC errors** name the request and keep only the numeric error code:
  `Codex app-server {initialize|account|quota} RPC failed with code N.`, or
  `... failed without a numeric code.` Provider error messages and `data` are
  never copied.
- **Output closed** (natural end of stdout) names the phase that was waiting:
  `Codex app-server stdout closed during {initialize|account|quota}; ...`.
  The child's exit code or signal is added only when the child had already
  exited before cleanup; otherwise the message says termination was not
  observed. The collector's own cleanup kill is never reported as the child's
  exit.
- **Deadline** keeps the existing 20-second bound and names the phase:
  `Codex app-server {phase} read timed out.`
- **Read errors** on the app-server's stdout now end the reading with the fixed
  text `Codex app-server stdout read failed.` instead of a silent end.

An `initialize` error is recorded, not acted on: the loop continues as before,
so an app-server that rejects `initialize` but still answers the account and
quota requests is still read successfully. If the session then ends without a
reading, whether by an account or quota RPC error, a closed stdout or the
deadline, the `initialize` error is the message: it is the likelier cause.

Nothing else changes: the handshake, response parsing, stdin lifetime,
credential and home handling, resolver, 20-second deadline, 256 KiB line,
256-message and 2 MiB total output bounds, channel size and cadence.

## Tests

A scripted app-server (synthetic Python fake, no provider calls) covers:

- an `initialize` error with a numeric code, an `initialize` error followed by
  successful account and quota answers (still a reading), and one followed by
  an account error (the `initialize` error is reported);
- account versus quota JSON-RPC errors, and an error without a numeric code;
- stdout closing during `initialize` (exit code 2, signal 15) and during the
  quota request, accepting only the observed exit or "not observed";
- the real 20-second deadline while the account request is pending;
- the 256 KiB line, 256-message and 2 MiB total bounds, with their existing
  messages;
- provider error text and data markers never appearing in any message.

Unit tests check the fixed text for a stdout read error and call the
end-of-session helper directly on already-reaped children: exit code 3 and
signal 15 are reported exactly, a still-running child is "not observed", an
earlier `initialize` error wins, and the deadline makes no exit claim.
