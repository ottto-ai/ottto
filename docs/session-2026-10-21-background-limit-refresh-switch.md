# One background limit refresh switch for Claude Code and Codex

The switch means: Ottto contacts Claude's and ChatGPT's servers in the
background to read usage limits, using the sign-in already on this Mac. There
is one per provider, with the same meaning. Both are on until the owner
chooses, so nothing changes for anyone who never touches them.

Off stops every background limit read for that provider, for every login on
this Mac, the default login included, and the sign-in renewal the daemon does
for it (Claude's refresher; for Codex the scheduled `codex app-server` reads
are the renewal, including the once-a-day same-login read). A person's Refresh
limits, setup and sign-in checks still read, and saved readings are served as
they age. Nothing new is collected.

Codex: new settings fields `background_quota_refresh_consent` and
`background_quota_refresh_consent_chosen` in the Codex account settings; status
field `background_quota_refresh` on the Codex accounts status (presence is the
capability bit); command `codex_account_set_quota_refresh_consent` at
command-scoped protocol version 27. The scheduler returns before its process
scan and spawns while off, and checks the setting again under the settings lock
before each read. A home never read while off reports
`codex_quota_background_refresh_off`. An older companion's status refresh,
which cannot be told from its timer, reads nothing while off.

Claude: the existing "Keep my Claude accounts signed in" consent
(`claude_account_set_upkeep_consent`) now also withholds the status lane's
`oauth/usage` reads for every login while off. Before, it stopped only the
refresher and the collection of expired saved slots; the default login and
saved slots with a valid token kept being read. Explicit refresh, setup
triggers and collections outside the lane still read. The status carries
`consent_covers_limit_reads: true` so a client can say what the switch covers;
an older client ignores it and its toggle keeps working.

Validation:

- settings default on, off, on, chosen, an older daemon's file, and a
  downgrade rewrite that drops the fields;
- protocol round trip, v27-only acceptance, and additive status fields;
- the Codex schedule reads nothing while off (also a day later), Refresh and
  the setup read still read, and the schedule resumes when switched on;
- Claude passes make no request for the default login or a slot while off and
  serve the stored reading; setup, account checks and Refresh still read; the
  schedule resumes when switched on.
