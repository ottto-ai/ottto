# How Ottto sees your Claude accounts

One Mac often uses more than one Claude account: a work account in the
terminal, a personal account in the Claude desktop app. Ottto's rule for all
of them is the same: **a number is shown under an account only when Ottto can
prove it belongs to that account. Anything unproven shows as unknown - it is
never guessed and never borrowed from another account.**

This page explains what Ottto can and cannot see, per surface, and why the
app sometimes shows a plan without numbers or a "Partial view" badge.

## Where your Claude accounts live

- **The terminal login (Claude Code CLI).** One credential slot per machine.
  Running `/login` as a different account replaces it - the previous account
  is signed out of the terminal. Every terminal session, including the
  terminal pane inside the Claude desktop app, uses this credential.
- **The desktop app login.** Separate from the terminal login. Chat sessions
  in the app run under whichever account the app is signed into - which can
  be a different account than the terminal, at the same time.

Sessions started from the app bill the app's account. Sessions started from a
terminal bill the terminal's account. Ottto tracks them separately.

## What Ottto can read, per surface

**Terminal account - the full picture, while you use it.** For the account
that owns the terminal credential, Ottto reads Claude's own usage summary:
the 5-hour session window, the weekly window, per-model weekly limits (a
single model can be exhausted while the account-level weekly still looks
fine), and usage-credit balances such as an organization's monthly spend
limit. This is the most complete view Claude exposes, and it is only
readable while the terminal credential stays fresh - Claude rotates it as
you work.

**Status line renders - a partial view.** Claude Code's status line reports
only the session and weekly percentages. It carries no per-model limits and
no credit balances, so a status-line-sourced reading can say "weekly 18%,
fine" while a model limit sits at 100% or a monthly spend cap is already
hit. Ottto marks quota that comes only from this source with a **Partial
view** badge rather than presenting it as the whole picture.

**Desktop app account - identity, but no numbers.** The app keeps its login
sealed (its tokens are encrypted by the app, and Ottto does not decrypt
anything). Ottto can see which account the app is signed into and attribute
the app's sessions and their cost to it, but it cannot read that account's
quota. This is why a desktop-only account shows its plan as "not verified"
with no meters: Ottto knows the account exists and what it spends, and
honestly does not know its limits.

## What this looks like on one two-account Mac

- The terminal account shows a full card: plan, session and weekly meters,
  per-model limits, credits.
- The app account shows its own card with sessions and cost attributed to
  it, plan unverified, no meters.
- The two never mix. If Ottto cannot tell which account a reading belongs
  to, the reading is dropped or shown as unattributed - not assigned to
  whichever account happens to be signed in.

## Tips

- To get full quota visibility for an account, use it from a terminal at
  least occasionally - the terminal credential is the only full-picture
  source.
- Remember `/login` replaces the terminal account rather than adding one.
  After switching, the previous account's terminal readings stop refreshing
  and will show their age honestly.
- The badge and the "not verified" label are not errors. They are Ottto
  telling you exactly how much it can prove.
