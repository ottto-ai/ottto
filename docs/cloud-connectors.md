# Cloud Connectors

Connect Amazon Bedrock or Google Vertex AI at <https://app.ottto.net/connections>.
The web flow creates a read-only, keyless connection and tests it before
saving. Bedrock can also connect through the Ottto app and CLI on a paired Mac.

## Connect Bedrock from the CLI

Use the release Ottto app, AWS CLI v2 with `configure export-credentials`, and
an Ottto workspace where command-line connect is enabled. In the app's
Settings, choose **Set up command-line connect** once. You need to be a current
workspace admin with a verified email address.

```bash
ottto cloud connect --source bedrock
ottto cloud connect --source bedrock --profile billing --json --watch
```

The CLI uses your AWS sign-in to create one CloudFormation stack with a read-only
role in `us-east-1`. AWS billing permissions cover more than Bedrock. Ottto
reads Bedrock costs and reads Bedrock CloudWatch usage numbers only if you
add `--metrics`. Use `--reconnect` to replace a connected AWS account.

Approve saving the connection with Touch ID in the Ottto app or a passkey in
your browser. Ottto checks access before saving, then emails workspace admins
when a connection is saved from the Mac. If you leave or the wait times out,
run the printed resume command with the same AWS account. It repeats the
request that started the attempt and names that attempt, so Ottto picks it
up, or reports it saved or ended, instead of creating another stack. Include
`--restart` only when you want to replace an open attempt.

`--json` prints the final result. Add `--watch` for NDJSON progress and a final
event. The final result includes the attempt ID, a next action, resume
arguments and a status command for the attempt. A delete command for a stack
appears only after `ottto cloud cancel` (or a restart) has ended its attempt
without saving. When status shows an attempt cancelled or expired, the CLI
prints that cancel command first, because a save may still be finishing. If
command-line setup is unavailable, follow the URL, which opens the Ottto
website this Mac is connected to, to complete it in the browser.

## Read status or cancel setup

```bash
ottto cloud status --json
ottto cloud status --source bedrock --json
ottto cloud status --source vertex --json
ottto cloud status --attempt <id> --json
ottto cloud cancel --attempt <id> --json
```

Status is read-only. Cancel ends the selected setup from this Mac, or confirms
that it already ended or saved. Any AWS stack remains in your account. When
Ottto confirms the setup ended without saving and knows the stack ARN, the CLI
prints a separate command you can run to delete the stack. Use the full ARN in
that command.

## Retired commands

The earlier `ottto cloud materials`, `plan`, `register`, `test`, and `sync`
commands have been removed. Use `ottto cloud connect` for Bedrock or complete
setup in the web app.
