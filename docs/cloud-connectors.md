# Cloud Connectors

Connect AWS (Bedrock) and Google Cloud (Vertex AI) to Ottto in the web app at
<https://app.ottto.net/apps>. The web flow creates a read-only, keyless
connection in your cloud account and tests it before saving. The local daemon
and the `ottto` CLI do not create, change, test or sync cloud connectors.

## Status from the CLI

`ottto cloud status` is a read-only JSON view of the connectors on the
connected Ottto account:

```bash
ottto cloud status --json
ottto cloud status --source bedrock --json
ottto cloud status --source vertex --json
```

The daemon reads status through its setup-run session; the command never
saves configuration or starts a sync.

## Retired commands

Earlier releases had `ottto cloud materials`, `plan`, `register`, `test` and
`sync`. They were removed because connecting a cloud is a web-only step. Use
<https://app.ottto.net/apps> for any change to a cloud connector.
