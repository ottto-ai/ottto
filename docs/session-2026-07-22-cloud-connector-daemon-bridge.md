# Cloud connector daemon bridge

Added the public `ottto cloud` command family and matching local-control
protocol/daemon handlers. The bridge reuses the connected setup-run identity,
refreshes an expired setup-run token once, and calls the private backend's
local-client cloud endpoints.

Read commands (`materials`, `plan`, `status`, and connector `test`) do not save
configuration or start ingestion. `register` and `sync` require explicit
approval in both the CLI and daemon. Config files are parsed locally and both
layers reject reusable AWS credentials and legacy Google key fields. Plan
output reports field names rather than manifest values.

Vertex documentation uses Workload Identity Federation from Ottto's own AWS
production workload to a customer billing-reader service account. It does not
require a customer AWS connector.
