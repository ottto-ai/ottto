# Cloud Connectors

`ottto cloud` is the stable JSON bridge between an agent or operator and the
connected Ottto account. The local daemon owns the setup-run session and calls
the backend; manifests never contain reusable cloud-provider secrets.

## Safe sequence

1. Read provider setup commands:

   ```bash
   ottto cloud materials --source vertex --json
   ```

2. Create a local JSON manifest and inspect the plan:

   ```bash
   ottto cloud plan --source vertex --config-file connector.json --json
   ```

3. Test access. Only after a passing test, explicitly approve registration and
   the first sync:

   ```bash
   ottto cloud test --source vertex --config-file connector.json --json
   ottto cloud register --source vertex --config-file connector.json --approve --json
   ottto cloud sync --source vertex --days 30 --approve --json
   ```

Read status at any time with `ottto cloud status --json` or filter it with
`--source bedrock|vertex`.

## Vertex manifest

Vertex uses Google Workload Identity Federation. Ottto's own production AWS
backend exchanges its short-lived task-role identity for short-lived Google
credentials, then impersonates the customer's dedicated billing-reader service
account. The customer does not need an AWS connector.

```json
{
  "credentials": {
    "project_id": "example-project",
    "location": "US",
    "service_account_email": "ottto-billing-reader@example-project.iam.gserviceaccount.com",
    "workload_identity_provider": "projects/123456789012/locations/global/workloadIdentityPools/ottto-cloud/providers/ottto-production"
  },
  "config": {
    "billing_export_table": "example-project.billing.gcp_billing_export_v1_XXXXXX"
  }
}
```

The CLI rejects `private_key`, `client_email`, `access_key_id`,
`secret_access_key`, and `session_token` anywhere in a manifest. It also never
echoes manifest values in plan output.

## Bedrock manifest

Bedrock uses a customer-created cross-account read-only IAM role. Supply the
role ARN, external ID from `materials`, and region. Do not supply access keys.

```json
{
  "credentials": {
    "role_arn": "arn:aws:iam::123456789012:role/OtttoCostReadOnlyRole",
    "external_id": "ottto-example",
    "region": "us-east-1"
  },
  "config": {}
}
```
