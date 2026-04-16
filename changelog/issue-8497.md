audience: deployers
level: minor
reference: issue 8497
---
The worker-manager Azure provider now captures ARM throttling signals for observability.
When Azure returns rate-limit headers (`x-ms-ratelimit-remaining-subscription-reads`, `-writes`, `-deletes`,
`x-ms-ratelimit-remaining-resource`, `Retry-After`), the provider records them as Prometheus metrics and,
on HTTP 429 responses, emits a structured `azureThrottled` warning log with the full header payload.

New Prometheus metrics:
- `worker_manager_azure_throttle_total` (counter) — incremented on every 429, labeled by `providerId` and `operationType`
- `worker_manager_azure_ratelimit_remaining` (gauge) — tracks the most recently observed remaining-quota value, labeled by `providerId` and `limitType`

The error handler in CloudAPI's `enqueue` path now respects `Retry-After` headers from Azure, using the server-specified delay (capped at 120 seconds) instead of the previous fixed backoff for 429 responses.

Rate-limit headers are observed on both Track 2 SDK calls (via a pipeline policy) and Track 1 REST polling calls (in `handleOperation`), covering all Azure API interactions made by the provider.
