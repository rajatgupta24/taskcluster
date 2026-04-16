audience: deployers
level: minor
reference: issue 8502
---
A new Prometheus histogram metric `iterate_duration_seconds` is now emitted by
all background iteration loops (provisioner, worker-scanner, queue resolvers,
etc.) via `lib-iterate`.

The metric is registered as a global builtin, meaning it automatically
propagates to whichever Prometheus registry a process exposes — no per-service
configuration is required. It is a no-op in deployments without Prometheus
configured.
