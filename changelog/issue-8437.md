audience: general
level: major
reference: issue 8437
---
Removed docker-worker from the monorepo. Docker-worker has been decommissioned across Taskcluster deployments and is no longer released. The d2g translation layer remains, so generic-worker continues to accept the legacy docker-worker payload format on Linux and the `docker-worker:*` scope namespace is unchanged. Existing tasks using the docker-worker payload format continue to run unchanged on generic-worker.

**Notes for deployers:**

- The `docker-worker` worker-runner implementation has been removed; deployments must run `generic-worker` (or a third-party worker that uses the Queue's worker protocol). worker-runner's `--help` no longer lists `docker-worker`.
- The `docker-worker` entry has been removed from the task-creator UI's `TASK_PAYLOAD_SCHEMAS` map. Deployments that set `SITE_SPECIFIC.tutorial_worker_schema` to `docker-worker` should change it to a generic-worker schema key (e.g. `generic-multi-posix` on Linux, `generic-multi-win` on Windows). Deployments that did not set this variable now default to `generic-multi-posix` instead of `docker-worker`.
- The `workers/docker-worker/` source tree is gone; deployments that built the docker-worker image themselves from this monorepo must source it from a docker-worker fork instead.
- The docker-worker payload schema has moved from `workers/docker-worker/schemas/v1/payload.yml` to `tools/d2g/schemas/docker-worker/v1/payload.yml`. The published service-schema URL (`schemas/docker-worker/v1/payload.json`) is unchanged, so consumers fetching the schema from a running deployment are unaffected.
