audience: deployers
level: patch
reference: issue 8526
---
Fixed the Azure provider's `deprovisionResource` wasting a worker-scanner cycle per resource when the backing VM/NIC/IP/disk had already been removed out-of-band (e.g. ARM cascade-delete via `deleteOption: 'Delete'`, Spot preemption). Previously the pre-flight `GET` was skipped whenever the worker still had a stored `id`, so the scanner fired a no-op `beginDelete` first and only discovered the resource was gone on the following cycle. The helper now always performs the pre-flight `GET`, so a missing resource is marked deleted immediately and the reap chain continues in a single cycle, shortening the `STOPPING` tail for affected Azure pools.
