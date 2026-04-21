audience: deployers
level: patch
reference: issue 8517
---
Fixed Azure provider workers getting stuck in `STOPPING` indefinitely when their backing Azure resources (VM, NIC, IP, disks, or ARM deployment) were deleted out-of-band (e.g. Spot preemption, ARM cascade delete). The `deprovisionResource` helper now treats a `404` from `beginDelete` the same way as a `404` from `get`: mark the resource as deleted and let the reap path continue.
