audience: worker-deployers
level: patch
reference: issue 8446
---
Worker Manager no longer removes Azure workers that are actively running tasks when an ARM deployment operation URL expires or the deployment shows a failed state. Previously, if Azure cleaned up a deployment record or the operation tracking URL expired before worker-manager marked provisioning as complete, the worker would be removed and any in-flight tasks resolved as `exception/worker-shutdown`, even though the worker was healthy.
