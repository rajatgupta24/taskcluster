audience: worker-deployers
level: patch
reference: issue 8410
---
Generic Worker: Fix panic "close of closed channel" in `Command.Kill()` when multiple abort paths (e.g., reclaim failure and graceful termination) race to kill a task's processes.
