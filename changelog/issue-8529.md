audience: users
level: patch
reference: issue 8529
---
Fix a bug in `queue.createTask` where idempotent retries could insert multiple
rows into the `queue_task_deadlines` table for a single task. Once those
duplicates became visible, several deadline-resolver instances could pick up
the same task concurrently, the first cancelled it, and the others crashed
because they assumed they were the only one working on the cancellation of said
task. A new unique constraint on `task_id` now prevents duplicate deadline
rows, and the migration deduplicates any existing stale rows.
