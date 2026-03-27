audience: deployers
level: patch
reference: issue 8388
---
The GitHub service now streams backing log artifacts instead of downloading them entirely into memory. Previously, tasks with very large logs (e.g. ~98MB) caused the status handler to crash with an out-of-memory error, leaving GitHub check runs stuck as `in_progress` indefinitely.
