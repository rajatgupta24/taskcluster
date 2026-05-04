audience: developers
level: patch
---
Replaced locally-redefined Win32 constants in `workers/generic-worker` with their equivalents from `golang.org/x/sys/windows` and `syscall`. No behavior change.
