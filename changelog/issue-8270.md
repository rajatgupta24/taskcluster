audience: deployers
level: patch
reference: issue 8270
---
Fixed a permission error on startup where nginx could not open its default error log
at `/var/lib/nginx/logs/error.log` when the container runs as a non-root user (UID 1000).
