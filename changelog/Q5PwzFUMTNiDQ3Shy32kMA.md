audience: worker-deployers
level: patch
---
D2G: limits concurrent `docker cp` artifact extractions to 10 to reduce RAM usage and avoid overwhelming the Docker daemon.
