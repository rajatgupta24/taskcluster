audience: worker-deployers
level: patch
---
D2G: performance improvements to `docker run` for d2g tasks. Adds `--pull=never` to skip redundant registry checks (image is already loaded), `--log-driver=none` to eliminate duplicate log writes, and parallelizes artifact extraction from stopped containers.
