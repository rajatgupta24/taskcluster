audience: users
level: major
---
The `taskcluster/websocktunnel` Docker image tags now include a `v` prefix (e.g., `v99.0.0` instead of `99.0.0`), matching the convention used by all other Taskcluster Docker images. A duplicate task definition in the release tooling was silently overriding the correct tag format since v36.0.0. If you reference websocktunnel images by tag, update your configurations to use the `v`-prefixed format.
