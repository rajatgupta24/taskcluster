level: patch
audience: developers
---
Fixed scope resolver performance tests that were silently not running due to an async
suite callback in mocha (which does not await suite callbacks). The tests using real-world
role and client fixture data are now registered and executed correctly. Also removed a stale
`docker_posix.json` entry from the unreferenced schemas list in `lib-references`.
