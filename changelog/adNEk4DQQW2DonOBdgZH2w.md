audience: developers
level: patch
---
Yarn will not execute the postinstall scripts from third-party packages when installing the project. This change helps to reduce supply-chain risks by preventing potentially malicious scripts from running automatically.

Note that you also have the ability to disable scripts on a per-package basis using `dependenciesMeta`, or to re-enable a specific script by combining `enableScripts` and `dependenciesMeta`.
