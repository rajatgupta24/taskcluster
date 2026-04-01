audience: deployers
level: patch
---
Web Server: OAuth2 token scopes are now intersected with the registered client's allowed scopes in addition to the user's scopes, preventing a tampered consent form submission from requesting scopes beyond what the client was registered for. A warning is logged when a scope mismatch is detected.
