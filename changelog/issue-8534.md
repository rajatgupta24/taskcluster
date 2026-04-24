audience: users
level: patch
reference: issue 8534
---
Fix a 500 raised from hooks.triggerHook when a hook's task template evaluates
to nothing. The endpoint now correctly replies with an empty object in that
case.
