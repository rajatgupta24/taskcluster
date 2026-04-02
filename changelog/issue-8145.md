level: patch
audience: developers
---
Update `@sentry/node` from v6 to v10. Migrate Sentry SDK usage to v10 APIs: replace removed `configureScope()` with direct `setTag()` calls, update import style, and remove deprecated `autoSessionTracking` option.
