audience: deployers
level: patch
---
The default `sendDeadline` for the pulse publisher has been raised from 12 seconds to 30 seconds. Under load, RabbitMQ blocking and client reconnects could consume most of the 12-second budget before a single publish-confirm round-trip completed, causing cascading `PulsePublisher.sendDeadline exceeded` errors. The new default gives more headroom while still remaining below typical HTTP proxy timeouts. Services can override this per-publisher via the `sendDeadline` option to `exchanges.publisher()`.
