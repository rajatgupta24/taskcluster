audience: deployers
level: patch
reference: issue 8569
---
Fix Azure worker registration in regions whose Azure IMDS attested-data leaf certificates have rotated to the new `Microsoft TLS RSA Root G2` hierarchy (uksouth as of 2026-04-29; other regions follow as their leaves renew). The G2 root is bundled in `worker-manager`'s azure CA store, so `addIntermediateCert` succeeds for the dynamically fetched `Microsoft TLS G2 RSA CA OCSP NN` intermediates and `registerWorker` returns 200 again.
