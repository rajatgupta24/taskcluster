audience: deployers
level: minor
reference: issue 8243
---
Add optional [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) support (`Gateway`, `HTTPRoute`, `HealthCheckPolicy`) as an alternative to the existing `Ingress` resource. These new resources are only rendered when `ingressType: gateway` is set in Helm values, so existing Ingress-based deployments are unaffected and no new CRDs or `skipResourceTypes` entries are required.

To adopt Gateway API for traffic routing, set `ingressType: gateway` along with `gatewayClassName`, and for GKE regional external ALBs, `gatewayStaticIpName` and `gcpManagedCertName`. Both `Ingress` and Gateway API resources will be rendered side-by-side, letting you migrate at your own pace; add `ingress` to `skipResourceTypes` once the Gateway setup is validated to stop rendering the legacy Ingress.

See the [Gateway API section of the dev deployment docs](https://github.com/taskcluster/taskcluster/blob/main/dev-docs/dev-deployment.md#gateway-api) for setup instructions.
