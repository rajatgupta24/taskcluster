audience: deployers
level: major
reference: issue 8243
---
**Action required when upgrading.** Gateway API resources (`Gateway`, `HTTPRoute`, `HealthCheckPolicy`) are now rendered by the Helm chart by default to enable side-by-side migration from Ingress. Before upgrading, either:
- install the Gateway API CRDs (`gateway.networking.k8s.io`) and, for GKE, the `HealthCheckPolicy` CRD (`networking.gke.io`); or
- opt out of rendering the new resources by adding `gateway`, `httproute`, and `healthcheckpolicy` to the `skipResourceTypes` list in your Helm values (the same list used today to skip other chart-managed resources such as `ingress` or `serviceaccount`). For example:
  ```yaml
  skipResourceTypes:
    - gateway
    - httproute
    - healthcheckpolicy
  ```
  This leaves your existing Ingress-based setup unchanged and lets you adopt Gateway API later.

Without one of the above, `helm upgrade` will fail with "no matches for kind" errors.

To adopt Gateway API for traffic routing, set `ingressType: gateway` along with `gatewayClassName`, `gatewayStaticIpName`, and `gcpManagedCertName`. Once the Gateway setup is validated, add `ingress` to `skipResourceTypes` to stop rendering the legacy Ingress resource.

See the [Gateway API section of the dev deployment docs](https://github.com/taskcluster/taskcluster/blob/main/dev-docs/dev-deployment.md#gateway-api) for setup instructions.
