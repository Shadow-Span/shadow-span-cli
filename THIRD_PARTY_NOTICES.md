# Third-Party Notices — Shadow Span AppSec CLI

This CLI invokes the following open-source scanner binaries as external
subprocesses (they are not embedded or modified). Their output is transformed
into Shadow Span's own finding format.

| Tool | Purpose | License |
|------|---------|---------|
| gitleaks | secret detection | MIT |
| ast-grep | static analysis (SAST) | MIT |
| osv-scanner | dependency CVEs (SCA) | Apache-2.0 |
| Trivy | IaC misconfiguration | Apache-2.0 |

Full license + copyright text for each tool is reproduced in
`engine/THIRD_PARTY_NOTICES.md`, which ships in every distributed artifact (npm
package + Docker image) that bundles these binaries. When a binary is already
present on your PATH (not distributed by us), no redistribution obligation applies.
