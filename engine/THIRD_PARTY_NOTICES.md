# Third-Party Notices

The Shadow Span AppSec engine invokes the following open-source scanner binaries
as external subprocesses. Their output is transformed into Shadow Span's own
finding format; their source is not embedded or modified. When these binaries are
distributed as part of a Shadow Span artifact (e.g. the bundled Docker image),
their licenses and copyright notices are reproduced below as required.

When a binary is already present on the host's PATH and was not distributed by
Shadow Span, no redistribution obligation applies.

---

## gitleaks — secret detection
- License: MIT
- Copyright © Zachary Rice and gitleaks contributors
- Project: https://github.com/gitleaks/gitleaks

## ast-grep — static analysis (SAST)
- License: MIT
- Copyright © Herrington Darkholme and ast-grep contributors
- Project: https://github.com/ast-grep/ast-grep

## Nuclei — dynamic scanning (DAST)
- License: MIT
- Copyright © ProjectDiscovery, Inc.
- Project: https://github.com/projectdiscovery/nuclei

## osv-scanner — software composition analysis (SCA)
- License: Apache License 2.0
- Copyright © Google LLC
- Project: https://github.com/google/osv-scanner

## Trivy — infrastructure-as-code & container scanning (IaC)
- License: Apache License 2.0
- Copyright © Aqua Security Software Ltd.
- Project: https://github.com/aquasecurity/trivy

---

## MIT License (gitleaks, ast-grep, Nuclei)

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Apache License 2.0 (osv-scanner, Trivy)

These components are licensed under the Apache License, Version 2.0. The full
license text is available at: https://www.apache.org/licenses/LICENSE-2.0

A copy of the NOTICE file from each project is retained alongside its binary in
any distributed artifact, per Section 4(d) of the license.
