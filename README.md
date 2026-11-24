# DMARC, SPF and DKIM Guardian

[![Technical Audit](https://img.shields.io/badge/TAVARDT-Email%20Security-5b3cf5.svg)](https://tools.tavardt.com/dmarc-checker/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

DNS email authentication auditor for eliminating domain spoofing, phishing, and enforcing CISA BOD 18-01 and NIST SP 800-177 standards.

Developed and maintained by the cybersecurity and infrastructure defense division of **TAVARDT United States**.

***

## Features and Verification Capabilities

* **DMARC Policy Enforcement**: In-depth inspection of enforcement directives (reject, quarantine, and none), subdomain policy (sp), and percentage enforcement rate (pct).
* **SPF Record Audit**: Validation of authorized sender mechanisms, DNS query lookup limits, and strict enforcement qualifiers (-all vs ~all).
* **DKIM Signature Verification**: Cryptographic public key verification across specified DNS selectors.
* **Forensic and Aggregate Reporting**: Verification of aggregate (rua) and forensic (ruf) feedback loops.
* **Regulatory and Standards Compliance**: Designed in alignment with CISA Binding Operational Directive 18-01 and NIST SP 800-177 Trustworthy Email.

***

## Installation and Quick Start

Requires Python 3.8 or higher. Built strictly using the Python standard library with zero external dependencies.

```bash
git clone https://github.com/TAVARDT-USA/dmarc-spf-guardian-usa.git
cd dmarc-spf-guardian-usa
python guardian.py enterprise.com
```

To test a specific DKIM selector or export results in structured JSON format:

```bash
python guardian.py enterprise.com -selector mail -json
```

***

## Online Web Diagnostics

For continuous perimeter monitoring and graphical reporting, access the official web diagnostic suite:

* **DMARC and Email Authentication Checker**
* **TAVARDT United States Corporate Portal**

***

## Enterprise Defense Consulting

For dedicated cybersecurity architecture, threat modeling, and incident readiness in United States, contact **TAVARDT United States**.

***

## Governance and Sovereignty

* **Sovereign Unit**: [TAVARDT United States](https://ag.tavardt.com/) (`TAVARDT-USA`)
* **Core Standards**: [00-core Governance](https://github.com/TAVARDT-USA/00-core)
* **Diagnostic Portal**: [TAVARDT US Diagnostic Suite](https://tools.tavardt.com/)
* **Enterprise Security**: [TAVARDT US Cybersecurity](https://ag.tavardt.com/cybersecurity/)

***

### License
Released under the MIT License. See [LICENSE](LICENSE) for full details.

***

© 2026 TAVARDT. All rights reserved.
