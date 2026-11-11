# Security policy

CargoTrail handles process supervision, filesystem identity checks, configuration, and build evidence. Please do not post security-sensitive details in public issues.

To report a vulnerability, open the [**Security**](https://github.com/dvrdnz/CargoTrail/security) tab of this repository and choose [**Report a vulnerability**](https://github.com/dvrdnz/CargoTrail/security/advisories/new). This creates a private report that only you and the maintainers can see.

Please include the affected version, operating system, Python version, minimal reproduction, and expected versus observed behavior. Do not include secrets, private source code, or evidence archives from private projects in the report.

The agent is not a sandbox and must not be treated as an isolation boundary for untrusted build scripts.
