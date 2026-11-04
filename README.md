# Nerium Public KQL Detection Rules
This repository holds a collection of custom Kusto Query Language (KQL) detection rules designed to identify suspicious activity, security threats, and potentially malicious behavior across Microsoft security platforms. These detection rules are often based on current events or (public) research.

The rules are stored in the `/docs/defender/rules/` folder of this repository.

The following detection rules are currently available:
* [PUB-MDE-001-Possible Exploitation of RCE Vulnerability in React Server Components](rules/PUB-MDE-001-PossibleExploitationofRCEVulnerabilityinReactServerComponents.md)
* [PUB-MDE-002-A Cloud-Backed File Was Potentially Remediated to a Privileged Directory](rules/PUB-MDE-002-ACloud-BackedFileWasPotentiallyRemediatedtoaPrivilegedDirectory.md)
* [PUB-MDE-003-An Uncommon Chrome Native Messaging Host Was Observed](rules/PUB-MDE-003-AnUncommonChromeNativeMessagingHostWasObserved.md)
* [PUB-MDE-004-Suspicious Chromium Isolated Web Application Execution](rules/PUB-MDE-004-SuspiciousChromiumIsolatedWebApplicationExecution.md)

### Disclaimer
Queries are provided as-is, without guarantees of accuracy, completeness, or effectiveness. Detection results depend on available telemetry, data quality, configuration, and environment-specific factors. Some detections may require tuning to reduce false positives. No detection should be considered a guarantee that a particular threat or technique will be identified. Always validate and test detection logic in a controlled environment before enabling production alerting.
