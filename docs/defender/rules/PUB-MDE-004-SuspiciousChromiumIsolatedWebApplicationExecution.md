






**PUB-MDE-004**
# Suspicious Chromium Isolated Web Application Execution
<br>

## Use Case Documentation
### Description
Isolated Web Applications provide a Chromium environment with capabilities that can extend the functionality of a browser-based C2. An adversary can abuse an IWA alongside a browser extension to provide additional functionality, including network communication through Direct Sockets. This can provide capabilities that are not available to a browser extension alone, while allowing the C2 functionality to remain within the Chromium environment. A Native Messaging Host can provide access to the host operating system, while an IWA can provide complementary network functionality.

This use case detects Chromium process creation associated with Isolated Web Application usage by monitoring for the `--enable-isolated-web-apps-in-renderer` and `--enable-features=IsolatedWebApps`. These arguments can indicate that an IWA is being enabled or launched.

### Recommended Response Actions
- Verify whether the Isolated Web Application is authorized and expected in the environment.
- Identify the IWA, associated extension, and originating Chromium process.
- Inspect the IWA and extension files for their source, publisher, and digital signature where applicable.
- Review network connections originating from Chromium or related processes for unexpected destinations.
- Check for associated Native Messaging Hosts or unusual child processes.

### Logging and Query Blind Spots
- Obfuscation of the process command line.

### Possible False Positives
The false positive rate should be low, since the isolated web apps feature is not used very often.


### References
- https://specterops.io/blog/2026/08/13/chromium-extension-c2-persistence/#h-detecting-isolated-web-applications-usage
- https://www.nerium.nl/blogs/when-browsers-become-c2



### MITRE ATT&CK Mapping
| Technique ID | Name | Description | Associated Tactics |
| ------------ | ---- | ------------| ------------------ |
| [T1176](https://attack.mitre.org/versions/v18/techniques/T1176/) | Software Extensions | Adversaries may abuse software extensions to establish persistent access to victim systems. Software extensions are modular components that enhance or customize the functionality of software applications, including web browsers, Integrated Development Environments (IDEs), and other platforms. Extensions are typically installed via official marketplaces, app stores, or manually loaded by users, and they often inherit the permissions and access levels of the host application.  | TA0003 - Persistence  |
| [T1176.001](https://attack.mitre.org/versions/v18/techniques/T1176/001/) | Browser Extensions | Adversaries may abuse internet browser extensions to establish persistent access to victim systems. Browser extensions or plugins are small programs that can add functionality to and customize aspects of internet browsers. They can be installed directly via a local file or custom URL or through a browser's app store - an official online platform where users can browse, install, and manage extensions for a specific web browser. Extensions generally inherit the web browser's permissions previously granted.  | TA0003 - Persistence  |
| [T1559](https://attack.mitre.org/versions/v18/techniques/T1559/) | Inter-Process Communication | Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern.  | TA0002 - Execution  |


<br>

## Detection

### Defender Configuration
| Property                   | Value            |
| -------------------------- | ---------------- |
| Name                                          | PUB-MDE-004-Suspicious Chromium Isolated Web Application Execution |
| Alert Name                                    | PUB-MDE-004-Suspicious Chromium Isolated Web Application Execution |
| Platform                                      | Microsoft Defender for Endpoint \(MDE\) |
| Severity                                      | Medium |
| Impacted Assets \(`EntityType:Identifier`\)   | `Device:DeviceId`   |
| Automated Response Actions                    |  No automated response actions defined.  |
| Query Period                                  |  1H  |

### Detection Logic
```kusto
// Managed by Nerium Exine - Do Not Edit
// Rule file: /home/runner/work/detection-rules/detection-rules/main/rules/defender/PUB/PUB-MDE-004-Suspicious Chromium Isolated Web Application Execution.yaml
let _span = 48d;
DeviceProcessEvents
|     where ingestion_time() >= ago(_span)
|     where ProcessCommandLine has_any ("--enable-isolated-web-apps-in-renderer", "--enable-features=IsolatedWebApps")
```

---

## Version History

| Version | Date | Impact | Notes |
|---------|------|--------|-------|
| 1.0 | 2026-09-25 | Major | Initial version of the detection rule. |