






**PUB-MDE-003**
# An Uncommon Chrome Native Messaging Host Was Observed
<br>

## Use Case Documentation
### Description
Chrome Native Messaging allows browser extensions to communicate with native applications installed on the host system. An adversary can abuse this mechanism to establish C2 communication through a browser extension and a Native Messaging Host, using the Native Messaging framework to communicate between the extension and the host system.

Compared with a traditional C2 implant, this approach can reduce reliance on a dedicated C2 process and may evade detections that focus on traditional C2 implants and their associated process or network characteristics.

This rule detects Chrome Native Messaging activity where the SHA-1 hash of the associated Native Messaging Host has low file prevalence. The prevalence of the Native Messaging Host is used as an indicator to identify uncommon hosts associated with this activity.

### Recommended Response Actions
- Verify whether the Native Messaging Host is associated with an approved application or browser extension.
- Check whether the SHA1 of the Native Nessaging Host is known and trusted within the environment.
- Review the Native Messaging Host file path, name, publisher, and digital signature.

### Logging and Query Blind Spots
- The use of a script instead of a Native Messaging Host executable won't be observed with this detection.

### Possible False Positives
The false positive rate should be low, as the use of Chrome Native Messaging is mostly used by high prevalence applications.


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
| Name                                          | PUB-MDE-003-An Uncommon Chrome Native Messaging Host Was Observed |
| Alert Name                                    | PUB-MDE-003-An Uncommon Chrome Native Messaging Host Was Observed |
| Platform                                      | Microsoft Defender for Endpoint \(MDE\) |
| Severity                                      | Medium |
| Impacted Assets \(`EntityType:Identifier`\)   | `Device:DeviceId`   |
| Automated Response Actions                    |  No automated response actions defined.  |
| Query Period                                  |  1H  |

### Detection Logic
```kusto
// Managed by Nerium Exine - Do Not Edit
// Rule file: /home/runner/work/detection-rules/detection-rules/main/rules/defender/PUB/PUB-MDE-003-An Uncommon Chrome Native Messaging Host Was Observed.yaml
let _span = 48h;
let _ChromeNativeMessagingNamedPipeEvents = () {
    DeviceEvents
    |     where ingestion_time() >= ago(_span)
    |     where ActionType == "NamedPipeEvent"
    |     where AdditionalFields contains @"chrome.nativeMessaging"
    |    extend NamedPipeEnd = extract_json("$.NamedPipeEnd",AdditionalFields, typeof(string))
    |     where NamedPipeEnd == "Client"
    |     where isnotempty(InitiatingProcessFileName)
    |    extend ParsedExtensionId = extract("chrome-extension://([a-p]{32})", 1, InitiatingProcessCommandLine, typeof(string))
              , ParsedMessagingHostFolderPath = tolower(replace_string(extract(```(?i)(?:"{0,2})((?:[A-Z]:[\\\/]|\\\\)[^"\r\n]+?)(?:"?\s+chrome-extension:\/\/)```, 1, InitiatingProcessCommandLine, typeof(string)), "/", @"\"))
};
let _ChromeNativeMessagingFolderPaths = () {
    _ChromeNativeMessagingNamedPipeEvents()
    |  distinct DeviceId
              , ParsedMessagingHostFolderPath
              , InitiatingProcessFileName
};
let _ChromeNativeMessagingSHA1s = () {
          union DeviceProcessEvents
              , DeviceImageLoadEvents
    |     where ingestion_time() >= ago(_span)
    |    extend FolderPath = tolower(FolderPath)
              , JoinProcessFileName = case ( ActionType == "ProcessCreated", InitiatingProcessFileName, ActionType == "ImageLoaded", InitiatingProcessParentFileName, "")
              , JoinProcessId = case ( ActionType == "ProcessCreated", InitiatingProcessId, ActionType == "ImageLoaded", InitiatingProcessParentId, 0)
    |     where FolderPath in~ ((_ChromeNativeMessagingFolderPaths() | project ParsedMessagingHostFolderPath))
    |      join kind=inner
                _ChromeNativeMessagingFolderPaths()
             on DeviceId
              , $left.FolderPath == $right.ParsedMessagingHostFolderPath
              , $left.JoinProcessFileName == $right.InitiatingProcessFileName
    |  distinct DeviceId
              , ParsedMessagingHostFolderPath
              , SHA1
              , InitiatingProcessFileName
};
let _EnrichedChromeNativeMessagingSHA1s = () {
    _ChromeNativeMessagingSHA1s()
    |  distinct SHA1
    |    invoke FileProfile(SHA1, 1000)
    |   project-away 
                SHA11
    |     where GlobalPrevalence < 50
    |   project SHA1
              , ChromeNativeMessagingFileProfile = pack_all()
};
let _NamedPipeInfo = () {
    _ChromeNativeMessagingNamedPipeEvents()
    |  distinct DeviceId
              , Timestamp
              , ReportId
              , ParsedMessagingHostFolderPath
              , InitiatingProcessFileName
              , InitiatingProcessId
              , ParsedExtensionId
              , NamedPipeInfo = AdditionalFields
};
      union DeviceProcessEvents
          , DeviceImageLoadEvents
|     where ingestion_time() >= ago(_span)
|     where SHA1 in ((_EnrichedChromeNativeMessagingSHA1s() | project SHA1))
|      join kind=inner
            _EnrichedChromeNativeMessagingSHA1s()
         on SHA1
|    extend FolderPath = tolower(FolderPath)
          , JoinProcessFileName = case ( ActionType == "ProcessCreated", InitiatingProcessFileName, ActionType == "ImageLoaded", InitiatingProcessParentFileName, "")
          , JoinProcessId = case ( ActionType == "ProcessCreated", InitiatingProcessId, ActionType == "ImageLoaded", InitiatingProcessParentId, 0)
|   project-rename
            ImageProcessTimestamp = Timestamp
          , ImageProcessReportId = ReportId
|      join kind=inner
            _NamedPipeInfo()
         on DeviceId
          , $left.JoinProcessFileName == $right.InitiatingProcessFileName
          , $left.JoinProcessId == $right.InitiatingProcessId
          , $left.FolderPath == $right.ParsedMessagingHostFolderPath
| summarize arg_min(Timestamp, *)
         by DeviceId
          , ParsedMessagingHostFolderPath
          , JoinProcessFileName
          , JoinProcessId
|   project-by-names
            column_names_of(DeviceProcessEvents)
          , column_names_of(_NamedPipeInfo)
          , column_names_of(_EnrichedChromeNativeMessagingSHA1s)
// Start of client-specific whitelisting block // 
//  End of client-specific whitelisting block  //
```

---

## Version History

| Version | Date | Impact | Notes |
|---------|------|--------|-------|
| 2.0 | 2026-10-27 | Major | Added redundant joining for DeviceImageLoadEvents, if there is no matching event in the DeviceProcessEvents. |
| 1.0 | 2026-09-25 | Major | Initial version of the detection rule. |