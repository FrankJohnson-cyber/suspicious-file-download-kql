# Suspicious File Download Detection with KQL

This project uses KQL on SecurityEvent logs to detect rare executable downloads or executions from unusual parent processes, simulating malware delivery detection.


## Usage
Run in Azure Sentinel to identify rare .exe or .dll executions from non-standard parents (e.g., PowerShell, cmd.exe) over 7 days. Ideal for spotting malware post-phishing.

Built by Frank Johnson, CompTIA CSAP | CySA+ certified.
## Query
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where ProcessName endswith ".exe" or ProcessName endswith ".dll"
| summarize EventCount = count(), ParentProcesses = make_set(ParentProcessName), Computers = make_set(Computer) by ProcessName, CommandLine
| where EventCount < 5
| extend IsSuspiciousParent = iif(ParentProcesses !contains "explorer.exe" and ParentProcesses !contains "msedge.exe", "Yes", "No")
| where IsSuspiciousParent == "Yes"
| project ProcessName, CommandLine, EventCount, ParentProcesses, Computers, IsSuspiciousParent
| order by EventCount asc
