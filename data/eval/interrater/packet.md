# Inter-rater review packet

20 agent runs from the dev split that nobody has reviewed. Rate each one on your own, without discussing, in your ratings file (A = approve, R = reject, then a short reason).

Rubric (the same one used for the test-split review):
- Hardened rule: approve if it passed the quality checks and adds no false alarm.
- Written rule: approve if it passed the quality checks, raises no false alarm on unseen legitimate
  commands, and catches at least 80% of unseen variations; or, with no unseen variations to measure,
  if its logic is tightly scoped on reading.
- Any rule: reject if it would fire on everyday legitimate commands you can think of, even when they
  are not in the test data.
- A rule that did not pass the quality checks can still be approved if you judge the failing check
  wrong for this rule; say why.

Unseen variations and legitimate commands are held out from the agent; you see them, it never did.

## 1. `c932ded3` · T1543.003 · written, zero-shot (no tuning variations)

- Model-call budget: 25; calls used: 8
- Quality checks: **passed**
- Tuning variations caught: n/a → n/a; tuning false alarms: 0
- **Unseen variations caught: 0% → 100%** (insertion 1/1, omission 3/3)
- **New false alarms on unseen legitimate commands: 0**

```yaml
title: Windows Service Creation via sc.exe
id: 5948358f-e624-59bf-812e-a717998eab73
status: experimental
description: Detects creation of Windows services using sc.exe, which is commonly used by attackers to establish persistence via T1543.003.
references:
  - https://attack.mitre.org/techniques/T1543/003/
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: \sc.exe
    - OriginalFileName: sc.exe
  selection_cli:
    CommandLine|contains|all:
      - ' create '
      - 'binPath'
      - 'start=auto'
  condition: all of selection_*
falsepositives:
  - Legitimate service installation by administrators or software installers creating auto-start services
level: medium
```

## 2. `40952cb8` · T1555.003 · written, zero-shot (no tuning variations)

- Model-call budget: 25; calls used: 10
- Quality checks: **passed**
  - no_copied_test_strings: warning, check these are general and not test-specific: \AppData\Local\Temp
- Tuning variations caught: n/a → n/a; tuning false alarms: 0
- **Unseen variations caught: 0% → 100%** (omission 1/1)
- **New false alarms on unseen legitimate commands: 0**

```yaml
title: Esentutl Copying Browser Credential Databases
id: 78abbf87-3afa-5955-b4c8-1819576e8abc
status: experimental
description: Detects esentutl.exe being used to copy browser credential databases (e.g., Chrome Login Data, Web Data, Cookies) which is indicative of credential theft from web browsers (T1555.003).
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: \esentutl.exe
    - OriginalFileName: esentutl.exe
  selection_y_flag:
    CommandLine|contains|windash: ' /y '
  selection_browser_db:
    CommandLine|contains:
      - \Login Data
      - \Web Data
      - \Cookies
      - \History
      - \Favicons
      - \Shortcuts
      - \Top Sites
  selection_suspicious_dest:
    CommandLine|contains:
      - \Temp\
      - \temp\
      - \Tmp\
      - \tmp\
      - \AppData\Local\Temp
  condition: all of selection_img and selection_y_flag and selection_browser_db and selection_suspicious_dest
falsepositives:
  - Legitimate database maintenance or backup operations by administrators
  - Forensic analysis activity
level: high
tags:
  - attack.credential_access
  - attack.t1555.003
```

## 3. `adb6111f` · T1053.005 · written from tuning variations

- Model-call budget: 15; calls used: 15
- Quality checks: **not passed**
  - model call budget exhausted (15 calls)
- Tuning variations caught: 0% → 100%; tuning false alarms: 0
- **Unseen variations caught: 0% → 33%** (insertion 3/6, omission 0/3)
- **New false alarms on unseen legitimate commands: 0**
- Unseen attack variations it misses (9, up to 4 shown):
  - insertion: `schtasks /"create" /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"`
  - omission: `schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd /c calc.exe"`
  - insertion: `SCHTASKS /"Create" /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`
  - omission: `SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd /ST 20:10`

```yaml
title: Suspicious Scheduled Task Creation via schtasks.exe
id: 318c3aa5-6f73-5ac4-9f6a-be78be7ac9b5
status: experimental
description: Detects creation of scheduled tasks using schtasks.exe with /create argument that execute suspicious commands (shells, scripting engines), indicating persistence (ATT&CK T1053.005).
references:
  - https://attack.mitre.org/techniques/T1053/005/
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    - Image|endswith: '\schtasks.exe'
    - OriginalFileName: 'schtasks.exe'
  selection_create:
    CommandLine|re: '(?i)(\s|^)[/-]create\b'
  selection_suspicious_tr:
    CommandLine|re: '(?i)(\s|^)[/-]tr\s+["'']?\s*([a-z]:[\\/][^\s"'']*[\\/])?(cmd\.exe|powershell\.exe|pwsh\.exe|wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe|bash\.exe|sh\.exe)(\s|$)'
  condition: selection_image and selection_create and selection_suspicious_tr
falsepositives:
  - Legitimate scheduled task creation running scripting engines (rare)
level: medium
```

## 4. `b155d0e0` · T1547.001 · written from tuning variations

- Model-call budget: 15; calls used: 15
- Quality checks: **not passed**
  - model call budget exhausted (15 calls)
  - no_unusual_characters: added characters real rules don't need (copied from the test attacks?): U+FE63 SMALL HYPHEN-MINUS
  - no_copied_test_strings: warning, check these are general and not test-specific: \CurrentVersion\Run
  - case_insensitive_regexes: case-sensitive regex on case-insensitive Windows fields (misses e.g. /TN for /tn); start it with (?i): '[\\s/﹣-][vVdD]\\s'
  - false_alarms: 1 (maximum 0)
- Tuning variations caught: 0% → 100%; tuning false alarms: 1
- **Unseen variations caught: 0% → 100%** (insertion 6/6, omission 1/1)
- **New false alarms on unseen legitimate commands: 1**
  - `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDrive`

```yaml
title: Registry Run Key Modification via reg.exe
id: cbea5907-2ffa-5111-82ac-18d0c3b149f9
status: experimental
description: Detects modification of Windows registry run keys (Run, RunOnce) via reg.exe to achieve persistence.
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    - Image|endswith: \reg.exe
    - OriginalFileName: reg.exe
  selection_run_key:
    CommandLine|contains: \CurrentVersion\Run
  selection_add_params:
    CommandLine|re: '[\s/﹣-][vVdD]\s'
  condition: all of selection_*
falsepositives:
  - Legitimate software installation or configuration that modifies startup programs
  - System administrator activity
level: medium
tags:
  - attack.persistence
  - attack.t1547.001
```

## 5. `69ea69a4` · T1543.003 · written, zero-shot (no tuning variations)

- Model-call budget: 15; calls used: 11
- Quality checks: **passed**
- Tuning variations caught: n/a → n/a; tuning false alarms: 0
- **Unseen variations caught: 0% → 100%** (insertion 1/1, omission 3/3)
- **New false alarms on unseen legitimate commands: 1**
  - `sc create "CompanyAgent" binPath= "C:\Program Files\Company\agent.exe" start= auto`

```yaml
title: Windows Service Creation via sc.exe
id: 71974f2e-3f09-521a-a893-8be4432f9e95
status: experimental
description: Detects creation of a new Windows service via sc.exe, which is commonly used by attackers to establish persistence (ATT&CK T1543.003).
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: \sc.exe
    - OriginalFileName: sc.exe
  selection_cli_create:
    CommandLine|re: '(?i)(^|\s)[/-]?create(\s|$)'
  selection_cli_binpath:
    CommandLine|re: '(?i)binpath\s*=' 
  selection_cli_autostart:
    CommandLine|re: '(?i)(^|\s)[/-]?start\s*=\s*auto(\s|$)'
  condition: all of selection_*
falsepositives:
  - Legitimate service installation by administrators or software installers that configure auto-start
level: medium
tags:
  - attack.persistence
  - attack.t1543.003
```

## 6. `dc9b3a31` · T1547.001 · written from tuning variations

- Model-call budget: 15; calls used: 15
- Quality checks: **not passed**
  - model call budget exhausted (15 calls)
  - no_copied_test_strings: warning, check these are general and not test-specific: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  - evasion_resistance: 67% (minimum 80%)
  - false_alarms: 1 (maximum 0)
- Tuning variations caught: 0% → 67%; tuning false alarms: 1
- **Unseen variations caught: 0% → 100%** (insertion 6/6, omission 1/1)
- **New false alarms on unseen legitimate commands: 1**
  - `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDrive`

```yaml
title: Registry Run Key Persistence via reg.exe
id: 7d180142-74d4-547e-91ba-ebb1bb03eec8
status: experimental
description: Detects creation of registry run keys for persistence via reg.exe ADD command targeting Run/RunOnce keys
references:
  - https://attack.mitre.org/techniques/T1547/001/
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: \reg.exe
    - OriginalFileName: reg.exe
  selection_runkey:
    CommandLine|contains: 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
  selection_value:
    CommandLine|re: '(?i)[/-][vd][\s"\'']'
  condition: all of selection_*
falsepositives:
  - Legitimate software installation or configuration
  - System administrator activity
level: medium
tags:
  - attack.persistence
  - attack.t1547.001
```

## 7. `78c04080` · T1490 · written from tuning variations

- Model-call budget: 25; calls used: 16
- Quality checks: **passed**
  - no_copied_test_strings: warning, check these are general and not test-specific:  shadowstorage 
- Tuning variations caught: 0% → 100%; tuning false alarms: 0
- **Unseen variations caught: 0% → 100%** (omission 2/2)
- **New false alarms on unseen legitimate commands: 0**
- Unseen attack variations it misses (4, up to 4 shown):
  - insertion: `bcdedit.exe /"set" {default} bootstatuspolicy ignoreallfailures`
  - omission: `bcdedit /set {default} bootstatuspolicy ignoreallfailures`
  - insertion: `bcdedit.exe /"set" {default} recoveryenabled no`
  - omission: `bcdedit /set {default} recoveryenabled no`

```yaml
title: Inhibit System Recovery - Shadow Copy and Backup Deletion
id: 35a8ba20-1034-5ecd-a872-152620876a1b
status: experimental
description: Detects deletion of shadow copies (VSS), WMI shadow copies, or Windows Backup catalogs using built-in Windows utilities. This is a common technique used by ransomware and destructive malware to prevent system recovery.
references:
  - https://attack.mitre.org/techniques/T1490/
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_vssadmin_delete_img:
    - Image|endswith: '\\vssadmin.exe'
    - OriginalFileName: 'vssadmin.exe'
  selection_vssadmin_delete_cli:
    CommandLine|contains|all:
      - ' delete '
      - ' shadows '
      - ' /all '
  selection_vssadmin_resize_img:
    - Image|endswith: '\\vssadmin.exe'
    - OriginalFileName: 'vssadmin.exe'
  selection_vssadmin_resize_cli:
    CommandLine|contains|all:
      - ' resize '
      - ' shadowstorage '
      - 'MaxSize'
  selection_wmic_img:
    - Image|endswith: '\\wmic.exe'
    - OriginalFileName: 'wmic.exe'
  selection_wmic_cli:
    CommandLine|contains: ' delete'
  selection_wbadmin_img:
    - Image|endswith: '\\wbadmin.exe'
    - OriginalFileName: 'wbadmin.exe'
  selection_wbadmin_cli:
    CommandLine|contains|all:
      - ' delete '
      - ' catalog '
  condition: (selection_vssadmin_delete_img and selection_vssadmin_delete_cli) or (selection_vssadmin_resize_img and selection_vssadmin_resize_cli) or (selection_wmic_img and selection_wmic_cli) or (selection_wbadmin_img and selection_wbadmin_cli)
falsepositives:
  - Legitimate administrative activity removing old backups
  - Backup software maintenance scripts
  - Storage management operations
  - Administrative use of WMIC to delete objects
level: high
tags:
  - attack.impact
  - attack.t1490
```

## 8. `ea913440` · T1543.003 · written, zero-shot (no tuning variations)

- Model-call budget: 15; calls used: 9
- Quality checks: **passed**
- Tuning variations caught: n/a → n/a; tuning false alarms: 0
- **Unseen variations caught: 0% → 100%** (insertion 1/1, omission 3/3)
- **New false alarms on unseen legitimate commands: 0**

```yaml
title: Windows Service Creation via sc.exe
id: 44da4803-958e-5948-bd14-c8e9d2bea997
status: experimental
description: Detects creation of Windows services using sc.exe with the create subcommand, which is commonly used by attackers to establish persistence via T1543.003.
references:
  - https://attack.mitre.org/techniques/T1543/003/
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: \sc.exe
    - OriginalFileName: sc.exe
  selection_cli:
    CommandLine|contains|all:
      - ' create '
      - 'binpath='
      - 'type='
  condition: all of selection_*
falsepositives:
  - Legitimate service installation by administrators or software installers that explicitly specify service type
level: medium
tags:
  - attack.persistence
  - attack.t1543.003
```

## 9. `a1284df7` · T1053.005 · written from tuning variations

- Model-call budget: 25; calls used: 15
- Quality checks: **passed**
- Tuning variations caught: 0% → 100%; tuning false alarms: 0
- **Unseen variations caught: 0% → 11%** (insertion 1/6, omission 0/3)
- **New false alarms on unseen legitimate commands: 0**
- Unseen attack variations it misses (11, up to 4 shown):
  - insertion: `schtasks /"create" /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"`
  - insertion: `schtasks /create /"tn" "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"`
  - omission: `schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd /c calc.exe"`
  - insertion: `SCHTASKS /"Create" /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`

```yaml
title: Scheduled Task Creation via schtasks.exe
id: 684448ae-4797-5aeb-a99a-80690c3943d3
status: experimental
description: Detects creation of scheduled tasks using schtasks.exe with the /create action. This technique is used for persistence (T1053.005) by creating tasks that execute on logon, at specific times, or on other triggers.
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith: \schtasks.exe
  selection_original:
    OriginalFileName: schtasks.exe
  selection_create:
    CommandLine|re: '(?i)[\s/\\-]create[\s"]'
  selection_tn:
    CommandLine|re: '(?i)[\s/\\-]tn[\s"]'
  selection_tr:
    CommandLine|re: '(?i)[\s/\\-]tr[\s"]'
  selection_suspicious_tr:
    CommandLine|re: '(?i)[\s/\\-]tr[\s"]\s*"?\s*(?:[a-z]:\\.*\\)?(cmd\.exe|powershell\.exe|pwsh\.exe|wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe|certutil\.exe|bitsadmin\.exe|bash\.exe|sh\.exe)'
  condition: (selection_image or selection_original) and selection_create and selection_tn and selection_tr and selection_suspicious_tr
falsepositives:
  - Legitimate scheduled task creation by administrators or software installers that invoke scripting engines
  - System management scripts that create scheduled tasks running command shells
level: medium
tags:
  - attack.persistence
  - attack.t1053.005
```

## 10. `c8983d3b` · T1053.005 · written from tuning variations

- Model-call budget: 25; calls used: 10
- Quality checks: **passed**
- Tuning variations caught: 0% → 100%; tuning false alarms: 0
- **Unseen variations caught: 0% → 33%** (insertion 1/2, omission 0/1)
- **New false alarms on unseen legitimate commands: 0**
- Unseen attack variations it misses (11, up to 4 shown):
  - insertion: `schtasks /"create" /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"`
  - insertion: `schtasks /create /"tn" "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"`
  - omission: `schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd /c calc.exe"`
  - insertion: `SCHTASKS /"Create" /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`

```yaml
title: Scheduled Task Creation via schtasks.exe for Persistence
id: 0bac102d-7485-5d7a-ab28-594928404edc
status: experimental
description: Detects creation of scheduled tasks via schtasks.exe with onstart trigger and SYSTEM account, commonly used for persistence.
references:
  - https://attack.mitre.org/techniques/T1053/005/
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith: \schtasks.exe
  selection_original:
    OriginalFileName: schtasks.exe
  selection_create:
    CommandLine|re: '(?i)[/\\-]create\b'
  selection_onstart:
    CommandLine|re: '(?i)[/\\-]sc\s+onstart\b'
  selection_ru_system:
    CommandLine|re: '(?i)[/\\-]ru\s+system\b'
  selection_tr_cmd:
    CommandLine|re: '(?i)[/\\-]tr\s+["'']?cmd\.exe'
  condition: (selection_image or selection_original) and selection_create and selection_onstart and selection_ru_system and selection_tr_cmd
falsepositives:
  - Legitimate administrative task creation with SYSTEM account on startup
level: high
tags:
  - attack.persistence
  - attack.t1053.005
```

## 11. `44f9235d` · T1555.003 · written, zero-shot (no tuning variations)

- Model-call budget: 15; calls used: 6
- Quality checks: **passed**
- Tuning variations caught: n/a → n/a; tuning false alarms: 0
- **Unseen variations caught: 0% → 100%** (omission 1/1)
- **New false alarms on unseen legitimate commands: 0**

```yaml
title: Esentutl Extracts Browser Credential Database
description: Detects use of esentutl.exe with /y and /d flags to copy browser credential databases (Login Data, Web Data, Cookies, etc.) to a staging location, indicative of credential theft from web browsers (T1555.003).
id: 2dbb05a5-883e-53cf-be37-824013ca77d6
status: experimental
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    - Image|endswith: \esentutl.exe
    - OriginalFileName: esentutl.exe
  selection_flags:
    CommandLine|contains|windash:
      - ' /y '
      - ' /d '
  selection_browser_db:
    CommandLine|contains:
      - 'Login Data'
      - 'Web Data'
      - 'Cookies'
      - 'History'
      - 'Shortcuts'
      - 'Favicons'
      - 'Top Sites'
  condition: all of selection_*
level: high
falsepositives:
  - Legitimate database repair or backup operations on browser profiles
  - Forensic investigation activity
tags:
  - attack.credential_access
  - attack.t1555.003
```

## 12. `06d6aadc` · T1490 · written from tuning variations

- Model-call budget: 25; calls used: 13
- Quality checks: **passed**
  - no_copied_test_strings: warning, check these are general and not test-specific: bootstatuspolicy ignoreallfailures; recoveryenabled no
- Tuning variations caught: 0% → 100%; tuning false alarms: 0
- **Unseen variations caught: 0% → 50%** (insertion 0/2, omission 2/2)
- **New false alarms on unseen legitimate commands: 0**
- Unseen attack variations it misses (4, up to 4 shown):
  - insertion: `bcdedit.exe /"set" {default} bootstatuspolicy ignoreallfailures`
  - insertion: `bcdedit.exe /"set" {default} recoveryenabled no`
  - omission: `vssadmin delete shadows /all /quiet`
  - omission: `wmic shadowcopy delete`

```yaml
title: Inhibit System Recovery via Bcdedit
id: 78fc30d3-662c-5546-979a-a8654cab550e
status: experimental
description: Detects use of bcdedit.exe to disable Windows recovery features by setting bootstatuspolicy to ignoreallfailures or recoveryenabled to no
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\bcdedit.exe'
    - OriginalFileName: 'bcdedit.exe'
  selection_set:
    CommandLine|re: '(?i)[-/]set\s'
  selection_bootstatus:
    CommandLine|contains: 'bootstatuspolicy ignoreallfailures'
  selection_recovery:
    CommandLine|contains: 'recoveryenabled no'
  condition: selection_img and selection_set and (selection_bootstatus or selection_recovery)
falsepositives:
  - Legitimate administration of boot configuration (rare)
level: high
tags:
  - attack.t1490
  - attack.impact
```

## 13. `c60d61e2` · T1053.005 · written from tuning variations

- Model-call budget: 15; calls used: 15
- Quality checks: **not passed**
  - model call budget exhausted (15 calls)
  - case_insensitive_regexes: case-sensitive regex on case-insensitive Windows fields (misses e.g. /TN for /tn); start it with (?i): '(^|\\s)[/-]create(\\s|$)'
  - detects_unmutated_attacks: 2/3 unmutated attacks detected
  - evasion_resistance: 40% (minimum 80%)
  - false_alarms: 1 (maximum 0)
- Tuning variations caught: 0% → 40%; tuning false alarms: 1
- **Unseen variations caught: 0% → 22%** (insertion 0/6, omission 2/3)
- **New false alarms on unseen legitimate commands: 1**
  - `schtasks /create /tn "CompanyUpdate" /tr "C:\Program Files\Company\update.exe" /sc daily /st 03:00`
- Unseen attack variations it misses (10, up to 4 shown):
  - insertion: `schtasks /"create" /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"`
  - insertion: `schtasks /create /"tn" "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"`
  - insertion: `SCHTASKS /"Create" /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`
  - insertion: `SCHTASKS /Create /"SC" ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`

```yaml
title: Scheduled Task Creation via schtasks.exe
id: 90538761-ecef-52d8-9239-5f25099ba476
status: experimental
description: Detects creation of scheduled tasks using schtasks.exe, which can be used for persistence (T1053.005)
references:
  - https://attack.mitre.org/techniques/T1053/005/
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    - Image|endswith: '\schtasks.exe'
    - OriginalFileName: 'schtasks.exe'
  selection_create:
    CommandLine|re: '(^|\s)[/-]create(\s|$)'
  selection_args:
    CommandLine|contains|all:
      - ' /tn '
      - ' /tr '
      - ' /sc '
  condition: all of selection_image and selection_create and selection_args
falsepositives:
  - Legitimate administrative task creation
  - Software installers creating scheduled tasks
level: medium
```

## 14. `90763e55` · T1547.001 · written from tuning variations

- Model-call budget: 25; calls used: 18
- Quality checks: **passed**
  - no_copied_test_strings: warning, check these are general and not test-specific: CurrentVersion\Run
- Tuning variations caught: 0% → 100%; tuning false alarms: 0
- **Unseen variations caught: 0% → 57%** (insertion 3/6, omission 1/1)
- **New false alarms on unseen legitimate commands: 0**
- Unseen attack variations it misses (3, up to 4 shown):
  - insertion: `REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /"V" "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"`
  - insertion: `REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /"v" 1 /d "C:\Path\AtomicRedTeam.dll"`
  - insertion: `REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /"d" "C:\Path\AtomicRedTeam.dll"`

```yaml
title: Registry Run Keys Modification via Reg.exe
id: 99a3bf56-713a-52aa-ab35-9f35f3dca581
status: experimental
description: Detects modification of Windows Run/RunOnce registry keys via reg.exe for persistence (ATT&CK T1547.001)
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    - Image|endswith: \reg.exe
    - OriginalFileName: reg.exe
  selection_run_path:
    CommandLine|contains: 'CurrentVersion\Run'
  selection_value_flag:
    CommandLine|re: '(?i)\s\Wv\s'
  selection_data_flag:
    CommandLine|re: '(?i)\s\Wd\s'
  condition: all of selection_*
falsepositives:
  - Legitimate software installation or configuration that adds Run keys
  - Administrative scripts managing startup programs
level: medium
tags:
  - attack.persistence
  - attack.t1547.001
```

## 15. `2b87ed68` · T1547.001 · written from tuning variations

- Model-call budget: 15; calls used: 13
- Quality checks: **passed**
  - no_copied_test_strings: warning, check these are general and not test-specific: \SOFTWARE\Microsoft\Windows\CurrentVersion\Run; \SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce; \SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
- Tuning variations caught: 0% → 100%; tuning false alarms: 0
- **Unseen variations caught: 0% → 100%** (insertion 6/6, omission 1/1)
- **New false alarms on unseen legitimate commands: 0**

```yaml
title: Persistence via Registry Run Keys (T1547.001)
id: f52952d1-e29d-5089-94d3-fd6d44cde378
status: experimental
description: Detects creation of persistence via registry Run/RunOnce/RunOnceEx keys using reg.exe.
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: \reg.exe
    - OriginalFileName: reg.exe
  selection_run_key:
    CommandLine|contains:
      - \SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      - \SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
      - \SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
  filter_query:
    CommandLine|re: '(?i)^reg\s+query\s'
  condition: all of selection_* and not filter_query
falsepositives:
  - Legitimate software installation or administration that adds Run keys
level: medium
tags:
  - attack.persistence
  - attack.t1547.001
```

## 16. `603d10de` · T1053.005 · written from tuning variations

- Model-call budget: 25; calls used: 16
- Quality checks: **passed**
- Tuning variations caught: 0% → 100%; tuning false alarms: 0
- **Unseen variations caught: 0% → 44%** (insertion 1/6, omission 3/3)
- **New false alarms on unseen legitimate commands: 1**
  - `schtasks /create /tn "CompanyUpdate" /tr "C:\Program Files\Company\update.exe" /sc daily /st 03:00`
- Unseen attack variations it misses (8, up to 4 shown):
  - insertion: `schtasks /"create" /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"`
  - insertion: `schtasks /create /"tn" "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"`
  - insertion: `SCHTASKS /"Create" /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`
  - insertion: `schtasks /"create" /TN "ProactiveScan" /TR "wscript.exe \"C:\Users\analyst\AppData\Roaming\Microsoft\Chkdsk.js\" -scan Kdw6gG7cpOSZsBeH" /SC ONLOGON /F`

```yaml
title: Scheduled Task Creation via schtasks.exe
id: c2b4a24d-3e00-53de-9490-781ed99cb705
status: experimental
description: Detects creation of scheduled tasks using schtasks.exe with the /create action, which is commonly used for persistence (T1053.005).
references:
  - https://attack.mitre.org/techniques/T1053/005/
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith: '\schtasks.exe'
  selection_original:
    OriginalFileName: 'schtasks.exe'
  selection_create:
    CommandLine|re: '(?i)[/\\-]create\b'
  selection_tn:
    CommandLine|re: '(?i)[/\\-]tn\b'
  selection_tr:
    CommandLine|re: '(?i)[/\\-]tr\b'
  selection_benign_diskcleanup:
    CommandLine|contains|all:
      - 'DiskCleanup'
      - 'cleanmgr.exe'
      - 'sagerun'
  condition: (selection_image or selection_original) and selection_create and selection_tn and selection_tr and not selection_benign_diskcleanup
falsepositives:
  - Legitimate administrative task creation
  - Software installation that creates scheduled tasks
level: medium
tags:
  - attack.persistence
  - attack.t1053.005
```

## 17. `f3244942` · T1490 · written from tuning variations

- Model-call budget: 25; calls used: 13
- Quality checks: **passed**
  - no_copied_test_strings: warning, check these are general and not test-specific:  shadowstorage 
- Tuning variations caught: 0% → 100%; tuning false alarms: 0
- **Unseen variations caught: 0% → 100%** (omission 2/2)
- **New false alarms on unseen legitimate commands: 0**
- Unseen attack variations it misses (4, up to 4 shown):
  - insertion: `bcdedit.exe /"set" {default} bootstatuspolicy ignoreallfailures`
  - omission: `bcdedit /set {default} bootstatuspolicy ignoreallfailures`
  - insertion: `bcdedit.exe /"set" {default} recoveryenabled no`
  - omission: `bcdedit /set {default} recoveryenabled no`

```yaml
title: Inhibit System Recovery via Volume Shadow Copy and Backup Deletion
id: ef0a90f3-0053-5acd-b257-d63a0898c35f
status: experimental
description: Detects deletion of volume shadow copies and backup catalogs using vssadmin, wmic, or wbadmin - techniques used to inhibit system recovery (ATT&CK T1490).
references:
  - https://attack.mitre.org/techniques/T1490/
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_vssadmin_img:
    - Image|endswith: \vssadmin.exe
    - OriginalFileName: vssadmin.exe
  selection_vssadmin_delete:
    CommandLine|contains|all:
      - ' delete '
      - ' shadows '
  selection_vssadmin_resize:
    CommandLine|contains|all:
      - ' resize '
      - ' shadowstorage '
      - 'MaxSize'
  selection_wmic_img:
    - Image|endswith: \wmic.exe
    - OriginalFileName: wmic.exe
  selection_wmic_cli:
    CommandLine|contains: ' delete'
  selection_wbadmin_img:
    - Image|endswith: \wbadmin.exe
    - OriginalFileName: wbadmin.exe
  selection_wbadmin_cli:
    CommandLine|contains|all:
      - ' delete '
      - ' catalog '
    CommandLine|contains|windash:
      - /quiet
      - -quiet
  condition: (selection_vssadmin_img and selection_vssadmin_delete) or (selection_vssadmin_img and selection_vssadmin_resize) or (selection_wmic_img and selection_wmic_cli) or (selection_wbadmin_img and selection_wbadmin_cli)
falsepositives:
  - Legitimate administrative backup management
  - Authorized system maintenance scripts
level: high
tags:
  - attack.t1490
  - attack.impact
```

## 18. `5b09be0b` · T1053.005 · written from tuning variations

- Model-call budget: 15; calls used: 13
- Quality checks: **passed**
- Tuning variations caught: 0% → 100%; tuning false alarms: 0
- **Unseen variations caught: 0% → 67%** (insertion 1/2, omission 1/1)
- **New false alarms on unseen legitimate commands: 0**
- Unseen attack variations it misses (10, up to 4 shown):
  - insertion: `schtasks /"create" /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"`
  - insertion: `schtasks /create /"tn" "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"`
  - omission: `schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd /c calc.exe"`
  - insertion: `SCHTASKS /"Create" /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`

```yaml
title: Scheduled Task Creation via schtasks.exe
id: cdeb49e5-d478-5751-ad86-a7d1c75364c0
status: experimental
description: Detects creation of scheduled tasks using schtasks.exe with essential parameters (create, task name, schedule, run as user, task to run), focusing on privilege escalation via SYSTEM and onstart triggers
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_schtasks:
    Image|endswith: '\schtasks.exe'
    OriginalFileName: 'schtasks.exe'
  selection_create:
    CommandLine|contains|windash: 'create'
  selection_tn:
    CommandLine|contains|windash: 'tn '
  selection_sc:
    CommandLine|contains|windash: 'sc '
  selection_ru:
    CommandLine|contains|windash: 'ru '
  selection_tr:
    CommandLine|contains|windash: 'tr '
  selection_ru_system:
    CommandLine|contains|windash: 'ru system'
  selection_sc_onstart:
    CommandLine|contains|windash: 'sc onstart'
  condition: (1 of selection_schtasks) and selection_create and selection_tn and selection_sc and selection_ru and selection_tr and (selection_ru_system or selection_sc_onstart)
falsepositives:
  - Legitimate scheduled task creation by administrators running as SYSTEM
  - Software installation that creates scheduled tasks running as SYSTEM on startup
level: medium
tags:
  - attack.t1053.005
  - attack.persistence
  - attack.privilege_escalation
```

## 19. `a8bb8c8c` · T1547.001 · written from tuning variations

- Model-call budget: 25; calls used: 20
- Quality checks: **passed**
  - no_copied_test_strings: warning, check these are general and not test-specific: CurrentVersion\Run
- Tuning variations caught: 0% → 100%; tuning false alarms: 0
- **Unseen variations caught: 0% → 57%** (insertion 3/6, omission 1/1)
- **New false alarms on unseen legitimate commands: 0**
- Unseen attack variations it misses (3, up to 4 shown):
  - insertion: `REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /"V" "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"`
  - insertion: `REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /"v" 1 /d "C:\Path\AtomicRedTeam.dll"`
  - insertion: `REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /"d" "C:\Path\AtomicRedTeam.dll"`

```yaml
title: "Registry Run/RunOnce Persistence via reg.exe"
id: 2035e159-92e8-5abd-b7a1-daa87880f32a
status: experimental
description: Detects registry modifications via reg.exe targeting Run and RunOnce keys for persistence (T1547.001). The rule keys on reg.exe writing to CurrentVersion\Run* keys with value (/V) and data (/D) parameters, using regex to tolerate all option prefix variants (/, -, Unicode dashes).
references:
  - https://attack.mitre.org/techniques/T1547/001/
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: \reg.exe
    - OriginalFileName: reg.exe
  selection_run_path:
    CommandLine|contains: 'CurrentVersion\Run'
  selection_v_param:
    CommandLine|re: '(?i)(^|\s)[^a-z0-9\s][v]\s'
  selection_d_param:
    CommandLine|re: '(?i)(^|\s)[^a-z0-9\s][d]\s'
  condition: all of selection_*
falsepositives:
  - Legitimate software installation or configuration that adds Run/RunOnce entries
  - System administration tasks
level: medium
tags:
  - attack.persistence
  - attack.t1547.001
```

## 20. `fdb2c4ba` · T1490 · written from tuning variations

- Model-call budget: 25; calls used: 7
- Quality checks: **passed**
  - no_copied_test_strings: warning, check these are general and not test-specific: set {default} bootstatuspolicy ignoreallfailures; set {default} recoveryenabled no
- Tuning variations caught: 0% → 100%; tuning false alarms: 0
- **Unseen variations caught: 0% → 50%** (insertion 0/2, omission 2/2)
- **New false alarms on unseen legitimate commands: 0**
- Unseen attack variations it misses (4, up to 4 shown):
  - insertion: `bcdedit.exe /"set" {default} bootstatuspolicy ignoreallfailures`
  - insertion: `bcdedit.exe /"set" {default} recoveryenabled no`
  - omission: `vssadmin delete shadows /all /quiet`
  - omission: `wmic shadowcopy delete`

```yaml
title: Inhibit System Recovery via bcdedit
id: 4ac02639-7d30-5e23-9444-054c55667171
status: experimental
description: Detects use of bcdedit.exe to disable boot status policy or recovery, which inhibits system recovery capabilities.
author: DetectForge (agent-written, human-reviewed before deployment)
date: '2026-11-22'
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: \bcdedit.exe
    - OriginalFileName: bcdedit.exe
  selection_cli:
    CommandLine|contains|windash:
      - 'set {default} bootstatuspolicy ignoreallfailures'
      - 'set {default} recoveryenabled no'
  condition: selection_img and selection_cli
level: high
falsepositives:
  - Legitimate administration of boot configuration (rare)
tags:
  - attack.t1490
```
