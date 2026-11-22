# Hard-negative labelling sheet (blind)

Label every command on your own, without looking at `hard_negatives.yml` (its class and notes
are the answers) and without discussing. Write A, B or X in your labels file, plus a short reason.

Rubric (decide from the command line and the attack description only):
- A, over-breadth near-miss: the same tool, but a different action or target than the attack (read
  instead of write, a benign key or file instead of a sensitive one, local instead of remote). A rule
  written precisely for the attack would NOT match it; a rule that fires on it is too broad.
- B, inherent ambiguity: the same action on the same kind of target as the attack, run for a
  legitimate reason. No rule on the command line alone could tell them apart; only context could
  (who ran it, the process tree, the destination's reputation).
Ask: "Could I write a rule that catches every version of this attack and still stays silent on this
command?" Yes = A. No = B. If the command is itself malicious, write X and say why.

## Main set: the dataset's hard negatives

**T1003.001-n1** · T1003.001 · attack: Process Memory Dump Via Comsvcs.DLL   (attack dumps lsass PID 692 to a temp path)

    rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 4821 C:\ProgramData\Diagnostics\apphang.dmp full

**T1003.002-n1** · T1003.002 · attack: Dumping of Sensitive Hives Via Reg.EXE   (attack saves/exports HKLM\sam|security|system)

    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDrive

**T1003.002-n2** · T1003.002 · attack: Dumping of Sensitive Hives Via Reg.EXE   (attack saves/exports HKLM\sam|security|system)

    reg export "HKLM\SOFTWARE\MyCompany\App" C:\Users\analyst\Desktop\app-backup.reg

**T1003.002-n3** · T1003.002 · attack: Dumping of Sensitive Hives Via Reg.EXE   (attack saves/exports HKLM\sam|security|system)

    reg save "HKLM\SOFTWARE\MyCompany\App" C:\Users\analyst\Desktop\app.hiv

**T1027-n1** · T1027 · attack: Suspicious Download Via Certutil.EXE   (attack uses -verifyctl/-urlcache -f <url>)

    certutil -hashfile C:\Users\analyst\Downloads\installer.exe SHA256

**T1027-n2** · T1027 · attack: Suspicious Download Via Certutil.EXE   (attack uses -verifyctl/-urlcache -f <url>)

    certutil -dump C:\Users\analyst\Documents\company.cer

**T1027-n3** · T1027 · attack: Suspicious Download Via Certutil.EXE   (attack uses -verifyctl/-urlcache -f <url>)

    certutil -verifyctl -split -f C:\ProgramData\Company\trust.ctl

**T1036.003-n1** · T1036.003 · attack: File Download Via Bitsadmin   (attack /transfer <url>)

    bitsadmin /list /allusers /verbose

**T1036.003-n2** · T1036.003 · attack: File Download Via Bitsadmin   (attack /transfer <url>)

    bitsadmin /transfer UpdateJob /priority normal https://download.company.com/patch.msp C:\ProgramData\patch.msp

**T1036.003-n3** · T1036.003 · attack: File Download Via Bitsadmin   (attack /transfer <url>)

    bitsadmin /transfer PatchJob \\fileserver\share\patch.msp C:\ProgramData\patch.msp

**T1047-n1** · T1047 · attack: Process Creation via Wmic / XSL Script Execution via Wmic

    wmic process list brief

**T1047-n2** · T1047 · attack: Process Creation via Wmic / XSL Script Execution via Wmic

    wmic process get name,processid /format:htable

**T1047-n3** · T1047 · attack: Process Creation via Wmic / XSL Script Execution via Wmic

    wmic process call create "C:\Program Files\Company\agent.exe"

**T1053.005-n1** · T1053.005 · attack: Suspicious Schtasks Schedule Types / Schtasks with SYSTEM privileges

    schtasks /query /fo LIST /v

**T1053.005-n2** · T1053.005 · attack: Suspicious Schtasks Schedule Types / Schtasks with SYSTEM privileges

    schtasks /create /tn "CompanyUpdate" /tr "C:\Program Files\Company\update.exe" /sc daily /st 03:00

**T1053.005-n3** · T1053.005 · attack: Suspicious Schtasks Schedule Types / Schtasks with SYSTEM privileges

    schtasks /create /tn "DiskCleanup" /tr "cleanmgr.exe /sagerun:1" /sc weekly /d SUN /st 02:00

**T1059.001-n1** · T1059.001 · attack: PowerShell base64 / download pattern

    powershell.exe -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5"

**T1059.001-n2** · T1059.001 · attack: PowerShell base64 / download pattern

    powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\inventory.ps1

**T1059.001-n3** · T1059.001 · attack: PowerShell base64 / download pattern

    powershell.exe -ExecutionPolicy Bypass -Command "iwr https://intranet.company.com/agent.ps1 -OutFile C:\ProgramData\agent.ps1"

**T1059.003-n1** · T1059.003 · attack: Read Contents From Stdin Via Cmd.EXE   (attack uses cmd < file)

    cmd /c dir C:\Users\analyst\Documents

**T1059.003-n2** · T1059.003 · attack: Read Contents From Stdin Via Cmd.EXE   (attack uses cmd < file)

    cmd /c type C:\Users\analyst\notes.txt

**T1059.003-n3** · T1059.003 · attack: Read Contents From Stdin Via Cmd.EXE   (attack uses cmd < file)

    cmd /c sort < C:\Users\analyst\Documents\list.txt

**T1105-n1** · T1105 · attack: Suspicious Curl Download / File Download via MpCmdRun

    curl -I https://api.company.com/health

**T1105-n2** · T1105 · attack: Suspicious Curl Download / File Download via MpCmdRun

    "C:\Program Files\Windows Defender\MpCmdRun.exe" -SignatureUpdate

**T1105-n3** · T1105 · attack: Suspicious Curl Download / File Download via MpCmdRun

    curl -o C:\Users\analyst\Downloads\logo.png https://www.company.com/logo.png

**T1105-n4** · T1105 · attack: Suspicious Curl Download / File Download via MpCmdRun

    curl -k http://localhost:8080/status -o C:\ProgramData\status.json

**T1218.005-n1** · T1218.005 · attack: Remotely Hosted HTA via Mshta   (attack runs remote script:)

    mshta.exe "C:\Program Files\Company\dialog.hta"

**T1218.005-n2** · T1218.005 · attack: Remotely Hosted HTA via Mshta   (attack runs remote script:)

    mshta.exe "C:\ProgramData\Company\wizard.hta"

**T1218.007-n1** · T1218.007 · attack: Msiexec Quiet Install From Remote   (attack /i <url>)

    msiexec /i "C:\Users\analyst\Downloads\app.msi" /qn

**T1218.007-n2** · T1218.007 · attack: Msiexec Quiet Install From Remote   (attack /i <url>)

    msiexec /x {3F2504E0-4F89-11D3-9A0C-0305E82C3301} /quiet

**T1218.007-n3** · T1218.007 · attack: Msiexec Quiet Install From Remote   (attack /i <url>)

    msiexec /i "\\deploy\software\tool.msi" /qn

**T1218.010-n1** · T1218.010 · attack: Regsvr32 HTTP/FTP Pattern   (attack /i:<url> scrobj.dll)

    regsvr32 /s "C:\Program Files\Company\plugin.dll"

**T1218.010-n2** · T1218.010 · attack: Regsvr32 HTTP/FTP Pattern   (attack /i:<url> scrobj.dll)

    regsvr32 /u /s "C:\Program Files\Company\plugin.dll"

**T1218.010-n3** · T1218.010 · attack: Regsvr32 HTTP/FTP Pattern   (attack /i:<url> scrobj.dll)

    regsvr32 /s /i:"C:\Program Files\Company\setup.dll"

**T1218.011-n1** · T1218.011 · attack: Potentially Suspicious Rundll32 Activity

    rundll32.exe shell32.dll,Control_RunDLL desk.cpl

**T1218.011-n2** · T1218.011 · attack: Potentially Suspicious Rundll32 Activity

    rundll32.exe user32.dll,LockWorkStation

**T1218.011-n3** · T1218.011 · attack: Potentially Suspicious Rundll32 Activity

    rundll32.exe printui.dll,PrintUIEntry /in /n "\\printserver\HP"

**T1490-n1** · T1490 · attack: Shadow Copies Deletion / Wbadmin / Bcdedit Boot Config Tampering

    vssadmin list shadows

**T1490-n2** · T1490 · attack: Shadow Copies Deletion / Wbadmin / Bcdedit Boot Config Tampering

    bcdedit /enum

**T1490-n3** · T1490 · attack: Shadow Copies Deletion / Wbadmin / Bcdedit Boot Config Tampering

    wbadmin get versions

**T1490-n4** · T1490 · attack: Shadow Copies Deletion / Wbadmin / Bcdedit Boot Config Tampering

    vssadmin delete shadows /all /quiet

**T1490-n5** · T1490 · attack: Shadow Copies Deletion / Wbadmin / Bcdedit Boot Config Tampering

    bcdedit /set {current} description "Production Boot"

**T1543.003-n1** · T1543.003 · attack: Suspicious New Service Creation

    sc query wuauserv

**T1543.003-n2** · T1543.003 · attack: Suspicious New Service Creation

    sc create "CompanyAgent" binPath= "C:\Program Files\Company\agent.exe" start= auto

**T1543.003-n3** · T1543.003 · attack: Suspicious New Service Creation

    sc create "BackupSvc" binPath= "C:\Program Files\Backup\bksvc.exe" start= demand

**T1547.001-n1** · T1547.001 · attack: Run Keys persistence

    reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

**T1547.001-n2** · T1547.001 · attack: Run Keys persistence

    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /t REG_SZ /d "C:\Program Files\OneDrive\OneDrive.exe" /f

**T1547.001-n3** · T1547.001 · attack: Run Keys persistence

    reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v CompanyApp

**T1555.003-n1** · T1555.003 · attack: Potential Browser Data Stealing (esentutl /y copy)

    esentutl.exe /y "C:\ProgramData\App\cache.edb" /d "C:\Temp\cache_copy.edb"

**T1555.003-n2** · T1555.003 · attack: Potential Browser Data Stealing (esentutl /y copy)

    esentutl /mh "C:\ProgramData\App\store.edb"

**T1555.003-n3** · T1555.003 · attack: Potential Browser Data Stealing (esentutl /y copy)

    esentutl.exe /y "C:\ProgramData\App\index.edb" /d "C:\Temp\index_copy.edb"

**T1685-n1** · T1685 · attack: Disable Windows Defender AV (sc config/stop WinDefend)

    sc query WinDefend

**T1685-n2** · T1685 · attack: Disable Windows Defender AV (sc config/stop WinDefend)

    sc config Fax start=disabled

**T1685-n3** · T1685 · attack: Disable Windows Defender AV (sc config/stop WinDefend)

    sc stop Spooler

**T1685.001-n1** · T1685.001 · attack: Audit Policy Tampering / Eventlog Clearing

    auditpol /get /category:*

**T1685.001-n2** · T1685.001 · attack: Audit Policy Tampering / Eventlog Clearing

    auditpol /set /category:"Logon/Logoff" /success:enable

**T1685.001-n3** · T1685.001 · attack: Audit Policy Tampering / Eventlog Clearing

    wevtutil cl Application

**T1685.001-n4** · T1685.001 · attack: Audit Policy Tampering / Eventlog Clearing

    auditpol /set /category:"Policy Change" /success:enable

## Pilot: new look-alikes

**pilot-1** · T1003.002 · attack: Dumping of Sensitive Hives Via Reg.EXE   (attack saves/exports HKLM\sam|security|system)

    reg query HKLM\SYSTEM\CurrentControlSet\Control\Session Manager /v PendingFileRenameOperations

**pilot-2** · T1003.002 · attack: Dumping of Sensitive Hives Via Reg.EXE   (attack saves/exports HKLM\sam|security|system)

    reg query HKLM\SECURITY\Policy

**pilot-3** · T1003.002 · attack: Dumping of Sensitive Hives Via Reg.EXE   (attack saves/exports HKLM\sam|security|system)

    reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

**pilot-4** · T1003.002 · attack: Dumping of Sensitive Hives Via Reg.EXE   (attack saves/exports HKLM\sam|security|system)

    reg delete HKLM\SYSTEM\CurrentControlSet\Services\OldDriver /f

**pilot-5** · T1547.001 · attack: Run Keys persistence

    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OldApp /f

**pilot-6** · T1543.003 · attack: Suspicious New Service Creation

    wmic service where name="OldSvc" delete

**pilot-7** · T1490 · attack: Shadow Copies Deletion / Wbadmin / Bcdedit Boot Config Tampering

    wbadmin start systemstatebackup -backupTarget:E: -quiet
