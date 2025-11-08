
---

# Download and install Software

---

## Git for Windows

https://gitforwindows.org/

## Visual Studio Build Tools for C++

https://visualstudio.microsoft.com/visual-cpp-build-tools/
## python-snappy
https://www.piwheels.org/project/python-snappy/

## Volatility

https://github.com/volatilityfoundation/volatility3

```bash
# git clone https://github.com/volatilityfoundation/volatility3.git
```





```powershell
C:\> python -V                                # check python version
C:\> pip install python_snappy-0.7.3-py3-none-any.whl   # install whl
C:\> pip install volatility3                  # install volatility
```

`Restart computer`

---

# Download sample 

https://archive.org/details/Africa-DFIRCTF-2021-WK02

---

# Analyzing Sample with Volatility

---


```powershell

C:\> python vol.py -f ACTF.mem windows.info

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.pslist | more
# Interesting things to look at: PID, PPID, ImageFileName, Threads, Handles

PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

4       0       System  0xbf0f64a63080  132     -       N/A     False   2021-04-30 12:39:40.000000 UTC  N/A     Disabled
108     4       Registry        0xbf0f64bc6040  4       -       N/A     False   2021-04-30 12:39:38.000000 UTC  N/A     Disabled
396     4       smss.exe        0xbf0f66967040  2       -       N/A     False   2021-04-30 12:39:40.000000 UTC  N/A     Disabled
492     484     csrss.exe       0xbf0f6adb6080  13      -       0       False   2021-04-30 12:39:44.000000 UTC  N/A     Disabled

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.pslist | Select-String chrome
# search for chrome in linux using 'grep' in place of 'Select-String' and "linux.pslist" 

Progress:  100.00               PDB scanning finished
1328    4352    chrome.exe      0xbf0f6d53e080  26      -       1       False   2021-04-30 17:44:52.000000 UTC  N/A     Disabled
6764    1328    chrome.exe      0xbf0f6d748080  7       -       1       False   2021-04-30 17:44:52.000000 UTC  N/A     Disabled

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.handles -h
# use help to find information about a plugin, run without specifying a pid will show all handles which is alot of info

PID     Process Offset  HandleValue     Type    GrantedAccess   Name

1328    chrome.exe      0xbf0f6cb02260  0x4     Event   0x1f0003        -
1328    chrome.exe      0xbf0f6cb03360  0x8     Event   0x1f0003        -
1328    chrome.exe      0xbf0f6d0547c0  0xc     WaitCompletionPacket    0x1     -

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.handles -h
# use help to find information about a plugin, run without specifying a pid will show all handles which is alot of info

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.handles --pid 1328 | more
# Interesting things to look at: PID, PPID, ImageFileName, Threads, Handles

PID     Process Offset  HandleValue     Type    GrantedAccess   Name

1328    chrome.exe      0xbf0f6cb02260  0x4     Event   0x1f0003        -
1328    chrome.exe      0xbf0f6cb03360  0x8     Event   0x1f0003        -
1328    chrome.exe      0xbf0f6d0547c0  0xc     WaitCompletionPacket    0x1     -
1328    chrome.exe      0xbf0f6ab07900  0x10    IoCompletion    0x1f0003        -

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.handles --pid 1328 | Select-String File | more
# Grab all handles pointing to files in the process

1328    chrome.exe      0xbf0f6ac8c9f0  0x70    File    0x100020        \Device\HarddiskVolume2\Program Files\Google\Chrome\Application\90.0.4430.93
1328    chrome.exe      0xbf0f6ac8a470  0x8c    File    0x100001        \Device\KsecDD
1328    chrome.exe      0xbf0f6ac8bd70  0x9c    File    0x100001        \Device\CNG

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.handles --pid 1328 | Select-String File | Select-String history | more
# Grab all handles pointing to files with history in the process

1328    chrome.exe      0xbf0f6abe9740  0x89c   File    0x12019f        \Device\HarddiskVolume2\Users\John Doe\AppData\Local\Google\Chrome\User Data\Default\History
1328    chrome.exe      0xbf0f6abe95b0  0x8c4   File    0x12019f        \Device\HarddiskVolume2\Users\John Doe\AppData\Local\Google\Chrome\User Data\Default\Media History
1328    chrome.exe      0xbf0f6aca1e90  0x1478  File    0x12019f        \Device\HarddiskVolume2\Users\John Doe\AppData\Local\Google\Chrome\User Data\Default\History-journal

-----------------------------------------------

C:\> mkdir dump
# Creating a folder called dump to pull data from the memory file

-----------------------------------------------

C:\> python vol.py -f ACTF.mem -o "dump" windows.dumpfile --pid 1328 --virtaddr 0xbf0f6abe9740
# Dumping the history file from the process

Progress:  100.00               PDB scanning finished
Cache   FileObject      FileName        Result

DataSectionObject       0xbf0f6abe9740  History Error dumping file
SharedCacheMap  0xbf0f6abe9740  History file.0xbf0f6abe9740.0xbf0f6c107c70.SharedCacheMap.History.vacb

-----------------------------------------------

C:\> python vol.py -f ACTF.mem -o "dump" windows.dumpfile --pid 1328
# You can dump all the files from a process and scan them with AV, just dont use a virtual address, easier to do one at a time though

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.cmdline | more
# Showing comand line args, look for switches used for launch ie "-k DcomLaunch -p" 

PID     Process Args

4       System  -
108     Registry        -
396     smss.exe        \SystemRoot\System32\smss.exe
492     csrss.exe       %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
568     wininit.exe     wininit.exe
856     svchost.exe     C:\Windows\system32\svchost.exe -k DcomLaunch -p

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.netstat | more
# Shows offset in the memory image and network connections

Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created

0xbf0f6a535aa0  TCPv4   10.0.2.15       49846   96.90.32.107    7680    SYN_SENT        2116    svchost.exe     2021-04-30 17:52:01.000000 UTC
0xbf0f6d8a1010  TCPv4   10.0.2.15       49771   185.70.41.35    443     CLOSE_WAIT      1840    chrome.exe      2021-04-30 17:44:57.000000 UTC
0xbf0f6cbb9530  TCPv4   10.0.2.15       49772   185.70.41.35    443     FIN_WAIT2       1840    chrome.exe      2021-04-30 17:44:58.000000 UTC

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.netstat | Select-String chrome | more
# Shows only chrome related network connections

0xbf0f6d8a1010  TCPv4   10.0.2.15       49771   185.70.41.35    443     CLOSE_WAIT      1840    chrome.exe      2021-04-30 17:44:57.000000 UTC
0xbf0f6cbb9530  TCPv4   10.0.2.15       49772   185.70.41.35    443     FIN_WAIT2       1840    chrome.exe      2021-04-30 17:44:58.000000 UTC
0xbf0f6ca71a20  TCPv4   10.0.2.15       49769   142.250.190.14  443     CLOSE_WAIT      1840    chrome.exe      2021-04-30 17:44:55.000000 UTC

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.hashdump | more
# Dump hashes to crack the values, may be useful for rogue user acct or pentest

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.registry.userassist | more
# Look at Hive Offset, Hive Name and use Last Write to determine last time something was written to that key, focus count shows how many time a user focused on a specific window, Time focused is how long a user was looking at something over time not per session

Hive Offset     Hive Name       Path    Last Write Time Type    Name    ID      Count   Focus Count     Time Focused    Last Updated    Raw Data

0xa80333cda000  \??\C:\Users\John Doe\ntuser.dat        ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}\Count   2021-04-25 17:57:45.000000 UTC  Key     N/A     N/A     N/A     N/A     N/A     N/A     N/A
0xa80333cda000  \??\C:\Users\John Doe\ntuser.dat        ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{A3D53349-6E61-4557-8FC7-0028EDCEEBF6}\Count   2021-04-25 17:57:45.000000 UTC  Key     N/A     N/A     N/A     N/A     N/A     N/A     N/A
* 0xa80333cda000        \??\C:\Users\John Doe\ntuser.dat        ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count   2021-04-30 17:52:18.000000 UTC  Value   %windir%\system32\mspaint.exe   N/A     7       7       0:01:00.504000  2021-04-25 17:56:02.000000 UTC
00 00 00 00 07 00 00 00 07 00 00 00 64 ea 00 00 ............d...
00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf ................
00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf ................
00 00 80 bf 00 00 80 bf ff ff ff ff b2 45 d3 41 .............E.A
fc 39 d7 01 00 00 00 00                         .9......

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.registry.hivelist --filter John
# filter hives with John listed, you can also dump the files or leave off the filter value to show all

Offset  FileFullPath    File output

0xa80333cda000  \??\C:\Users\John Doe\ntuser.dat        Disabled
0xa80333d60000  \??\C:\Users\John Doe\AppData\Local\Microsoft\Windows\UsrClass.dat      Disabled
0xa80334a9e000  \??\C:\Users\John Doe\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\Settings\settings.dat      Disabled
0xa80334cd8000  \??\C:\Users\John Doe\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\Settings\settings.dat       Disabled
0xa8033522b000  \??\C:\Users\John Doe\AppData\Local\Packages\Microsoft.LockApp_cw5n1h2txyewy\Settings\settings.dat      Disabled

-----------------------------------------------

C:\> python vol.py -f ACTF.mem -o "dump" windows.registry.hivelist --filter Doe\ntuser.dat --dump
# This will dump the users ntuser.dat file

Offset  FileFullPath    File output

0xa80333cda000  \??\C:\Users\John Doe\ntuser.dat        registry.ntuserdat.0xa80333cda000.hive

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion" | more
# Print out the registry keys 

Last Write Time Hive Offset     Type    Key     Name    Data    Volatile

-       0xa8032f064000  Key     [NONAME]\Software\Microsoft\Windows\CurrentVersion      -       -       -
-       0xa8032f089000  Key     \REGISTRY\MACHINE\SYSTEM\Software\Microsoft\Windows\CurrentVersion      -       -       -
-       0xa8032f135000  Key     \REGISTRY\MACHINE\HARDWARE\Software\Microsoft\Windows\CurrentVersion    -       -       -
-       0xa8033262f000  Key     \Device\HarddiskVolume1\Boot\BCD\Software\Microsoft\Windows\CurrentVersion      -       -       -
-       0xa8032fac1000  Key     \SystemRoot\System32\Config\SOFTWARE\Software\Microsoft\Windows\CurrentVersion  -       -       -
2021-04-25 18:07:47.000000 UTC  0xa8032f632000  Key     \SystemRoot\System32\Config\DEFAULT\Software\Microsoft\Windows\CurrentVersion   CloudStore      N/A     False
2021-04-29 14:19:16.000000 UTC  0xa8032f632000  Key     \SystemRoot\System32\Config\DEFAULT\Software\Microsoft\Windows\CurrentVersion   Explorer        N/A     False
2021-04-25 18:08:15.000000 UTC  0xa8032f632000  Key     \SystemRoot\System32\Config\DEFAULT\Software\Microsoft\Windows\CurrentVersion   FileAssociations        N/A     False

-----------------------------------------------

C:\> python vol.py -f ACTF.mem windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion" --recurse | more
# Print out the registry keys but recursively showing all the keys

-       0xa8032f064000  Key     [NONAME]\Software\Microsoft\Windows\CurrentVersion      -       -       -
-       0xa8032f089000  Key     \REGISTRY\MACHINE\SYSTEM\Software\Microsoft\Windows\CurrentVersion      -       -       -
-       0xa8032f135000  Key     \REGISTRY\MACHINE\HARDWARE\Software\Microsoft\Windows\CurrentVersion    -       -       -
-       0xa8033262f000  Key     \Device\HarddiskVolume1\Boot\BCD\Software\Microsoft\Windows\CurrentVersion      -       -       -
-       0xa8032fac1000  Key     \SystemRoot\System32\Config\SOFTWARE\Software\Microsoft\Windows\CurrentVersion  -       -       -
2021-04-25 18:07:47.000000 UTC  0xa8032f632000  Key     \SystemRoot\System32\Config\DEFAULT\Software\Microsoft\Windows\CurrentVersion   CloudStore      N/A     False
* 2021-04-25 18:07:47.000000 UTC        0xa8032f632000  Key     \SystemRoot\System32\Config\DEFAULT\Software\Microsoft\Windows\CurrentVersion\CloudStore        SystemMetaData  N/A     False
** 2021-04-25 18:07:47.000000 UTC       0xa8032f632000  REG_DWORD       \SystemRoot\System32\Config\DEFAULT\Software\Microsoft\Windows\CurrentVersion\CloudStore\SystemMetaData HasCuratedTileCollectionsInitialized    1       False
2021-04-29 14:19:16.000000 UTC  0xa8032f632000  Key     \SystemRoot\System32\Config\DEFAULT\Software\Microsoft\Windows\CurrentVersion   Explorer        N/A     False 

-----------------------------------------------






```


---

# Key Volatility 3 Windows plugins and their forensic use

Here’s a categorized overview of important Windows plugins, what they do, and why they matter in memory analysis.

## Process and Thread Analysis

**windows.pslist.PsList**

- Lists active processes using the EPROCESS list.
- Forensic use: Detects active processes, helps identify known or suspicious programs.

**windows.psscan.PsScan**

- Scans memory for EPROCESS structures.
- Forensic use: Identifies hidden or terminated processes that may not appear in standard lists.

**windows.pstree.PsTree**

- Displays process hierarchy (parent-child relationships).
- Forensic use: Traces process lineage and detects potential injection or privilege escalation chains.

**windows.psxview.PsXView**

- Cross-verifies processes using multiple enumeration techniques.
- Forensic use: Highlights stealth techniques such as Direct Kernel Object Manipulation (DKOM).

**windows.threads.Threads**

- Lists all active threads in the system.
- Forensic use: Identifies rogue or anomalous thread activity.

**windows.suspicious_threads.SuspiciousThreads**

- Detects threads based on suspicious behaviors.
- Forensic use: Useful for malware detection or thread injection analysis.

## Malware and Injection Detection

**windows.malfind.Malfind**

- Identifies suspicious memory regions linked to code injection.
- Forensic use: Detects reflective DLL injection, process hollowing, and other malware behaviors.

**windows.hollowprocesses.HollowProcesses**

- Detects hollowed processes.
- Forensic use: Confirms whether an attacker replaced process memory with malicious code.

**windows.vadinfo.VadInfo**

- Shows Virtual Address Descriptors (VADs) of processes.
- Forensic use: Reveals unusual memory allocations or hidden code.

**windows.vadyarascan.VadYaraScan**

- Performs YARA signature matching on VADs.
- Forensic use: Detects known malware based on custom or public YARA rules.

**windows.iat.IAT** and **windows.ssdt.SSDT**

- Show Import Address Table and System Service Dispatch Table.
- Forensic use: Detects API hooking or rootkit behavior.

## Credential and Registry Analysis

**windows.hashdump**

- Extracts NTLM hashes from memory.
- Forensic use: Enables offline password cracking for user accounts.

**windows.lsadump (or) windows.registry.lsadump**

- Dumps LSA secrets such as cached passwords and service credentials.
- Forensic use: Critical for privilege escalation and lateral movement analysis.

**windows.cachedump**

- Retrieves cached domain credentials.
- Forensic use: Supports analysis of offline access or domain authentication.

**windows.registry.printkey**

- Prints the values of registry keys.
- Forensic use: Used to extract autostart entries, malware configs, or user activity.

**windows.registry.userassist**

- Lists applications recently executed by the user.
- Forensic use: Provides insights into user behavior and application usage.

## Services and Network Activity

**windows.svcscan**

- Scans for registered services.
- Forensic use: Identifies unauthorized or malicious services.

**windows.svclist**

- Lists services associated with processes.
- Forensic use: Verifies consistency of service-related processes.

**windows.netscan**

- Lists active TCP/UDP connections.
- Forensic use: Reveals network activity including potential C2 communication.

**windows.netstat**

- Emulates netstat output from memory.
- Forensic use: Helps identify suspicious remote connections.

## Files, DLLs, and Handles

**windows.dlllist**

- Lists loaded DLLs for each process.
- Forensic use: Detects unsigned or injected modules.

**windows.filescan**

- Scans memory for FILE_OBJECTs.
- Forensic use: Recovers open or deleted files that were accessed during runtime.

**windows.handles**

- Displays all open handles per process.
- Forensic use: Shows access to files, registry keys, mutexes, and other objects.

## Drivers and Kernel Structures

**windows.modules** and **windows.modscan**

- Show loaded kernel modules and scan for driver artifacts.
- Forensic use: Detects unsigned drivers or kernel rootkits.

**windows.drivermodule**

- Maps driver objects to loaded modules.
- Forensic use: Helps analyze third-party or malicious drivers.

**windows.callbacks**

- Lists kernel callback functions.
- Forensic use: Identifies potential hooks used by rootkits.

**windows.kpcrs**

- Dumps Kernel Processor Control Regions (per-CPU).
- Forensic use: Validates multi-core memory parsing and CPU control.

## System Info and Miscellaneous

**windows.info**

- Displays OS version, architecture, and symbol information.
- Forensic use: Essential for validating the memory image context and plugin compatibility.

**windows.envars**

- Lists environment variables of each process.
- Forensic use: Checks for evidence of persistence or attacker behavior.

**windows.getsids**

- Retrieves Security Identifiers (SIDs) for processes.
- Forensic use: Analyzes user tokens and impersonation attacks.

**windows.privileges**

- Shows privileges held by each process.
- Forensic use: Identifies privilege escalation or SeDebugPrivilege abuse.

**windows.strings**

- Extracts printable ASCII and Unicode strings from memory.
- Forensic use: Reveals command-line arguments, IP addresses, and hardcoded malware indicators.