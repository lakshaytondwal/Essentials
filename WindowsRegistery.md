# Windows Registery

Numerous other registry keys can be used for extracting important evidence from a Windows system during an incident investigation. The investigation of these registry keys during forensics cannot be done via the built-in Registry Editor tool. It is because the Registry analysis cannot be done on the system under investigation (due to the chance of modification), so we collect the Registry Hives and open them offline into our forensic workstation. However, the Registry Editor does not allow opening offline hives. The Register editor also displays some of the key values in binary which are not readable.

To solve this problem, there are some tools built for registry forensics such as [Registry Explorer](https://ericzimmerman.github.io/) tool which is a registry forensics tool. It is open source and can parse the binary data out of the registry, and we can analyze it without the fear of modification.

| Registry Path                                                            | What It Stores                                                                                                  |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`     | Information about recently accessed applications launched via the GUI (tracks execution, ROT13-encoded values). |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`     | All paths and locations typed by the user into the Explorer address bar.                                        |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths`               | File system paths of registered applications (used to locate executables).                                      |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` | Search terms typed by the user in the Explorer search bar.                                                      |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`                     | Programs configured to automatically start when a user logs in (startup persistence).                           |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`     | Information about files recently accessed by the user, grouped by file extension.                               |
| `HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`        | The computer’s name (hostname).                                                                                 |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`               | Details of installed programs (name, version, install path, uninstall command).                                 |

---
---
---

| Registry Path                                                                         | What It Stores                                                                             |
| ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`                      | Commands typed into the **Run dialog** (`Win+R`). Excellent for tracking manual execution. |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`    | Files opened or saved via standard **Open/Save dialogs** (per file type).                  |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` | Last folders accessed via Open/Save dialogs, including the executable used.                |
| `HKLM\SYSTEM\CurrentControlSet\Services`                                              | Installed **services and drivers**. Malware loves persistence here.                        |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`                          | Logon behavior (Shell, Userinit). Classic persistence and hijacking target.                |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`                                  | User-level startup programs (per-user persistence).                                        |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`                | USB and removable media history (drive letters, volume names).                             |
| `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`                                          | Detailed USB storage device history (vendor, product, serial).                             |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedURLs`                   | URLs typed into Internet Explorer / legacy Edge address bar.                               |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`                                   | OS version, build, install date — baseline system fingerprinting.                          |
