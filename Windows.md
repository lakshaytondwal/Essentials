# Windows Essentials

---

## PowerShell Command Reference

### General Commands

- `Get-Command`  
  Shows available commands (cmdlets).

- `Get-Command -CommandType "Function"`  
  Filters commands based on type.

- `Get-Help <CMDLET>`  
  Provides help information about a cmdlet.

- `Get-Help <CMDLET> -examples`  
  Shows usage examples of a cmdlet.

- `Get-Alias`  
  Lists all aliases for cmdlets.

- `Find-Module -Name "PowerShell*"`  
  Searches for PowerShell modules online.

- `Install-Module -Name "PowerShellGet"`  
  Installs a module from online sources.

### Filesystem Commands

- `Get-ChildItem`  
  Lists the content of the current directory.

- `Get-ChildItem -Path "<PATH>"`  
  Lists the content of the specified directory.

- `Get-Content -Path "<PATH>"`  
  Displays the content of a file.

- `Set-Location`  
  Changes (sets) the current working directory.

- `New-Item -Path "<PATH>" -ItemType "Directory"`  
  Creates a new directory.

- `New-Item -Path "<PATH/new.txt>" -ItemType "file"`  
  Creates a new file.

- `Remove-Item -Path "<PATH>"`  
  Deletes a file or directory.

- `Copy-Item -Path "<PATH>" -Destination "<DESTINATION>"`  
  Copies an item from one location to another.

- `Move-Item -Path "<PATH>" -Destination "<DESTINATION>"`  
  Moves an item from one location to another.

### Pipelining Examples

- `Get-ChildItem | Sort-Object Length`  
  Sorts items by length.

- `Get-ChildItem | Where-Object -Property "Extension" -eq ".txt"`  
  Filters only `.txt` files.

- `Get-ChildItem | Where-Object -Property "Name" -like "ship*"`  
  Filters files that start with "ship".

- `Get-ChildItem | Select-Object Name, Length`  
  Displays only name and size of items.

- `Select-String -Path ".\captain-hat.txt" -Pattern "hat"`  
  Searches for the pattern "hat" in a file.

### System Information

- `Get-ComputerInfo`  
  Retrieves system and OS info.

- `Get-LocalUser`  
  Lists all local users.

- `Get-NetIPConfiguration`  
  Displays network configuration.

- `Get-NetIPAddress`  
  Shows assigned IP addresses.

### Process and Network

- `Get-Process`  
  Lists all running processes.

- `Get-Service`  
  Lists all services.

- `Get-NetTCPConnection`  
  Displays TCP network connections.

- `Get-FileHash -Path "<PATH>"`  
  Computes the hash value of a file.

### Remote Execution

- `Invoke-Command`  
  Runs a command on a local or remote computer.

---

## Windows Command Line Reference

### Basic System Commands

- `set`  
  Displays environment variables.

- `path`  
  Displays or sets the system path.

- `ver`  
  Displays the Windows version.

- `sysinfo`  
  Displays detailed system information.

### Network Commands

- `ipconfig`  
  Displays IP configuration.

- `ipconfig /all`  
  Displays detailed IP info including MAC address, DHCP, DNS, etc.

- `tracert example.com`  
  Traces the route to a remote host.

- `nslookup example.com`  
  Queries DNS to obtain domain name or IP address mapping.

- `netstat`  
  Displays active network connections and ports.

- `netstat -abon`  
  Shows detailed connection info:
  - `-a`: Displays all connections and listening ports  
  - `-b`: Shows the executable involved in creating the connection  
  - `-o`: Displays the owning process ID (PID)  
  - `-n`: Displays addresses and port numbers in numerical form

### File System Navigation & Management

- `cd`  
  Changes the current directory.

- `cd ..`  
  Moves up one directory level.

- `dir`  
  Lists contents of a directory.

- `dir /a`  
  Lists all files including hidden/system files.

- `dir /s`  
  Lists all files in the current and subdirectories.

- `tree`  
  Graphically displays folder structure.

- `mkdir <folder>`  
  Creates a new directory.

- `move <source> <destination>`  
  Moves a file or folder.

- `copy <source> <destination>`  
  Copies a file or folder.

- `del <file>`  
  Deletes a file.

- `erase <file>`  
  Deletes one or more files (similar to `del`).

- `type <file>`  
  Displays the content of a file.

- `more`  
  Used with piping (`|`) to paginate output, e.g. `some_command | more`.

### Task & Process Management

- `tasklist`  
  Lists currently running processes.

- `tasklist /?`  
  Shows help for `tasklist`.

- `tasklist /FI "imagename eq sshd.exe"`  
  Filters the task list by image name.

- `taskkill /PID <target_pid>`  
  Terminates a process using its PID.

### System Utilities

- `chkdsk`  
  Checks disk and file system for errors and bad sectors.

- `driverquery`  
  Displays a list of installed device drivers.

- `sfc /scannow`  
  Scans system files and repairs any corruption.

### Shutdown Commands

- `shutdown /s`  
  Shuts down the computer.

- `shutdown /r`  
  Restarts the computer.

- `shutdown /a`  
  Aborts a system shutdown.
