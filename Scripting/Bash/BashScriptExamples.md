# Bash Script examples

```bash
#!/bin/bash
# Logs basic system information (date, user, hostname, uptime, disk usage) into a file.

logfile="system_info.log"

echo "==== System Info Log ====" >> "$logfile"
echo "Date: $(date)" >> "$logfile"
echo "User: $(whoami)" >> "$logfile"
echo "Hostname: $(hostname)" >> "$logfile"
echo "Uptime: $(uptime -p)" >> "$logfile"
echo "Disk Usage:" >> "$logfile"
df -h >> "$logfile"

echo "Saved to $logfile"
```

```bash
#!/bin/bash
# Creates a compressed backup of the Documents directory with a timestamped filename.

source_dir="$HOME/Documents"
backup_dir="$HOME/backup"

mkdir -p "$backup_dir"

timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
backup_file="$backup_dir/backup_$timestamp.tar.gz"

tar -czf "$backup_file" "$source_dir"

echo "Backup created: $backup_file"
```

```bash
#!/bin/bash
# Checks whether a given system user exists.

read -p "Enter username: " username

if id "$username" &>/dev/null
then
    echo "User exists"
else
    echo "User does not exist"
fi
```

```bash
#!/bin/bash
# Generates a random 12-character alphanumeric password.

length=12
password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c $length)

echo "Generated Password: $password"
```

```bash
#!/bin/bash
# Verifies whether a specific file exists on the system.

file="/etc/passwd"

if [ -f "$file" ]
then
    echo "File exists"
else
    echo "File missing"
fi
```

```bash
#!/bin/bash
# Reads usernames from users.txt and checks if each user exists.

while read user
do
    if id "$user" &>/dev/null
    then
        echo "$user exists"
    else
        echo "$user does not exist"
    fi
done < users.txt
```

```bash
#!/bin/bash
# Accepts a service action (start/stop/restart) and performs the corresponding operation message.

read -p "Enter action (start/stop/restart): " action

case $action in
    start)
        echo "Starting service..."
        ;;
    stop)
        echo "Stopping service..."
        ;;
    restart)
        echo "Restarting service..."
        ;;
    *)
        echo "Invalid option"
        ;;
esac
```

```bash
#!/bin/bash
# Checks root disk usage and warns if it exceeds 80%.

usage=$(df / | grep / | awk '{print $5}' | sed 's/%//')

if [ "$usage" -gt 80 ]
then
    echo "Disk usage is above 80%"
else
    echo "Disk usage is normal"
fi
```

```bash
#!/bin/bash
# Accepts a filename as a command-line argument and checks if it exists.

if [ $# -eq 0 ]
then
    echo "Usage: $0 filename"
    exit 1
fi

file=$1

if [ -f "$file" ]
then
    echo "File exists"
else
    echo "File does not exist"
fi
```

```bash
#!/bin/bash
# Performs basic network reconnaissance by pinging a target and running an Nmap scan.

read -p "Enter target IP: " target

echo "Pinging target..."
ping -c 1 "$target"

echo "Scanning ports..."
nmap "$target"
```
