# Netcat as a Port Scanner

Useful when other scanning tools are unavailable.

```bash
nc -nv -w 1 -z [TARGET] [PORT_RANGE]
```

* `-n` → No DNS resolution
* `-v` → Verbose output
* `-w` → Timeout (in seconds)
* `-z` → Scan mode (no data transfer)

---

## One-liner for HTTP Port Scan (Port 80)

```bash
while read ip; do nc -nv -w 1 -z "$ip" 80; done < ip_list.txt
```

---

## Python Script Version

```python
#!/usr/bin/python3
import os

with open("ip_list.txt", "r") as f:
    for line in f:
        ip = line.strip()
        os.system(f"nc -nv -w 1 -z {ip} 80")
```

---
