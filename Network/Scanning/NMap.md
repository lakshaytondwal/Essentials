# NMap

## 1. Introduction to Nmap

Nmap (Network Mapper) is a network scanning tool used to discover hosts, open ports, running services, operating systems, and network characteristics.

It works by sending crafted packets to a target and analyzing the responses.

Basic syntax:

```bash
nmap [scan type] [options] [target]
```

Example:

```bash
nmap 192.168.1.10
```

---

## 2. Target and Port Specification

Defines which hosts and ports Nmap will scan.

```bash
# Targets
nmap 192.168.1.10                          # single host
nmap 192.168.1.10 192.168.1.20 192.168.1.30 # multiple hosts
nmap 192.168.1.10-200                      # IP range
nmap 192.168.1.0/24                        # CIDR subnet
nmap -iL targets.txt                       # from file

# Ports
nmap 192.168.1.10                          # top 1000 ports (default)
nmap -p 22,80,443 192.168.1.10             # specific ports
nmap -p 1-1000 192.168.1.10                # port range
sudo nmap -p- 192.168.1.10                 # all ports

# Combined
sudo nmap -p 22,80,443 192.168.1.0/24
```

---

## 3. Host Discovery

Determines whether host is alive before scanning ports.

### Ping Scan (-sn)

```bash
nmap -sn 192.168.1.10
```

Purpose:

* Checks if host is alive
* Does not scan ports

Example:

```bash
nmap -sn 192.168.1.0/24
```

Use case:

Network discovery.

### Skip Host Discovery (-Pn)

```bash
nmap -Pn 192.168.1.10
```

Purpose:

Treats host as alive even if it does not respond to ping.

Use case:

* Firewall blocks ping
* Hidden systems

---

## 4. Port Scanning Techniques

### TCP Connect Scan (-sT)

```bash
nmap -sT 192.168.1.10
```

Characteristics:

* Full TCP handshake
* Reliable
* Detectable
* Does not require root

Use case:

When root access is not available.

### SYN Scan (-sS) — Recommended

```bash
sudo nmap -sS 192.168.1.10
```

Characteristics:

* Half-open scan
* Faster
* Stealthier
* Requires root

Scan all ports:

```bash
sudo nmap -sS -p- 192.168.1.10
```

Scan specific ports:

```bash
sudo nmap -sS -p 22,80,443 192.168.1.10
```

### UDP Scan (-sU)

```bash
sudo nmap -sU 192.168.1.10
```

Example:

```bash
sudo nmap -sU -p 53,161,123 192.168.1.10
```

Common UDP services:

* DNS (53)
* SNMP (161)
* NTP (123)

UDP scanning is slower than TCP.

Combine TCP and UDP:

```bash
sudo nmap -sS -sU 192.168.1.10
```

---

## 5. Service and Version Detection

### Service Version Detection (-sV)

```bash
nmap -sV 192.168.1.10
```

Detects:

* Service type
* Version number

Example output:

```bash
22/tcp open ssh OpenSSH 7.6
80/tcp open http Apache 2.4.29
```

Use case:

Vulnerability identification.

---

## 6. OS Detection (-O)

```bash
sudo nmap -O 192.168.1.10
```

Detects:

* Operating system
* Kernel version

Requires root/sudo.

---

## 7. Aggressive Scan (-A)

```bash
sudo nmap -A 192.168.1.10
```

Includes:

* OS detection
* Service detection
* Additional enumeration
* Traceroute

Use case:

Full system enumeration.

---

## 8. Verbose Output (-v, -vv)

```bash
nmap -v 192.168.1.10
```

More detailed:

```bash
nmap -vv 192.168.1.10
```

Shows scan progress and detailed results.

---

## 9. Timing Templates (-T0 to -T5)

Controls scan speed and aggressiveness.

```bash
nmap -T4 192.168.1.10
```

Timing levels:

```txt
-T0 → Paranoid
-T1 → Sneaky
-T2 → Polite
-T3 → Normal (default)
-T4 → Aggressive
-T5 → Insane
```

---

## 10. Saving Scan Results

---

### Normal output

```bash
nmap -oN output.txt 192.168.1.10
```

### XML output

```bash
nmap -oX output.xml 192.168.1.10
```

### Grepable output

```bash
nmap -oG output.gnmap 192.168.1.10
```

### Save all formats — Recommended

```bash
nmap -oA scan 192.168.1.10
```

Creates:

```txt
scan.nmap
scan.xml
scan.gnmap
```

---

## 11. Real-World Recon Workflow

```bash
# Step 1: discover live hosts
nmap -sn 192.168.1.0/24

# Step 2: scan all ports
sudo nmap -sS -p- 192.168.1.10

# Step 3: service detection
nmap -sV -p 22,80,443 192.168.1.10

# Step 4: system enumeration
sudo nmap -sV -O 192.168.1.10

# Step 5: full scan
sudo nmap -A -p- 192.168.1.10
```

---

## 12. Most Practical Real-World Scan Command

```bash
sudo nmap -sS -Pn -p- -sV -O -vv -oA full_scan target_ip
```

Provides:

* Stealth SYN scan
* All ports
* Service detection
* OS detection
* Verbose output
* Saved results

---

This structure mirrors how real penetration testers actually think: define the target surface, identify reachable systems, map exposed ports, fingerprint services, and extract system identity. Enumeration is not just data collection—it is turning an anonymous machine into a fully described entity with behaviors, weaknesses, and patterns.

---
