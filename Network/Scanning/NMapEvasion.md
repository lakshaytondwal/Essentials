# NMap Firewall and IDS Evasion Techniques

Firewalls and Intrusion Detection Systems (IDS) analyze packet structure, timing, and origin to detect scans.

Nmap provides techniques to evade or bypass detection.

These techniques manipulate:

* Packet size
* Packet timing
* Packet fragmentation
* Source identity
* Packet validity

## 1. Packet Fragmentation (-f)

```bash
sudo nmap -f 192.168.1.10
```

Purpose:
Breaks packets into smaller fragments.

How it works:

Instead of sending one complete packet:

```tcp
[Complete TCP Header]
```

It sends fragments:

```tcp
[Fragment 1]
[Fragment 2]
[Fragment 3]
```

Effect:

Some firewalls and IDS fail to properly reassemble fragments, allowing packets to bypass detection.

Use case:

* Bypass poorly configured firewalls
* Avoid simple IDS detection

Example:

```bash
sudo nmap -sS -f 192.168.1.10
```

More fragmentation:

```bash
sudo nmap -sS -ff 192.168.1.10
```

---

## 2. Custom MTU (--mtu)

```bash
sudo nmap --mtu 8 192.168.1.10
```

Purpose:
Manually specifies packet fragment size.

MTU = Maximum Transmission Unit

Example values:

```txt
8
16
24
32
64
```

Requirement:

Must be multiple of 8.

Example:

```bash
sudo nmap -sS --mtu 16 192.168.1.10
```

Effect:

* Controls exact fragment size
* Helps bypass advanced firewalls

Difference from -f:

* `-f` = automatic fragmentation
* `--mtu` = manual control

---

## 3. Scan Delay (--scan-delay)

```bash
sudo nmap --scan-delay 5s 192.168.1.10
```

Purpose:
Adds delay between packets.

Example:

```bash
--scan-delay 1s
--scan-delay 500ms
--scan-delay 10s
```

Effect:

Avoids IDS detection based on scan speed.

Normal scan:

```txt
100 packets/sec → easily detected
```

Delayed scan:

```txt
1 packet/sec → harder to detect
```

Example:

```bash
sudo nmap -sS --scan-delay 2s 192.168.1.10
```

Use case:

* Stealth scanning
* Avoid rate-based detection

Tradeoff:

Slower scan speed.

---

## 4. Decoy Scan (-D)

```bash
sudo nmap -D decoy1,decoy2,ME,target
```

Example:

```bash
sudo nmap -D 192.168.1.5,192.168.1.6,ME 192.168.1.10
```

Purpose:

Hides your real IP among decoys.

Target sees:

```txt
192.168.1.5 scanning
192.168.1.6 scanning
Your real IP scanning
```

Harder to identify real scanner.

---

## 5. Bad Checksum (--badsum)

```bash
sudo nmap --badsum 192.168.1.10
```

Purpose:

Sends packets with invalid checksum.

Behavior:

Real host → ignores packet
Firewall → may respond

Use case:

Detect firewall presence.

---

## 6. Packet Padding (--data-length)

```bash
sudo nmap --data-length 50 192.168.1.10
```

Purpose:

Adds random data to packets.

Effect:

Makes packets harder to fingerprint.

Use case:

IDS evasion.

---

## 7. Idle Scan (-sI)

```bash
sudo nmap -sI zombie_ip target_ip
```

Purpose:

Completely anonymous scan.

Uses third-party zombie host.

Target never sees your IP.

Extremely stealthy.

Requirement:

Zombie must have predictable IP ID sequence.

---

## 8. NULL, FIN, and Xmas Scans (TCP Flag Evasion)

These scans manipulate TCP flags to bypass firewalls that primarily filter SYN packets. They rely on RFC-defined behavior where closed ports respond with RST, while open ports ignore unexpected packets.

### 8.1 NULL Scan (-sN)

```bash
sudo nmap -sN target_ip
```

Sends TCP packet with **no flags set**.

Response:

RST → Closed port
No response → Open or filtered port

Purpose:

* Evade simple firewalls
* Identify open ports indirectly

### 8.2 FIN Scan (-sF)

```bash
sudo nmap -sF target_ip
```

Sends packet with **FIN flag only**.

Response:

RST → Closed port
No response → Open or filtered port

Purpose:

* Firewall evasion
* Stealth enumeration

### 8.3 Xmas Scan (-sX)

```bash
sudo nmap -sX target_ip
```

Sends packet with flags:

FIN + PSH + URG

Response:

RST → Closed port
No response → Open or filtered port

Purpose:

* Bypass stateless firewalls
* Detect open ports

### Limitation

Unreliable on Windows systems. Windows often responds with RST for all ports, making results inaccurate.

Works best on Linux, Unix, and BSD systems.

---

## 9. Real-World Stealth Scan Example

```bash
sudo nmap -sS -Pn -p- -sV -O -sC -f --scan-delay 2s -oA stealth_scan target_ip
```

Includes:

* SYN stealth scan
* All ports
* Service detection
* OS detection
* Script scan
* Packet fragmentation
* Slow timing
* Saved output

---

Evasion flags do not magically make you invisible. Modern enterprise IDS (Suricata, Zeek, Palo Alto, CrowdStrike) reconstruct fragments, normalize packets, and detect timing anomalies using statistical models. Fragmentation and delays mainly defeat weak or misconfigured defenses, not mature ones.

The real stealth comes from behavioral camouflage—scanning like a normal system would, blending into expected traffic patterns, and minimizing noise. The best scan is often the quietest, smallest, and most targeted one, not the loud “scan everything with every trick” approach.
