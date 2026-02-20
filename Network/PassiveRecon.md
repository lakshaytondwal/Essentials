# Passive Reconnaissance

## 1. **p0f - Passive OS Fingerprinting**

p0f identifies operating systems, network distance (hop count), and connection characteristics by passively analyzing TCP/IP packet signatures, without sending probes. Its effectiveness is reduced by NAT, load balancers, proxies, VPNs, and modern TCP stack normalization, and it performs best on direct, unaltered network traffic.

**Where p0f works well:**

* Local LAN traffic
* SPAN / mirror ports
* Network taps
* Gateway interfaces before NAT or normalization
* IDS/IPS monitoring points

```bash
p0f -i eth0
```

Listens passively on interface `eth0` and fingerprints operating systems and connection metadata from observed TCP traffic.

> **Note:** p0f only produces results when it receives live network traffic on the monitored interface; no traffic means no fingerprints.

---
