# CIDR

CIDR splits the 32-bit IP address into **network bits (N)** and **host bits(H)**: network bits cannot change, while host bits can change within the subnet.

CIDR format = IPv4 Address/N

## Calculate the Starting IP Address, Broadcast and Usable Hosts

Given an IP address and a Subnet mask, find the starting IP address (network address), Broadcast IP address, and useable hosts.

* IP address = 192.168.218.226
* Subnet Mask = 255.255.248.0

**Convert to binary and perform AND operation:**

```txt
255.255.248.0    --> 11111111.11111111.11111000.00000000
192.168.218.226  --> 11000000.10101000.11011010.11100010
                    --------------------------------------
AND Operation    --> 11000000.10101000.11011000.00000000  --> 192.168.216.0


Number of 1's in Subnet mask (N) = 21
Number of 0's in Subnet mask (H) = 11

CIDR Notation = 192.168.216.0/N => 192.168.216.0/21

Usable hosts = (2^H) - 2
             => (2^11) - 2
             => 2048 - 2
             => 2046

Broadcast address => Turn all host bits (H ie. 11) bits of our address to 1.
                  => 11000000.10101000.11011111.11111111
                  => 192.168.223.255
```

>**Note:** Usable hosts = total addresses − 2 for IPv4 subnets /0–/30 (network + broadcast), but /31 has 2 usable addresses and /32 has 1 usable address.
