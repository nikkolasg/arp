#!/usr/bin/sh

## Activate ip forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

./sniff wlp3s0 

echo 0 > /proc/sys/net/ipv4/ip_forward

