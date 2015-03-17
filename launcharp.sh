#!/usr/bin/sh

## Activate ip forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
##De activate redirection 
echo 0 > /proc/sys/net/ipv4/conf/*/secure_redirects
echo 0 > /proc/sys/net/ipv4/conf/*/send_redirects

./sniff wlp3s0 

echo 0 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv4/conf/*/secure_redirects
echo 1 > /proc/sys/net/ipv4/conf/*/send_redirects
