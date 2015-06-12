#!/bin/sh

ifconfig eth0 $1 netmask 255.255.255.0
ip route add default via 10.0.0.10
echo "nameserver 208.67.222.222" > /etc/resolv.conf
echo "nameserver 208.67.220.220" > /etc/resolv.conf



