#!/bin/sh

ifconfig eth0 $1 netmask 255.255.255.0
