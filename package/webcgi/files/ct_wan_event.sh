#!/bin/sh

ACTION=$1

[ "$ACTION" = "up" ] || exit 0

# ipsec restart
/etc/init.d/ipsec restart
