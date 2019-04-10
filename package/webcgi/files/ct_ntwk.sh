#!/bin/sh

CONFIG=/bin/config

get_pid_by_name()
{
	ps -w | grep "$1" | grep -v grep | awk '{print $1}'
}

print_lanx_dhcpd_conf()
{
	local n=0
	local num=0
	local idx=$1
	local leases_file=/tmp/udhcpd${idx}.leases
	local host_file=/tmp/udhcpd${idx}.hostlist
	local ip mac name

	[ ! -f $leases_file ] && touch $leases_file

	cat <<EOF
pidfile /var/run/udhcpd${idx}.pid
start $($CONFIG get ct_lan_dhcp_start_x$idx)
end $($CONFIG get ct_lan_dhcp_end_x$idx)
interface br$idx
remaining yes
auto_time 5
lease_file $leases_file
host_file $host_file
option subnet $($CONFIG get ct_lan_netmask_x$idx)
option router $($CONFIG get ct_lan_ipaddr_x$idx)
option dns $($CONFIG get ct_lan_ipaddr_x$idx)
option lease 86400
EOF

	num="$($CONFIG get ct_dhcpd${idx}_reserv_num)"
	num=${num:=0}
	while [ $n -lt $num ]; do
		ip="$($CONFIG get ct_dhcpd${idx}_reserv_ip_x$n)"
		mac="$($CONFIG get ct_dhcpd${idx}_reserv_mac_x$n)"
		name="$($CONFIG get ct_dhcpd${idx}_reserv_name_x$n)"
		[ -n "$ip" -a -n "$mac" ] && {
			echo "static_lease $ip $mac $name"
		}
		n=$(($n + 1))
	done
}

start_lanx_dhcpd()
{
	local idx=$1
	[ "$($CONFIG get ct_lan_dhcp_x$idx)" = "0" ] && return
	print_lanx_dhcpd_conf $idx > /tmp/udhcpd${idx}.conf
	udhcpd /tmp/udhcpd${idx}.conf
}

killall_lanx_udhcpd()
{
	local tmpfile
	ls /tmp/udhcpd*.conf | while read file
	do
		tmpfile=$(basename $file)
		[ "$tmpfile" != "udhcpd.conf" ] && {
			pid=$(get_pid_by_name $tmpfile)
			[ "$pid" != "" ] && {
				kill $pid
			}
		}
	done
}

start_lanx()
{
	local lan_num
	local lan_ip lan_mask
	local lan_if
	local index=1

	killall_lanx_udhcpd
	
	lan_num=$($CONFIG get lan_num)
	lan_num=${lan_num:=1}
	
	while [ $index -lt $lan_num ]; do
		lan_if="br$index"
		lan_ip=$($CONFIG get ct_lan_ipaddr_x$index)
		lan_mask=$($CONFIG get ct_lan_netmask_x$index)
		
		echo "$index"
		echo "$lan_ip"
		echo "$lan_mask"
		
		if [ -n "$lan_ip" -a -n "$lan_mask" ]; then
			ifconfig $lan_if up
			ifconfig $lan_if $lan_ip netmask $lan_mask
			start_lanx_dhcpd $index
		fi
		index=$((index + 1))
	done
	
	/etc/init.d/lan-scan restart
}

br_create() # $1: brname
{
	brctl addbr $1
	brctl setfd $1 0
	brctl stp $1 0
	echo 0 > /sys/devices/virtual/net/$1/bridge/multicast_snooping
}

lanx_allbrs()
{
	awk '/br[0-9]/ {print $1}' /proc/net/dev |sed 's/://g'
}

br_allnifs() # $1: brx
{
	brctl show $1 | awk '!/bridge/ {print $NF}' | grep "eth\|ath\|host0."
}

create_all_lanx_brs_vifs()
{
	local index=1
	local lan_num
	local vid mac

	lan_num=$($CONFIG get lan_num)
	lan_num=${lan_num:=1}

	while [ $index -lt $lan_num ]; do
		vid=$($CONFIG get ct_lan_vid_x$index)
		mac=$($CONFIG get ct_lan_macaddr_x$index)
		br_create br$index
		vconfig add ethlan $vid
		ifconfig ethlan.$vid up
		brctl addif br$index ethlan.$vid
		ifconfig br$index hw ether $mac
		index=$((index + 1))
	done
}

del_all_lanx_brs_vifs()
{
	local brx nif

	for brx in $(lanx_allbrs); do
		[ "$brx" != "br0" ] && {
			ifconfig $brx down
			for nif in $(br_allnifs $brx); do 
				ifconfig $nif down
				brctl delif $brx $nif
				case "$nif" in
				ethlan|ethwan)
					;;
				eth*)
					vconfig rem $nif
					;;
				esac
			done
			[ "$brx" != br0 -a $brx != "brwan" ] && brctl delbr $brx
		}
	done
}

switch_port_down_up()
{
	# PHY link will be pulled low some seconds to force transition to reboot state 
	# and generating DHCP request and Discovery protocol and address refresh in the 
	# devices connected to the NETGEAR Local Area Network ports.
	#
	# After echo 9 into /proc/switch_phy, LAN physical signal will bring down 9 seconds,
	# should wait for LAN physical signal bring up, and then execute subsequence actions
	# as below.
	echo -n 9 > /proc/switch_phy && sleep 10
}

case $1 in
	"reload")
		del_all_lanx_brs_vifs
		create_all_lanx_brs_vifs
		start_lanx
		switch_port_down_up
		;;
       *)
		echo "do nothing." 
		;;
esac