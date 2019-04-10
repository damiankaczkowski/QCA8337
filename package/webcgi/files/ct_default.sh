#!/bin/sh

CONFIG=/bin/config

load_nmap_scan_default()
{
	$CONFIG set nmap_enable=1
	$CONFIG set manual=0
	$CONFIG set scan_rate=10
	$CONFIG set retry_count=0
	$CONFIG set scan_depth=0
	$CONFIG set process_num=0
	$CONFIG set scan_timeout=30
	$CONFIG set port_pool="21,22,23,25,465,110,143,993,445,139,80,8080,1080,9090,9080,443,8443,9001,3389,5901,1443,1521,3306"
	lan_ipaddr="$($CONFIG get lan_ipaddr)"
	$CONFIG set ip_pool="${lan_ipaddr}-254"
}

load_system_default()
{
	# web mngt
	$CONFIG set http_port=80
	$CONFIG set https_port=443
	$CONFIG set redirect_https=1
	$CONFIG set idle_time=5
	
	# 系统默认时间，月日时分年
	echo "None"
}

reload_vlan_default()
{
	local vlan_num
	
	vlan_num=$($CONFIG get ct_vlan_num)
	[ $vlan_num -lt 1 ] && return
	
	index=0
	while [ $index -lt $vlan_num ]; do
		
		eval "$CONFIG unset ct_vlan_name_x$index"
		eval "$CONFIG unset ct_vlan_vid_x$index"
		eval "$CONFIG unset ct_vlan_prio_x$index"
		eval "$CONFIG unset ct_vlan_ports_x$index"
		eval "$CONFIG unset ct_vlan_phyports_x$index"
		eval "$CONFIG unset ct_vlan_desc_x$index"
		
		index=$(expr $index + 1)
	done
}

load_vlan_default()
{
	$CONFIG set ct_vlan_en=1	
	$CONFIG set ct_vlan_num=2

	# VLAN1
	$CONFIG set ct_vlan_name_x0="vlan1"
	$CONFIG set ct_vlan_vid_x0="1"
	$CONFIG set ct_vlan_prio_x0="0"
	$CONFIG set ct_vlan_ports_x0="1 2 3 4"
	$CONFIG set ct_vlan_phyports_x0="6t 1 2 3 4"
	$CONFIG set ct_vlan_desc_x0="vlan for lan"

	# VLAN2
	$CONFIG set ct_vlan_name_x1="vlan2"
	$CONFIG set ct_vlan_vid_x1="2"
	$CONFIG set ct_vlan_prio_x1="0"
	$CONFIG set ct_vlan_ports_x1="5"
	$CONFIG set ct_vlan_phyports_x1="0t 5"
	$CONFIG set ct_vlan_desc_x1="vlan for wan"

	# PVID
	$CONFIG set ct_port_pvid_x1="1"
	$CONFIG set ct_port_pvid_x2="1"
	$CONFIG set ct_port_pvid_x3="1"
	$CONFIG set ct_port_pvid_x4="1"
	$CONFIG set ct_port_pvid_x5="2"
}

load_network_default()
{
	$CONFIG set lan_num=1
	$CONFIG set wan_num=1
	
	$CONFIG set lan_name="LAN1"
	$CONFIG set lan_vid="1"
	$CONFIG set lan_desc="Default Manage Lan"
	
	$CONFIG set wan_name="WAN1"
	$CONFIG set wan_vid="2"
}

reload_ct_default()
{
	# flag
	$CONFIG unset load_ct_default
	
	# vlan
	reload_vlan_default
	
	# ct_default
	load_ct_default
}

load_ct_default()
{
	[ "ct$($CONFIG get load_ct_default)" = "ct" ] && {	
		# system
		load_system_default
	
		# vlan
		load_vlan_default
		
		# network
		load_network_default

		# firewall

		#nmap_scan
		load_nmap_scan_default
		
		# commit 
		$CONFIG set load_ct_default="1"
		$CONFIG commit
	}
	
	echo "Done."
}

case $1 in
	"reload")
		reload_ct_default
		;;
	*)
		load_ct_default
		;;
esac
