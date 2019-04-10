#!/bin/sh

# 
# 作用，主要用来生成ipsec.conf与ipsec.secrets文件
#

IPTB="/usr/sbin/iptables"
IFCONFIG="/sbin/ifconfig"
IPCALC="/usr/sbin/ipcalc"
RESOLVEIP="/usr/bin/resolveip"
CONFIG="/bin/config"

LAN_IFACE=br0
WAN_IFACE=brwan

ipsec_conf=/etc/ipsec.conf
ipsec_secrets=/etc/ipsec.secrets
strongswan_conf=/etc/strongswan.conf

# basic config
IPSEC_ENABLED=
IPSEC_IKEV=""
IPSEC_LEFT_IP=""
IPSEC_LEFT_SUBNET=""
IPSEC_LEFTID=""
IPSEC_RIGHT_IP=""
IPSEC_RIGHT_SUBNET=""
IPSEC_RIGHTID=""
IPSEC_IPSEC_PSK=""
# phase 1 advance
IPSEC_IKE_PROPOSAL=""
IPSEC_EXCHANGE_MODE=""
IPSEC_NEGOTIATE_MODE=""
IPSEC_IKELIFETIME=""
IPSEC_DPD=""
# phase 2 advance
IPSEC_PROTOCOL=""
IPSEC_ENCAP_MODE=""
IPSEC_PH2_PROPOSAL=""
IPSEC_PFS=""
IPSEC_SALIFETIME=""
IPSEC_HAVE_AGGRESSIVE=""

WAN_PROTO=$($CONFIG get wan_proto)
if [ "$WAN_PROTO" = "dhcp" -o "$WAN_PROTO" = "static" ]; then
	WAN_IFACE="brwan"
else
	WAN_IFACE="ppp0"
fi

#
# domain name resolv whith
# timeout
#
domain_query() {
	[ -n "$1" ] && {
		echo "$($RESOLVEIP -t 5 $1 | head -1)"
	}
}

#
# 网络号 + 掩码转换成网络号/网络前缀
# 192.168.1.0 255.255.255 -- 192.168.1.0/24
#
net_mask_to_subnet() {
	eval "$($IPCALC -n -p $1/$2)"
	echo "$NETWORK/$PREFIX"
}

ifconf_iface_ipaddr() {
	local iface=$1
	$IFCONFIG $iface | grep "inet addr:" | awk -F ":" '{print $2}' | awk -F " " '{print $1}'
}

ifconf_iface_netmask() {
	local iface=$1
	$IFCONFIG $iface | grep "inet addr:" | awk -F ":" '{print $4}'
}

#
# dh_to_modp
#
dh_to_modp() {
	case $1 in
		dh1) echo "modp768" ;;
		dh2) echo "modp1024" ;;
		dh5) echo "modp1536" ;;
		dh14) echo "modp2048" ;;
		dh15) echo "modp3072" ;;
		dh16) echo "modp4096" ;;
		dh17) echo "modp6144" ;;
		dh18) echo "modp8192" ;;
		dh19) echo "ecp256" ;;
		dh20) echo "ecp384" ;;
		dh21) echo "ecp521" ;;
		dh22) echo "modp1024s160" ;;
		dh23) echo "modp2048s224" ;;
		dh24) echo "modp2048s256" ;;
		*) echo "modp1024" ;;
	esac
}

#
# sha1-aes128-dh1 
#
ike_cipher_convert() {
	local cipher hash dh
	
	hash=$(echo "$1" | awk -F "-" '{print $1}')
	cipher=$(echo "$1" | awk -F "-" '{print $2}')
	dh=$(echo "$1" | awk -F "-" '{print $3}')
	
	[ -n "$hash" -a -n "$cipher" -a -n "$dh" ] && {
		echo "$cipher-$hash-$(dh_to_modp $dh)"
	}
}

#
# $1 sha1-aes128/sha1
# $2 protocal : ah / esp
#
ph2_cipher_convert () {
	if [ "$2" = "ah" ]; then
		echo "$1"
	elif  [ "$2" = "esp" ]; then
		echo "$1" | awk -F "-" '{print $2 "-" $1}'
	fi
}

strongswan_print_conf() {
	cat <<EOF > $strongswan_conf
# strongswan.conf - strongSwan configuration file
charon {
	# number of worker threads in charon
	threads = 16
	${IPSEC_HAVE_AGGRESSIVE}
	
	filelog {
		/var/log/ipsec.log {
			time_format = %b %e %T
			default = 1
			append = no
			flush_line = yes
			ike_name = yes
		}
	}
}

pluto {

}

libstrongswan {

}
EOF
}

ipsec_printconf_init() {
	cat <<EOF > $ipsec_conf
# /etc/ipsec.conf - IPsec configuration file

config setup
	uniqueids=yes
	charondebug=""
	
EOF
}

ipsec_printconf_add_conn() {
	cat <<EOF >> $ipsec_conf 
conn conn$1
	type=${IPSEC_ENCAP_MODE}
	${IPSEC_EXCHANGE_MODE}
	authby=secret
	keyexchange=${IPSEC_IKEV}
	
	reauth=yes
	rekey=yes
	rekeymargin=180s
	forceencaps=no
	installpolicy=yes	
	
	## phase 1 ##
	ike=${IPSEC_IKE_PROPOSAL}!
	ikelifetime=${IPSEC_IKELIFETIME}s
	keyingtries=%forever
	
	## phase 2 ##
	esp=${IPSEC_PH2_PROPOSAL}!
	keylife=${IPSEC_SALIFETIME}s
	
	left=${IPSEC_LEFT_IP}
	leftsubnet=${IPSEC_LEFT_SUBNET}
	leftid=${IPSEC_LEFTID}
	
	right=${IPSEC_RIGHT_IP}
	rightsubnet=${IPSEC_RIGHT_SUBNET}
	rightid=${IPSEC_RIGHTID}
	
	${IPSEC_DPD}
	
	auto=${IPSEC_NEGOTIATE_MODE}
	
EOF
}

ipsec_printsecrets_init() {
	cat <<EOF > $ipsec_secrets 
# /etc/ipsec.secrets - IPsec sensitive configuration file
EOF
}

ipsec_printsecrets_add_psk() {
	cat <<EOF >> $ipsec_secrets 
%any  %any  : PSK "$IPSEC_IPSEC_PSK"
EOF
}

ipsec_config_get_policy()
{
	local pfs
	local net mask
	local dpd_enable dpd_delay dpd_timeout
	local ike_proposal1 ike_proposal2 ike_proposal3 ike_proposal4
	local ph2_proposal1 ph2_proposal2 ph2_proposal3 ph2_proposal4
	
	IPSEC_ENABLED=$($CONFIG get ct_ipsec_enabled$1)
	
	# default ikev2
	IPSEC_IKEV=$($CONFIG get ct_ipsec_ikev$1)
	IPSEC_IKEV=${IPSEC_IKEV:=ikev2}
	
	IPSEC_LEFT_IP=$(ifconf_iface_ipaddr $WAN_IFACE)
	net=$($CONFIG get ct_ipsec_leftsubnet$1)
	mask=$($CONFIG get ct_ipsec_leftnetmask$1)
	IPSEC_LEFT_SUBNET=$(net_mask_to_subnet $net $mask)
	IPSEC_LEFTID=$IPSEC_LEFT_IP
	
	IPSEC_RIGHT_IP=$($CONFIG get ct_ipsec_right$1)
	net=$($CONFIG get ct_ipsec_rightsubnet$1)
	mask=$($CONFIG get ct_ipsec_rightnetmask$1)
	IPSEC_RIGHT_SUBNET=$(net_mask_to_subnet $net $mask)
	IPSEC_RIGHTID=$(domain_query $IPSEC_RIGHT_IP)
	
	IPSEC_IPSEC_PSK=$($CONFIG get ct_ipsec_psk$1)
	
	ike_proposal1=$($CONFIG get ct_ipsec_ike_proposal1$1)
	ike_proposal2=$($CONFIG get ct_ipsec_ike_proposal2$1)
	ike_proposal3=$($CONFIG get ct_ipsec_ike_proposal3$1)
	ike_proposal4=$($CONFIG get ct_ipsec_ike_proposal4$1)
	
	[ -n "$ike_proposal1" ] && {
		IPSEC_IKE_PROPOSAL="$(ike_cipher_convert $ike_proposal1)"
	}

	[ -n "$ike_proposal2" ] && {
		IPSEC_IKE_PROPOSAL="$IPSEC_IKE_PROPOSAL,$(ike_cipher_convert $ike_proposal2)"
	}

	[ -n "$ike_proposal3" ] && {
		IPSEC_IKE_PROPOSAL="$IPSEC_IKE_PROPOSAL,$(ike_cipher_convert $ike_proposal3)"
	}

	[ -n "$ike_proposal4" ] && {
		IPSEC_IKE_PROPOSAL="$IPSEC_IKE_PROPOSAL,$(ike_cipher_convert $ike_proposal4)"
	}
	IPSEC_IKE_PROPOSAL=${IPSEC_IKE_PROPOSAL:=aes128-sha1-modp1024}
	
	IPSEC_EXCHANGE_MODE=$($CONFIG get ct_ipsec_exchange_mode$1)
	if [ "$IPSEC_EXCHANGE_MODE" = "aggressive" ]; then
		IPSEC_EXCHANGE_MODE="aggressive=yes"
		if [ -z "$IPSEC_HAVE_AGGRESSIVE" ]; then
			IPSEC_HAVE_AGGRESSIVE="i_dont_care_about_security_and_use_aggressive_mode_psk = yes"
		fi
	else
		IPSEC_EXCHANGE_MODE="aggressive=no"
	fi
	
	IPSEC_NEGOTIATE_MODE=$($CONFIG get ct_ipsec_negotiate_mode$1)
	if [ "$IPSEC_NEGOTIATE_MODE" = "responder" ]; then
		IPSEC_NEGOTIATE_MODE="add"
	else
		IPSEC_NEGOTIATE_MODE="start"
	fi
	
	IPSEC_IKELIFETIME=$($CONFIG get ct_ipsec_ikelifetime$1)
	IPSEC_IKELIFETIME=${IPSEC_IKELIFETIME:=28800}
	
	dpd_enable=$($CONFIG get ct_ipsec_dpd_enable$1)
	dpd_enable=${dpd_enable:=1}
	dpd_delay=$($CONFIG get ct_ipsec_dpd_interval$1)
	dpd_delay=${dpd_delay:=10}
	
	dpd_timeout=$((dpd_delay*6))
	
	if [ "$dpd_enable" = "1" ]; then
		IPSEC_DPD=$(echo -e "dpdaction=restart\n\tdpdtimeout=${dpd_timeout}\n\tdpddelay=${dpd_delay}\n")
	else
		IPSEC_DPD=""
	fi
	
	IPSEC_PROTOCOL=$($CONFIG get ct_ipsec_protocol$1)
	IPSEC_PROTOCOL=${IPSEC_PROTOCOL:=esp}
	
	IPSEC_ENCAP_MODE=$($CONFIG get ct_ipsec_encap_mode$1)
	IPSEC_ENCAP_MODE=${IPSEC_ENCAP_MODE:=tunnel}
	
	ph2_proposal1=$($CONFIG get ct_ipsec_ph2_proposal1$1)
	ph2_proposal2=$($CONFIG get ct_ipsec_ph2_proposal2$1)
	ph2_proposal3=$($CONFIG get ct_ipsec_ph2_proposal3$1)
	ph2_proposal4=$($CONFIG get ct_ipsec_ph2_proposal4$1)
	
	IPSEC_PFS=$($CONFIG get ct_ipsec_pfs$1)
	IPSEC_PFS=${IPSEC_PFS:=no}
	
	if [ "$IPSEC_PFS" = "no" ]; then
		pfs=""
	else
		pfs="-$(dh_to_modp $IPSEC_PFS)"
		IPSEC_PFS="yes"
	fi
	
	[ -n "$ph2_proposal1" ] && {
		IPSEC_PH2_PROPOSAL="$(ph2_cipher_convert $ph2_proposal1 $IPSEC_PROTOCOL)${pfs}"
	}
	
	[ -n "$ph2_proposal2" ] && {
		IPSEC_PH2_PROPOSAL="$IPSEC_PH2_PROPOSAL,$(ph2_cipher_convert $ph2_proposal2 $IPSEC_PROTOCOL)${pfs}"
	}
	
	[ -n "$ph2_proposal3" ] && {
		IPSEC_PH2_PROPOSAL="$IPSEC_PH2_PROPOSAL,$(ph2_cipher_convert $ph2_proposal3 $IPSEC_PROTOCOL)${pfs}"
	}

	[ -n "$ph2_proposal4" ] && {
		IPSEC_PH2_PROPOSAL="$IPSEC_PH2_PROPOSAL,$(ph2_cipher_convert $ph2_proposal4 $IPSEC_PROTOCOL)${pfs}"
	}
	
	IPSEC_PH2_PROPOSAL=${IPSEC_PH2_PROPOSAL:=aes128-sha1}
	IPSEC_PH2_PROPOSAL="${IPSEC_PH2_PROPOSAL}"
	
	IPSEC_SALIFETIME=$($CONFIG get ct_ipsec_salifetime$1)
	IPSEC_SALIFETIME=${IPSEC_SALIFETIME:=3600}
}

ipsec_load_conf() {
	local index=0
	local ipsec_num

	ipsec_printconf_init
	ipsec_printsecrets_init

	ipsec_num=$($CONFIG get ipsec_num)
	ipsec_num=${ipsec_num:=0}
	
	while [ $index -lt $ipsec_num ]; do
		ipsec_config_get_policy $index
		[ "$IPSEC_ENABLED" = "1" ] && {
			ipsec_printconf_add_conn $index
			ipsec_printsecrets_add_psk
		}
		index=$((index + 1))
	done
	
	# 生成strongswan配置文件
	strongswan_print_conf
}

ipsec_reload_conf() {
	local _IPSEC=$(which ipsec)

	ipsec_load_conf
	$_IPSEC reload
}

ipsec_fw_stop() {

	# clear ipsec out chain,
	$IPTB -t nat -F ipsec_out 2>/dev/null
	$IPTB -t nat -D POSTROUTING -j ipsec_out 2>/dev/null
	$IPTB -t nat -X ipsec_out 2>/dev/null
	
	# clear spiDos n2n chain
	$IPTB -t mangle -F ipsec_n2n 2>/dev/null
	$IPTB -t mangle -D PREROUTING -j ipsec_n2n 2>/dev/null
	$IPTB -t mangle -X ipsec_n2n 2>/dev/null

	# clear ipsec to local chain.
	$IPTB -t filter -F ipsec_in 2>/dev/null
	$IPTB -t filter -D ${WAN_IFACE}_in -j ipsec_in 2>/dev/null
	$IPTB -t filter -X ipsec_in 2>/dev/null

	$IPTB -t filter -F ipsec_fwd 2>/dev/null
	$IPTB -t filter -D ${WAN_IFACE}_fwd -j ipsec_fwd 2>/dev/null
	$IPTB -t filter -X ipsec_fwd 2>/dev/null
	
	# clear wan ipsec rules
	$IPTB -D ${WAN_IFACE}_in -p esp -j ACCEPT
	$IPTB -D ${WAN_IFACE}_in -p udp --dport 500 -j ACCEPT
	$IPTB -D ${WAN_IFACE}_in -p udp --dport 4500 -j ACCEPT
}

ipsec_fw_start() {
	local index=0

	# ipsec out chain,
	$IPTB -t nat -N ipsec_out
	$IPTB -t nat -I POSTROUTING -j ipsec_out

	# avoid spiDos Drop ipsec site-to-site packet
	$IPTB -t mangle -N ipsec_n2n
	$IPTB -t mangle -I PREROUTING -j ipsec_n2n

	$IPTB -t filter -N ipsec_in
	$IPTB -t filter -N ipsec_fwd
	
	$IPTB -I ${WAN_IFACE}_in -j ipsec_in
	$IPTB -I ${WAN_IFACE}_fwd -j ipsec_fwd
	
	# ipsec isakmp and esp
	$IPTB -I ${WAN_IFACE}_in -p esp -j ACCEPT
	$IPTB -I ${WAN_IFACE}_in -p udp --dport 500 -j ACCEPT
	$IPTB -I ${WAN_IFACE}_in -p udp --dport 4500 -j ACCEPT
	
	ipsec_num=$($CONFIG get ipsec_num)
	ipsec_num=${ipsec_num:=0}
	
	while [ $index -lt $ipsec_num ]; do
		ipsec_config_get_policy $index
		[ "$IPSEC_ENABLED" = "1" ] && {
			# ipsec to local
			$IPTB -A ipsec_in -s ${IPSEC_RIGHT_SUBNET} -j ACCEPT
			$IPTB -A ipsec_fwd -s ${IPSEC_RIGHT_SUBNET} -j ACCEPT
			# ipsec to local resp
			$IPTB -t nat -A ipsec_out -s ${IPSEC_LEFT_SUBNET} -m policy --dir out --pol ipsec -j ACCEPT
			$IPTB -t mangle -A ipsec_n2n -s ${IPSEC_RIGHT_SUBNET} -d ${IPSEC_LEFT_SUBNET} -j ACCEPT
		}
		index=$((index + 1))
	done
}

ipsec_fw_status() {
	echo "to be done."
}

ipsec_fw_restart() {
	local ipsec_num
	
	ipsec_fw_stop

	ipsec_num=$($CONFIG get ipsec_num)
	ipsec_num=${ipsec_num:=0}
	
	[ $ipsec_num -gt 0 ] && { 
		ipsec_fw_start
	}
}

case $1 in
	"start")
		ipsec_load_conf
		;;
	"stop")
		;;
	"reload")
		ipsec_reload_conf
		;;
	"fw_restart")
		ipsec_fw_restart
		;;
	"fw_start")
		ipsec_fw_start
		;;
	"fw_stop")
		ipsec_fw_stop
		;;
	"fw_status")
		ipsec_fw_status
		;;
	*)
		echo "unknow argument!"
		;;
esac

exit 0
