#!/bin/sh

. /lib/cfgmgr/cfgmgr.sh
. /lib/cfgmgr/enet.sh

switch_config()
{
    # 为了避免与dni配置冲突，
    # 这里custom vlan只有在normal模式才会生效
    [ "$($CONFIG get i_opmode)" != "normal" ] && return

    sw_configvlan normal
}

firewall_config()
{
    # 注意此脚本仅对自定义的防火墙规则有效，
    # 默认防火墙规则在net-wall中初始化
    /etc/scripts/firewall/005-ct_fw.rule reload
}

network_config()
{
    # 仅初始化新加的子网以及一些基本的防火墙规则
    /usr/sbin/ct_ntwk.sh reload
    net-wall restart
}

restart_all()
{
    echo "None."
}

case $1 in
    "switch_config") switch_config ;;
    "network_config") network_config ;;
    "firewall_config") firewall_config ;;
    *) restart_all ;;
esac