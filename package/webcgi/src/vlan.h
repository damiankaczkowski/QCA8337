
#ifndef __VLAN_H_
#define __VLAN_H_

#include <stdint.h>

#include "switch.h"

#define MIN_VLAN_ID 1
#define MAX_VLAN_ID 4094

#define MAX_VLAN_ENTRY 128

#define VLAN_UNTAGGED 0
#define VLAN_TAGGED 1

typedef uint16_t ct_vlan_t;
typedef uint16_t ct_pbmp_t;

struct sw_vlan_cfg {
    int vlan_entry;
    ct_vlan_t pvid[MAX_PHY_PORT];
    ct_vlan_t vlan_id[MAX_VLAN_ENTRY];
    ct_pbmp_t pbmp_vlan[MAX_VLAN_ENTRY];
    ct_pbmp_t tbmp_vlan[MAX_VLAN_ENTRY];
};

struct port_attr {
    int port;
    int pvid;
    int vlans;
};

struct vlan_attr {
    char name[33];
    int vid;
    int prio;
    char ports[33];
    char phyports[33];
    char desc[33];
};

int vlan_main(char *cmd, char *param);

#endif
