
#ifndef __FIREWALL_H_
#define __FIREWALL_H_

#define MAX_FW_RULE_NUM 128
#define MAX_BLK_SVC_NUM 100

enum {
    CFG_FW_RULE = 1,
    CFG_BLK_SVC
};

enum {
    FW_IPV4 = 0,
    FW_IPV6,
    FW_DUAL,
};

struct fw_rule {
    char name[33];
    char src[20];
    char src_ip[16];
    char src_ip_range[32];
    char src_mac[18];
    char src_port[65];
    char dest[20];
    char dest_ip[16];
    char dest_ip_range[32];
    char dest_port[65];
    char proto[10];
    int action;
    int family;
    char extra[128];
};

struct blk_svc {
    char name[20];
    char proto[10];
    int start_port;
    int end_port;
    char svc_type[33];
    int addr_type;
    char addr[32];
};

int firewall_main(char *cmd, char *data);

#endif
