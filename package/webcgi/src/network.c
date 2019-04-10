
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "switch.h"
#include "network.h"
#include "adapter.h"

int g_lan_idx = 0;

int parse_lan_reserv_dhcpd(dhcpd_res_t *cfg, char *reserv)
{
    int ret = 0;
    
    cfg->lan_idx = 1;
    ret = sscanf(reserv, "%s %s %s", cfg->ip, cfg->mac, cfg->name);
    if(ret > 0)
    {
        return 0;
    }

    return -1;
}

int get_lan_dhcp_reserv_num(int *reserv_num)
{
    int i = 0;
    char *tmp = NULL;

    while(1)
    {   
        tmp = config_get_ext("reservation", i + 1);
        if(tmp[0] == '\0')
        {
            break;
        }
        i ++;
    }

    *reserv_num = i;

    return 0;
}

void dhcpd_reserv_config_get(int idx, dhcpd_res_t *cfg)
{
    char tmp[128] = {0};

    if(cfg->lan_idx == 1)
    {
        strncpy(tmp, config_get_ext("reservation", idx + 1), sizeof(tmp) - 1);
        parse_lan_reserv_dhcpd(cfg, tmp);
    }
    else
    {
        /* ip */
        snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_ip_x", cfg->lan_idx - 1);
        strncpy(cfg->ip, config_get_ext(tmp, idx), sizeof(cfg->ip) - 1);
        /* mac */
        snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_mac_x", cfg->lan_idx - 1);
        strncpy(cfg->mac, config_get_ext(tmp, idx), sizeof(cfg->mac) - 1);
        /* name */
        snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_name_x", cfg->lan_idx - 1);
        strncpy(cfg->name, config_get_ext(tmp, idx), sizeof(cfg->name) - 1);
    }
}

void dhcpd_reserv_config_set(int idx, dhcpd_res_t *cfg)
{
    char tmp[128] = {0};

    if(cfg->lan_idx == 1)
    {
        snprintf(tmp, sizeof(tmp), "%s %s %s", cfg->ip, cfg->mac, cfg->name);
        config_set_ext("reservation", idx + 1, tmp);
    }
    else
    {
        /* ip */
        snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_ip_x", cfg->lan_idx - 1);
        config_set_ext(tmp, idx, cfg->ip);
        /* mac */
        snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_mac_x", cfg->lan_idx - 1);
        config_set_ext(tmp, idx, cfg->mac);
        /* name */
        snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_name_x", cfg->lan_idx - 1);
        config_set_ext(tmp, idx, cfg->name);
    }
}

void dhcpd_reserv_config_delete(int idx, int lan_idx)
{
    char tmp[32] = {0};

    if(lan_idx == 1)
    {
        config_unset_ext("reservation", idx + 1);
    }
    else
    {
        /* ip */
        snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_ip_x", lan_idx - 1);
        config_unset_ext(tmp, idx);
        /* mac */
        snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_mac_x", lan_idx - 1);
        config_unset_ext(tmp, idx);
        /* name */
        snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_name_x", lan_idx - 1);
        config_unset_ext(tmp, idx);
    }
}

void lan_subnet_config_get(int idx, lan_cfg_t *lan)
{
    if(idx == 0)
    {
        strncpy(lan->name, config_get("lan_name"), sizeof(lan->name) - 1);
        strncpy(lan->ipaddr, config_get("lan_ipaddr"), sizeof(lan->ipaddr) - 1);
        strncpy(lan->netmask, config_get("lan_netmask"), sizeof(lan->netmask) - 1);
        lan->dhcpd_enable = config_get_int("lan_dhcp");
        strncpy(lan->dhcpd_start, config_get("dhcp_start"), sizeof(lan->dhcpd_start) - 1);
        strncpy(lan->dhcpd_end, config_get("dhcp_end"), sizeof(lan->dhcpd_end) - 1);
        strncpy(lan->macaddr, config_get("lan_factory_mac"), sizeof(lan->macaddr) - 1);
        lan->vlanid = config_get_int("lan_vid");
        strncpy(lan->desc, config_get("lan_desc"), sizeof(lan->desc) - 1);
        lan->rip_version = config_get_int("rip_version");
        lan->rip_direction = config_get_int("rip_direction");
        if(lan->rip_version == 0)
        {
            lan->ripd_enable = 0;
        }
        else
        {
            lan->ripd_enable = 1;
        }
    }
    else
    {
        strncpy(lan->name, config_get_ext("ct_lan_name_x", idx), sizeof(lan->name) - 1);
        strncpy(lan->ipaddr, config_get_ext("ct_lan_ipaddr_x", idx), sizeof(lan->ipaddr) - 1);
        strncpy(lan->netmask, config_get_ext("ct_lan_netmask_x", idx), sizeof(lan->netmask) - 1);
        lan->dhcpd_enable = config_get_int_ext("ct_lan_dhcp_x", idx);
        strncpy(lan->dhcpd_start, config_get_ext("ct_lan_dhcp_start_x", idx), sizeof(lan->dhcpd_start) - 1);
        strncpy(lan->dhcpd_end, config_get_ext("ct_lan_dhcp_end_x", idx), sizeof(lan->dhcpd_end) - 1);
        strncpy(lan->macaddr, config_get_ext("ct_lan_macaddr_x", idx), sizeof(lan->macaddr) - 1);
        lan->vlanid = config_get_int_ext("ct_lan_vid_x", idx);
        strncpy(lan->desc, config_get_ext("ct_lan_desc_x", idx), sizeof(lan->desc) - 1);
        lan->ripd_enable = 0;
        lan->rip_version = 0;
        lan->rip_direction = 0;
    }
}

void lan_subnet_config_set(int idx, lan_cfg_t *lan)
{
    if(idx == 0)
    {
        config_set("lan_ipaddr", lan->ipaddr);
        config_set("lan_netmask", lan->netmask);
        config_set_int("lan_dhcp", lan->dhcpd_enable);
        config_set("dhcp_start", lan->dhcpd_start);
        config_set("dhcp_end", lan->dhcpd_end);
        if (lan->ripd_enable == 0)
        {
            config_set_int("rip_version", 0);
            config_set_int("rip_direction", 0);
        }
        else
        {
            config_set_int("rip_version", lan->rip_version);
            config_set_int("rip_direction", lan->rip_direction);
        }
    }
    else
    {   
        config_set_ext("ct_lan_name_x", idx, lan->name);
        config_set_ext("ct_lan_ipaddr_x", idx, lan->ipaddr);
        config_set_ext("ct_lan_netmask_x", idx, lan->netmask);
        config_set_int_ext("ct_lan_dhcp_x", idx, lan->dhcpd_enable);
        config_set_ext("ct_lan_dhcp_start_x", idx, lan->dhcpd_start);
        config_set_ext("ct_lan_dhcp_end_x", idx, lan->dhcpd_end);
        config_set_ext("ct_lan_macaddr_x", idx, lan->macaddr);
        config_set_int_ext("ct_lan_vid_x", idx, lan->vlanid);
        config_set_ext("ct_lan_desc_x", idx, lan->desc);
    }
}

void lan_subnet_config_del(int idx)
{
    int i = 0;
    char tmp[32] = {0};
    int dhcpd_reserv_num = 0;
    
    config_unset_ext("ct_lan_name_x", idx);
    config_unset_ext("ct_lan_ipaddr_x", idx);
    config_unset_ext("ct_lan_netmask_x", idx);
    config_unset_ext("ct_lan_dhcp_x", idx);
    config_unset_ext("ct_lan_dhcp_start_x", idx);
    config_unset_ext("ct_lan_dhcp_end_x", idx);
    config_unset_ext("ct_lan_macaddr_x", idx);
    config_unset_ext("ct_lan_vid_x", idx);
    config_unset_ext("ct_lan_desc_x", idx);

    if(idx != 0)
    {
        snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_num", idx);
        dhcpd_reserv_num = config_get_int(tmp);

        for(i = 0; i < dhcpd_reserv_num; i ++)
        {
            dhcpd_reserv_config_delete(i, idx);
        }
    }
}

int lan_subnet_config_align(int orig_num)
{
    int i = 0;
    int j = 0;
    int r_idx = 0;
    lan_cfg_t lan;

    for(i = 1; i < orig_num; i ++)
    {
        memset(&lan, 0x0, sizeof(lan_cfg_t));

        lan_subnet_config_get(i, &lan);

        if(lan.name[0] == '\0')
        {
            j ++;
        }
        else
        {
            r_idx = i - j;

            if(j > 0)
            {
                lan_subnet_config_set(r_idx, &lan);
                lan_subnet_config_del(i);
           }
        }
    }

    return 0;
}

int parse_lan_param(cJSON *item, struct lan_cfg *lan)
{
    int ret = 0;
    int intVal = 0;
    char *strVal = NULL;

    if(!item || item->type != cJSON_Object)
    {
        return -1;
    }

    strVal = cjson_get_string(item, "name");
    if(!strVal)
    {
        return -1;
    }
    strncpy(lan->name, strVal, sizeof(lan->name) - 1);

    strVal = cjson_get_string(item, "ipaddr");
    if(!strVal)
    {
        return -1;
    }
    strncpy(lan->ipaddr, strVal, sizeof(lan->ipaddr) - 1);

    strVal = cjson_get_string(item, "netmask");
    if(!strVal)
    {
        return -1;
    }  
    strncpy(lan->netmask, strVal, sizeof(lan->netmask) - 1);

    ret = cjson_get_int(item, "dhcp_enable", &intVal);
    if(ret < 0)
    {
        return -1;
    }
    lan->dhcpd_enable = intVal;

    strVal = cjson_get_string(item, "dhcp_start");
    if(!strVal)
    {
        return -1;
    }
    strncpy(lan->dhcpd_start, strVal, sizeof(lan->dhcpd_start) - 1); 

    strVal = cjson_get_string(item, "dhcp_end");
    if(!strVal)
    {
        return -1;
    }
    strncpy(lan->dhcpd_end, strVal, sizeof(lan->dhcpd_end) - 1); 

    ret = cjson_get_int(item, "ripd_enable", &intVal);
    if(ret == 0)
    {
        lan->ripd_enable = intVal;
    }
    
    ret = cjson_get_int(item, "rip_direction", &intVal);
    if(ret == 0)
    {
        lan->rip_direction = intVal;
    }

    ret = cjson_get_int(item, "rip_version", &intVal);
    if(ret == 0)
    {
        lan->rip_version = intVal;
    }

    strVal = cjson_get_string(item, "macaddr");
    if(!strVal)
    {
        return -1;
    }
    strncpy(lan->macaddr, strVal, sizeof(lan->macaddr) - 1);    

    ret = cjson_get_int(item, "vlanid", &intVal);
    if(ret < 0)
    {
        return -1;
    }
    lan->vlanid = intVal;

    strVal = cjson_get_string(item, "desc");
    if(!strVal)
    {
        return -1;
    }
    strncpy(lan->desc, strVal, sizeof(lan->desc) - 1);

    return 0;
}

cJSON *get_dhcpd_reserv_list(char *name)
{
    int idx = 0;
    int num = 0;
    int ret = 0;
    int lan_idx = 0;
    cJSON *list = NULL;
    cJSON *item = NULL;
    char tmp[32] = {0};
    dhcpd_res_t cfg;

    list = cJSON_CreateArray();
    if(!list)
    {
        return NULL;
    }

    ret = sscanf(name, "LAN%d", &lan_idx);
    if(ret != 1)
    {
        return list;
    }

    if(lan_idx == 1)
    {
        get_lan_dhcp_reserv_num(&num);
    }
    else
    {
        snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_num", lan_idx - 1);
        num = config_get_int(tmp);
    }
    
    for(idx = 0; idx < num; idx ++)
    {
        memset(&cfg, 0x0, sizeof(dhcpd_res_t));
        
        cfg.lan_idx = lan_idx;
        dhcpd_reserv_config_get(idx, &cfg);
        
        if(cfg.mac[0] != '\0')
        {
            item = cJSON_CreateObject();
            if(!item)
            {
                continue;
            }

            cJSON_AddNumberToObject(item, "id", idx + 1);
            cJSON_AddStringToObject(item, "ip", cfg.ip);
            cJSON_AddStringToObject(item, "mac", cfg.mac);
            cJSON_AddStringToObject(item, "name", cfg.name);
            cJSON_AddItemToArray(list, item);
        }
        else
        {
            break;
        }
    }        

    return list;
}

/* 显示子网列表 */
int lan_subnet_list()
{
    int i = 0;
    int lan_num;
    lan_cfg_t lan;
    cJSON *rObj = NULL;
    cJSON *data = NULL;
    cJSON *subnet = NULL;

    rObj = cJSON_CreateObject();
    data = cJSON_CreateObject();
    subnet = cJSON_CreateArray();
    
    if(!rObj || !data || !subnet)
    {
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    lan_num = config_get_int("lan_num");
    lan_num = ((lan_num > 0) ? lan_num : 1);

    for(i = 0; i < lan_num; i ++)
    {
        cJSON *item = NULL;

        item = cJSON_CreateObject();
        if(!item)
        {
            cgi_errno = CGI_ERR_OTHER;
            goto err;
        }
        
        memset(&lan, 0x0, sizeof(lan_cfg_t));
    
        lan_subnet_config_get(i, &lan);

        cJSON_AddNumberToObject(item, "id", i + 1);
        cJSON_AddStringToObject(item, "name", lan.name);
        cJSON_AddStringToObject(item, "ipaddr", lan.ipaddr);
        cJSON_AddStringToObject(item, "netmask", lan.netmask);
        cJSON_AddStringToObject(item, "macaddr", lan.macaddr);
        cJSON_AddNumberToObject(item, "dhcp_enable", lan.dhcpd_enable);
        cJSON_AddStringToObject(item, "dhcp_start", lan.dhcpd_start);
        cJSON_AddStringToObject(item, "dhcp_end", lan.dhcpd_end);
        cJSON_AddItemToObject(item, "dhcp_reserv", get_dhcpd_reserv_list(lan.name));
        cJSON_AddNumberToObject(item, "ripd_enable", lan.ripd_enable);
        cJSON_AddNumberToObject(item, "rip_version", lan.rip_version);        
        cJSON_AddNumberToObject(item, "rip_direction", lan.rip_direction);
        cJSON_AddNumberToObject(item, "vlanid", lan.vlanid);
        cJSON_AddStringToObject(item, "desc", lan.desc);

        cJSON_AddItemToArray(subnet, item);
    }

    cJSON_AddNumberToObject(data, "num", lan_num);
    cJSON_AddItemToObject(data, "subnet", subnet);
    cJSON_AddNumberToObject(rObj, "code", cgi_errno);
    cJSON_AddItemToObject(rObj, "data", data); 

    char *out = NULL;

    out = cJSON_PrintUnformatted(rObj);
    if(!out)
    {
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    webs_write(stdout, "%s", out);
    free(out);

    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    
err:
    if(cgi_errno != CGI_ERR_OK)
    {
        webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }

    return 0;
}

int lan_arp_list()
{
    int i = 0;
    int ret = 0;
    FILE *fp = NULL;
    char line[128] = {0};
    char ip[16];
    char mac[18];
    char device[20];
    int lan_id = 0;
    char lan_name[20] = {0};

    fp = fopen("/proc/net/arp", "r");
    if(!fp)
    {
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    webs_write(stdout, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(stdout, "\"arplist\":[");

    while(fgets(line, sizeof(line), fp))
    {
        ret = sscanf(line, "%s %*s %*s %s %*s %s", ip, mac, device);
        if(ret != 3)
        {
            continue;
        }

        if(strcmp(mac, "00:00:00:00:00:00") == 0)
        {
            continue;
        }

        lan_id = get_lan_idx(device);
        if(lan_id < 0)
        {
            continue;
        }
        
        strncpy(lan_name, get_lan_name(lan_id), sizeof(lan_name) - 1);
        
        webs_write(stdout, "%s{\"mac\":\"%s\",\"name\":\"%s\",\"ip\":\"%s\"}", (i == 0) ? "" : ",",
            mac, lan_name, ip);
        
        i ++;
    }

    webs_write(stdout, "]}}");

    fclose(fp);

err:
    if(cgi_errno != CGI_ERR_OK)
    {
        webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return 0;
}

int parse_dhcpd_reserv_param(cJSON *item, dhcpd_res_t *cfg)
{
    int ret = 0;
    int match = 0;
    char *strVal = 0;
    char lan_name[20] = {0};

    strVal = cjson_get_string(item, "ifdesc");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(lan_name, strVal, sizeof(lan_name) - 1);

    match = sscanf(lan_name, "LAN%d", &cfg->lan_idx);
    if(match != 1)
    {
        ret = -1;
        goto err;
    }
    
    strVal = cjson_get_string(item, "ip");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->ip, strVal, sizeof(cfg->ip) - 1);

    strVal = cjson_get_string(item, "mac");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->mac, strVal, sizeof(cfg->mac) - 1);

    strVal = cjson_get_string(item, "dev_name");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    
    strncpy(cfg->name, strVal, sizeof(cfg->name) - 1);

err:

    return ret;
}

int lan_dhcp_reserv_add(char *data, int len)
{
    int ret = 0;
    cJSON *rObj = NULL;
    cJSON *item = NULL;
    char tmp[32] = {0};
    int reserv_num = 0;
    dhcpd_res_t cfg;

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    item = cJSON_GetObjectItem(rObj, "item");
    if(!item)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    memset(&cfg, 0x0, sizeof(dhcpd_res_t));

    ret = parse_dhcpd_reserv_param(item, &cfg);
    if(ret < 0)
    {   
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    if(cfg.lan_idx == 1)
    {
        get_lan_dhcp_reserv_num(&reserv_num);
    }
    else
    {
        snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_num", cfg.lan_idx - 1);
        reserv_num = config_get_int(tmp);
    }

    g_lan_idx = cfg.lan_idx;
    dhcpd_reserv_config_set(reserv_num, &cfg);

    config_set_int(tmp, (reserv_num + 1));

    /* 保存配置 */
    config_commit();

err:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }

    webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return ret;
}

int lan_dhcp_reserv_edit(char *data, int len)
{
    int ret = 0;
    int idx = 0;
    cJSON *rObj = NULL;
    cJSON *item = NULL;
    dhcpd_res_t cfg;

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    item = cJSON_GetObjectItem(rObj, "item");
    if(!item)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }
    
    ret = cjson_get_int(item, "id", &idx);
    if(ret < 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    memset(&cfg, 0x0, sizeof(dhcpd_res_t));
    
    ret = parse_dhcpd_reserv_param(item, &cfg);
    if(ret < 0)
    {   
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    g_lan_idx = cfg.lan_idx;
    dhcpd_reserv_config_set(idx - 1, &cfg);
    
    /* 保存配置 */
    config_commit();
    
err:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    
    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);   

    return ret;    
}

static int _dhcpd_reserv_del(char *lan_name, int idx)
{
    int ret = 0;
    int lan_idx = 0;

    ret = sscanf(lan_name, "LAN%d", &lan_idx);
    if(ret != 1)
    {
        return -1;
    }

    g_lan_idx = lan_idx;
    dhcpd_reserv_config_delete(idx - 1, lan_idx);

    return 0;
}

void dhcpd_reserv_config_align(int lan_reserv_num)
{
    int i = 0;
    int n = 0;
    int orig_num = 0;
    int lan_num = 0;
    char tmp[32] = {0};    
    int j = 0, r_idx = 0;
    dhcpd_res_t cfg;

    lan_num = config_get_int("lan_num");
    lan_num = ((lan_num > 0) ? lan_num : 1);

    /* skip LAN1 */
    for(n = 0; n < lan_num; n ++)
    {
        if(n == 0)
        {
            orig_num = lan_reserv_num;
        }
        else
        {
            snprintf(tmp, sizeof(tmp), "ct_dhcpd%d_reserv_num", n);
            orig_num = config_get_int(tmp);
        }
                
        for (i = 0, j = 0; i < orig_num; i ++)
        {
            memset(&cfg, 0x0, sizeof(dhcpd_res_t));

            cfg.lan_idx = n + 1;
            dhcpd_reserv_config_get(i, &cfg);
            
            if(cfg.mac[0] == '\0')
            {
                j ++;
            }
            else
            {
                r_idx = i - j;

                if(j > 0)
                {
                    dhcpd_reserv_config_set(r_idx, &cfg);
                    dhcpd_reserv_config_delete(i, n + 1);
                }
            }
        }        

        config_set_int(tmp, orig_num - j);
    }
    
}

int lan_dhcp_reserv_del(char *data, int len)
{
    int i = 0;
    int ret = 0;
    int size = 0;
    cJSON *rObj = NULL;
    cJSON *reserv = NULL;
    cJSON *item = NULL;
    char *strVal = NULL;
    int lan_reserv_num = 0;

    get_lan_dhcp_reserv_num(&lan_reserv_num);

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    reserv = cJSON_GetObjectItem(rObj, "reserv");
    if(!reserv || reserv->type != cJSON_Array)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    size = cJSON_GetArraySize(reserv);

    for(i = 0; i < size; i ++)
    {
        int idx = 0;

        item = cJSON_GetArrayItem(reserv, i);
        if(!item)
        {
            continue;
        }
        
        ret = cjson_get_int(item, "id", &idx);
        if(ret < 0)
        {
            cgi_errno = CGI_ERR_PARAM;
            continue;
        }
        
        strVal = cjson_get_string(item, "ifdesc");
        if(!strVal)
        {
            cgi_errno = CGI_ERR_PARAM;
            continue;            
        }
        
        ret = _dhcpd_reserv_del(strVal, idx);
        if(ret < 0)
        {
            cgi_errno = CGI_ERR_OTHER;
            continue;             
        }
    }

    dhcpd_reserv_config_align(lan_reserv_num);
    
    /* 保存配置 */
    config_commit();
    
err:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    
    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);   

    return ret;
}

/* 添加子网 */
int lan_subnet_add(char *data, int len)
{
    int ret = 0;
    cJSON *rObj = NULL;
    cJSON *item = NULL;
    struct lan_cfg lan;
    int lan_num, lan_id;
    char lan_name[20] = {0};

    lan_num = config_get_int("lan_num");
    lan_num = ((lan_num > 0) ? lan_num : 1);
    if(lan_num >= MAX_LAN_NUM)
    {
        ret = -1;
        cgi_errno = 222;
        goto err;
    }

    lan_id = lan_num + 1;
    strncpy(lan_name, get_lan_name(lan_id), sizeof(lan_id) - 1);

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    item = cJSON_GetObjectItem(rObj, "subnet");
    if(!item)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }
    
    memset(&lan, 0x0, sizeof(struct lan_cfg));
    ret = parse_lan_param(item, &lan);
    if(ret < 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    lan_subnet_config_set(lan_id - 1, &lan);
    
    config_set_int("lan_num", lan_num + 1);
    
    /* 保存配置 */
    config_commit();

    g_lan_idx = lan_id;
    cgi_log_info("add %s subnet ok", lan_name);
    
err:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    
    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return ret;
}

int lan_subnet_edit(char *data, int len)
{
    int ret = 0;
    cJSON *rObj = NULL;
    cJSON *item = NULL;
    struct lan_cfg lan;
    int lan_num, lan_id;
    char lan_name[20] = {0};

    lan_num = config_get_int("lan_num");
    lan_num = ((lan_num > 0) ? lan_num : 1);
	
    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    item = cJSON_GetObjectItem(rObj, "subnet");
    if(!item)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }
    
    memset(&lan, 0x0, sizeof(struct lan_cfg));

    ret = cjson_get_int(item, "id", &lan_id);
    if(ret < 0 || (lan_id > lan_num || lan_id <= 0))
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }
    
    ret = parse_lan_param(item, &lan);
    if(ret < 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    strncpy(lan_name, get_lan_name(lan_id), sizeof(lan_id) - 1);
    lan_subnet_config_set((lan_id - 1), &lan);
    
    /* 保存配置 */
    config_commit();

    g_lan_idx = lan_id;
    cgi_log_info("edit %s subnet ok", lan_name);
    
err:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    
    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);   

    return ret;
}

int lan_subnet_del(char *data, int len)
{
    int i = 0;
    int ret = 0;
    int size = 0;
    cJSON *rObj = NULL;
    cJSON *subnet = NULL;
    int lan_num = 0;
    int left_num = 0;

    lan_num = config_get_int("lan_num");
    lan_num = ((lan_num > 0) ? lan_num : 1);

    left_num = lan_num;

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    subnet = cJSON_GetObjectItem(rObj, "subnet");
    if(!subnet || subnet->type != cJSON_Array)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    size = cJSON_GetArraySize(subnet);
    
    for(i = 0; i < size; i ++)
    {
        int lan_id = 0;
        cJSON *item = NULL;

        item = cJSON_GetArrayItem(subnet, i);
        if(!item)
        {
            continue;
        }
        
        ret = cjson_get_int(item, "id", &lan_id);
        if(ret < 0)
        {
            cgi_errno = CGI_ERR_PARAM;
            continue;
        }
        
        g_lan_idx = lan_id;
        
        if(lan_id != 1 && lan_id <= lan_num)
        {
            lan_subnet_config_del(lan_id - 1);
            left_num --;
        }
        else
        {
            cgi_errno = CGI_ERR_PARAM;
        }
    }

    config_set_int("lan_num", left_num);

    lan_subnet_config_align(lan_num);
    
    /* 保存配置 */
    config_commit();

    cgi_log_info("delete lan subnet ok");
    
err:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    
    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);
    
    return ret;
}

int network_main(char *cmd, char *data)
{
    int ret = 0;

    if(!cmd)
    {
        return -1;
    }

    if(strcmp(cmd, "lan_subnet_list") == 0)
    {
        return lan_subnet_list();
    }
    else if(strcmp(cmd, "lan_arp_list") == 0)
    {
        ret = lan_arp_list();
    }
    
    if(data != NULL)
    {
        if(strcmp(cmd, "lan_subnet_add") == 0)
        {
            ret = lan_subnet_add(data, strlen(data));
        }
        else if(strcmp(cmd, "lan_subnet_edit") == 0)
        {
            ret = lan_subnet_edit(data, strlen(data));
        }
        else if(strcmp(cmd, "lan_subnet_del") == 0)
        {
            ret = lan_subnet_del(data, strlen(data));
        }
        else if(strcmp(cmd, "dhcpd_reserv_add") == 0)
        {
            ret = lan_dhcp_reserv_add(data, strlen(data));
        }
        else if(strcmp(cmd, "dhcpd_reserv_edit") == 0)
        {
            ret = lan_dhcp_reserv_edit(data, strlen(data));
        }
        else if(strcmp(cmd, "dhcpd_reserv_del") == 0)
        {
            ret = lan_dhcp_reserv_del(data, strlen(data));
        }

        if(ret == 0)
        {
            if(g_lan_idx == 1)
            {
                ret = wait_eval(3, "/etc/init.d/net-lan restart");
            }
            else
            {
                ret = wait_eval(3, "/usr/sbin/cgi_reload.sh network_config");
            }
        }
    }

    return ret;
}
