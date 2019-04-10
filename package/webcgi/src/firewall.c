
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "firewall.h"

#define FIREWALL_RULE

void fw_rule_config_get(int idx, struct fw_rule *rule)
{
    strncpy(rule->name, config_get_ext("ct_fw_rule_name_x", idx), sizeof(rule->name) - 1);
    strncpy(rule->src, config_get_ext("ct_fw_rule_src_x", idx), sizeof(rule->src) - 1);
    strncpy(rule->src_ip, config_get_ext("ct_fw_rule_srcip_x", idx), sizeof(rule->src_ip) - 1);    
    strncpy(rule->src_ip_range, config_get_ext("ct_fw_rule_srcipr_x", idx), sizeof(rule->src_ip_range) - 1);
    strncpy(rule->src_mac, config_get_ext("ct_fw_rule_srcmac_x", idx), sizeof(rule->src_mac) - 1);
    strncpy(rule->src_port, config_get_ext("ct_fw_rule_srcport_x", idx), sizeof(rule->src_port) - 1);
    strncpy(rule->dest, config_get_ext("ct_fw_rule_dest_x", idx), sizeof(rule->dest) - 1);
    strncpy(rule->dest_ip, config_get_ext("ct_fw_rule_destip_x", idx), sizeof(rule->dest_ip) - 1);
    strncpy(rule->dest_ip_range, config_get_ext("ct_fw_rule_destipr_x", idx), sizeof(rule->dest_ip_range) - 1);
    strncpy(rule->dest_port, config_get_ext("ct_fw_rule_destport_x", idx), sizeof(rule->dest_port) - 1);
    strncpy(rule->proto, config_get_ext("ct_fw_rule_proto_x", idx), sizeof(rule->proto) - 1);
    rule->action = config_get_int_ext("ct_fw_rule_action_x", idx);
    rule->family = config_get_int_ext("ct_fw_rule_family_x", idx);
    strncpy(rule->extra, config_get_ext("ct_fw_rule_extra_x", idx), sizeof(rule->extra) - 1);
}

void fw_rule_config_set(int idx, struct fw_rule *rule)
{
    config_set_ext("ct_fw_rule_name_x", idx, rule->name);
    config_set_ext("ct_fw_rule_src_x", idx, rule->src);
    config_set_ext("ct_fw_rule_srcip_x", idx, rule->src_ip);    
    config_set_ext("ct_fw_rule_srcipr_x", idx, rule->src_ip_range);
    config_set_ext("ct_fw_rule_srcmac_x", idx, rule->src_mac);
    config_set_ext("ct_fw_rule_srcport_x", idx, rule->src_port);
    config_set_ext("ct_fw_rule_dest_x", idx, rule->dest);
    config_set_ext("ct_fw_rule_destip_x", idx, rule->dest_ip);    
    config_set_ext("ct_fw_rule_destipr_x", idx, rule->dest_ip_range);
    config_set_ext("ct_fw_rule_destport_x", idx, rule->dest_port);
    config_set_ext("ct_fw_rule_proto_x", idx, rule->proto);
    config_set_int_ext("ct_fw_rule_action_x", idx, rule->action);
    config_set_int_ext("ct_fw_rule_family_x", idx, rule->family);
    config_set_ext("ct_fw_rule_extra_x", idx, rule->extra);
}

void fw_rule_config_del(int idx)
{
    config_unset_ext("ct_fw_rule_name_x", idx);
    config_unset_ext("ct_fw_rule_src_x", idx);
    config_unset_ext("ct_fw_rule_srcip_x", idx);    
    config_unset_ext("ct_fw_rule_srcipr_x", idx);
    config_unset_ext("ct_fw_rule_srcmac_x", idx);
    config_unset_ext("ct_fw_rule_srcport_x", idx);
    config_unset_ext("ct_fw_rule_dest_x", idx);
    config_unset_ext("ct_fw_rule_destip_x", idx);    
    config_unset_ext("ct_fw_rule_destipr_x", idx);
    config_unset_ext("ct_fw_rule_destport_x", idx);
    config_unset_ext("ct_fw_rule_proto_x", idx);
    config_unset_ext("ct_fw_rule_action_x", idx);
    config_unset_ext("ct_fw_rule_family_x", idx);
    config_unset_ext("ct_fw_rule_extra_x", idx);
}

int fw_rule_config_align(int orig_num)
{
    int i = 0, j = 0;
    int r_idx = 0;
    struct fw_rule rule;

    cgi_debug("origNum = %d\n", orig_num);

    for(i = 0; i < orig_num; i ++)
    {
        memset(&rule, 0x0, sizeof(struct fw_rule));

        fw_rule_config_get(i, &rule);  

        if(rule.name[0] == '\0')
        {
            j ++;
        }
        else
        {
            r_idx = i - j;

            cgi_debug("r idx = %d\n", r_idx);

            if(j > 0)
            {
                fw_rule_config_set(r_idx, &rule);
                fw_rule_config_del(i);
           }
        }
    }

    return 0;
}


int parse_json_fw_rule(cJSON *item, struct fw_rule *rule)
{
    int ret = 0;
    int intVal = 0;
    char *strVal = NULL;

    if(item->type != cJSON_Object)
    {
        return -1;
    }

    strVal = cjson_get_string(item, "name");
    if(!strVal)
    {
        return -1;
    }
    strncpy(rule->name, strVal, sizeof(rule->name) - 1); 

    strVal = cjson_get_string(item, "src");
    if(strVal)
    {
       strncpy(rule->src, strVal, sizeof(rule->src) - 1); 
    }

    strVal = cjson_get_string(item, "src_ip");
    if(strVal)
    {
       strncpy(rule->src_ip, strVal, sizeof(rule->src_ip) - 1); 
    }

    strVal = cjson_get_string(item, "src_ip_range");
    if(strVal)
    {
       strncpy(rule->src_ip_range, strVal, sizeof(rule->src_ip_range) - 1); 
    }

    strVal = cjson_get_string(item, "src_mac");
    if(strVal)
    {
       strncpy(rule->src_mac, strVal, sizeof(rule->src_mac) - 1); 
    }

    strVal = cjson_get_string(item, "src_port");
    if(strVal)
    {   
        strncpy(rule->src_port, strVal, sizeof(rule->src_port) - 1);
    }

    strVal = cjson_get_string(item, "dest");
    if(strVal)
    {
       strncpy(rule->dest, strVal, sizeof(rule->dest) - 1); 
    }
    
    strVal = cjson_get_string(item, "dest_ip");
    if(strVal)
    {
       strncpy(rule->dest_ip, strVal, sizeof(rule->dest_ip) - 1); 
    }

    strVal = cjson_get_string(item, "dest_ip_range");
    if(strVal)
    {
       strncpy(rule->dest_ip_range, strVal, sizeof(rule->dest_ip_range) - 1); 
    }

    strVal = cjson_get_string(item, "dest_port");    
    if(strVal)
    {  
        strncpy(rule->dest_port, strVal, sizeof(rule->dest_port) - 1);
    }
    
    strVal = cjson_get_string(item, "proto");
    if(strVal)
    {   
        strncpy(rule->proto, strVal, sizeof(rule->proto) - 1); 
    }

    ret = cjson_get_int(item, "action", &intVal);
    if(!ret)
    {   
        rule->action = intVal;
    }

    rule->family = FW_IPV4;

    strVal = cjson_get_string(item, "extra");
    if(strVal)
    {
       strncpy(rule->extra, strVal, sizeof(rule->extra) - 1); 
    }

    return 0;
}

int firewall_rule_list()
{
    int num = 0;
    int idx = 0;
    cJSON *rObj = NULL;
    cJSON *data = NULL;
    cJSON *rules = NULL;
    struct fw_rule rule;

    rObj = cJSON_CreateObject();
    data = cJSON_CreateObject();
    rules = cJSON_CreateArray();
    if(!rObj || !data || !rules)
    {
        cgi_errno = CGI_ERR_OTHER;
        return -1;
    }
    
    num = config_get_int("ct_fw_rule_num");

    for(idx = 0; idx < num; idx ++)
    {
        cJSON *item = NULL;

        item = cJSON_CreateObject();
        if(!item)
        {
            continue;
        }
        
        memset(&rule, 0x0, sizeof(struct fw_rule));
        fw_rule_config_get(idx, &rule);

        cJSON_AddNumberToObject(item, "id", (idx + 1));
        cJSON_AddStringToObject(item, "name", rule.name);
        cJSON_AddStringToObject(item, "src", rule.src);
        cJSON_AddStringToObject(item, "src_ip", rule.src_ip);
        cJSON_AddStringToObject(item, "src_ip_range", rule.src_ip_range);
        cJSON_AddStringToObject(item, "src_mac", rule.src_mac);
        cJSON_AddStringToObject(item, "src_port", rule.src_port);
        cJSON_AddStringToObject(item, "dest", rule.dest);
        cJSON_AddStringToObject(item, "dest_ip", rule.dest_ip);
        cJSON_AddStringToObject(item, "dest_ip_range", rule.dest_ip_range);
        cJSON_AddStringToObject(item, "dest_port", rule.dest_port);
        cJSON_AddStringToObject(item, "proto", rule.proto);
        cJSON_AddNumberToObject(item, "action", rule.action);
        cJSON_AddStringToObject(item, "extra", rule.extra);

        cJSON_AddItemToArray(rules, item);
    }

    cJSON_AddNumberToObject(data, "num", num);
    cJSON_AddItemToObject(data, "rules", rules);
    cJSON_AddNumberToObject(rObj, "code", cgi_errno);
    cJSON_AddItemToObject(rObj, "data", data); 

    char *out = NULL;

    out = cJSON_PrintUnformatted(rObj);
    if(!out)
    {
        goto end_proc;
    }

    fprintf(stdout, "%s", out);

end_proc:

    return 0;
}

int firewall_rule_add(char *data, int len)
{
    int ret = 0;
    int idx = 0;
    int num = 0;
    cJSON *rObj = NULL;
    cJSON *item = NULL;
    struct fw_rule rule;

    num = config_get_int("ct_fw_rule_num");
    if(num >= MAX_FW_RULE_NUM)
    {
        ret = -1;
        cgi_errno = 333;
        goto end_proc;
    }

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto end_proc;
    }

    item = cJSON_GetObjectItem(rObj, "fw_rule");
    if(!item)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;        
    }

    memset(&rule, 0x0, sizeof(struct fw_rule));
    
    ret = parse_json_fw_rule(item, &rule);
    if(ret < 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }

    idx = num;
    fw_rule_config_set(idx, &rule);
    
    config_set_int("ct_fw_rule_num", (num + 1));

    config_commit();

    cgi_log_info("add traffic rules from %s to %s ok", rule.src, rule.dest);
    
end_proc:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }

    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return ret;
}

int firewall_rule_edit(char *data, int len)
{
    int ret = 0;
    int idx = 0;
    int num = 0;
    cJSON *rObj = NULL;
    cJSON *item = NULL;
    struct fw_rule rule;

    num = config_get_int("ct_fw_rule_num");
    if(num >= MAX_FW_RULE_NUM)
    {
        ret = -1;
        cgi_errno = 333;
        goto end_proc;
    }

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto end_proc;
    }

    item = cJSON_GetObjectItem(rObj, "fw_rule");
    if(!item)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;        
    }

    ret = cjson_get_int(item, "id", &idx);
    if(ret < 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }

    if(idx <= 0 || idx > num)
    {
        ret = -1;
        cgi_errno = 444;
        goto end_proc;
    }

    memset(&rule, 0x0, sizeof(struct fw_rule));
    
    ret = parse_json_fw_rule(item, &rule);
    if(ret < 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }

    fw_rule_config_set((idx - 1), &rule);

    config_commit();

    cgi_log_info("edit traffic rules from %s to %s ok", rule.src, rule.dest);

end_proc:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }

    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return ret;
}

int firewall_rule_del(char *data, int len)
{
    int i = 0;
    int ret = 0;
    int size = 0;
    cJSON *rObj = NULL;
    cJSON *rules = NULL;
    int rule_num = 0;
    int left_num = 0;

    rule_num = config_get_int("ct_fw_rule_num");
    left_num = rule_num;

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    rules = cJSON_GetObjectItem(rObj, "rules");
    if(!rules || rules->type != cJSON_Array)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    size = cJSON_GetArraySize(rules);
    for(i = 0; i < size; i ++)
    {        
        int idx = 0;
        cJSON *item = NULL;

        item = cJSON_GetArrayItem(rules, i);
        if(item->type != cJSON_Object)
        {
            continue;
        }
        
        ret = cjson_get_int(item, "id", &idx);
        if(ret < 0)
        {
            continue;
        }

        if(idx > 0 && idx <= rule_num)
        {
            fw_rule_config_del((idx - 1));
            left_num --;
        }
    }

    config_set_int("ct_fw_rule_num", left_num);

    fw_rule_config_align(rule_num);

    /* 保存配置 */
    config_commit();

    cgi_log_info("delete traffic rules ok");
    
err:
    if(!rObj)
    {
        cJSON_Delete(rObj);
    }
    
    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);  

    return 0;
}

#define BLK_SERVICE

int get_blk_svc_num()
{
    int num = 0;
    char *strVal = NULL;

    while(1)
    {
        strVal = config_get_ext("block_services", num + 1);
        if(strVal[0] == '\0')
        {
            break;
        }

        num ++;
    }

    return num;
}

void blk_svc_config_get(int idx, struct blk_svc *cfg)
{
    int ret = 0;
    char *strVal = NULL;
    char rule[128] = {0};
    
    strVal = config_get_ext("block_services", idx);
    if(strVal[0] == '\0')
    {
        return;
    }

    strncpy(rule, strVal, sizeof(rule) - 1);
    ret = sscanf(rule, "%s %s %d %d %s %d %s", cfg->name, cfg->proto, 
        &cfg->start_port, &cfg->end_port, cfg->svc_type, &cfg->addr_type, cfg->addr);
    if(ret != 7)
    {
        cgi_debug("config get failed!\n");
    }
}

void blk_svc_config_set(int idx, struct blk_svc *cfg)
{
    char rule[128] = {0};

    snprintf(rule, sizeof(rule), "%s %s %d %d %s %d %s", cfg->name, cfg->proto, 
        cfg->start_port, cfg->end_port, cfg->svc_type, cfg->addr_type, cfg->addr);

    config_set_ext("block_services", idx, rule);
}

void blk_svc_config_del(int idx)
{
    config_unset_ext("block_services", idx);    
}

int blk_svc_config_align(int orig_num)
{
    int i = 0, j = 0;
    int r_idx = 0;
    struct blk_svc cfg;

    for(i = 1; i <= orig_num; i ++)
    {
        memset(&cfg, 0x0, sizeof(struct blk_svc));

        blk_svc_config_get(i, &cfg);

        if(cfg.name[0] == '\0')
        {
            j ++;
        }
        else
        {
            r_idx = i - j;
            if(j > 0)
            {
                blk_svc_config_set(r_idx, &cfg);
                blk_svc_config_del(i);
            }
        }
    }

    return 0;

}

int parse_json_blk_svc(cJSON *item, struct blk_svc *cfg)
{
    int ret = 0;
    int intVal = 0;
    char *strVal = NULL;

    strVal = cjson_get_string(item, "name");
    if(!strVal)
    {
        return -1;
    }
    strncpy(cfg->name, strVal, sizeof(cfg->name) - 1);

    strVal = cjson_get_string(item, "protocol");
    if(!strVal)
    {
        return -1;
    }
    strncpy(cfg->proto, strVal, sizeof(cfg->proto) - 1);

    ret = cjson_get_int(item, "start_port", &intVal);
    if(ret < 0)
    {
        return -1;
    }
    cfg->start_port = intVal;

    ret = cjson_get_int(item, "end_port", &intVal);
    if(ret < 0)
    {
        return -1;
    }
    cfg->end_port = intVal;
    
    strVal = cjson_get_string(item, "svc_type");
    if(!strVal)
    {
        return -1;
    }
    strncpy(cfg->svc_type, strVal, sizeof(cfg->svc_type) - 1);

    ret = cjson_get_int(item, "addr_type", &intVal);
    if(ret < 0)
    {
        return -1;
    }
    cfg->addr_type = intVal;
    
    strVal = cjson_get_string(item, "addr");
    if(!strVal)
    {
        return -1;
    }
    strncpy(cfg->addr, strVal, sizeof(cfg->addr) - 1);

    return 0;
}

int blk_service_list()
{
    int num = 0;
    int idx = 0;
    cJSON *rObj = NULL;
    cJSON *data = NULL;
    cJSON *rules = NULL;
    int ctrl_type = 0;
    struct blk_svc cfg;

    rObj = cJSON_CreateObject();
    data = cJSON_CreateObject();
    rules = cJSON_CreateArray();
    if(!rObj || !data || !rules)
    {
        cgi_errno = CGI_ERR_OTHER;
        return -1;
    }

    ctrl_type = config_get_int("blockserv_ctrl");
    num = get_blk_svc_num();
    for(idx = 1; idx <= num; idx ++)
    {
        cJSON *item = NULL;

        item = cJSON_CreateObject();
        if(!item)
        {
            continue;
        }
        
        memset(&cfg, 0x0, sizeof(struct blk_svc));
        blk_svc_config_get(idx, &cfg);

        cJSON_AddNumberToObject(item, "id", idx);
        cJSON_AddStringToObject(item, "name", cfg.name);
        cJSON_AddStringToObject(item, "protocol", cfg.proto);
        cJSON_AddNumberToObject(item, "start_port", cfg.start_port);
        cJSON_AddNumberToObject(item, "end_port", cfg.end_port);
        cJSON_AddStringToObject(item, "svc_type", cfg.proto);
        cJSON_AddNumberToObject(item, "addr_type", cfg.addr_type);
        cJSON_AddStringToObject(item, "addr", cfg.addr);

        cJSON_AddItemToArray(rules, item);
    }

    cJSON_AddNumberToObject(data, "num", num);
    cJSON_AddNumberToObject(data, "ctrl_type", ctrl_type);
    cJSON_AddItemToObject(data, "rules", rules);
    cJSON_AddNumberToObject(rObj, "code", cgi_errno);
    cJSON_AddItemToObject(rObj, "data", data); 

    char *out = NULL;

    out = cJSON_PrintUnformatted(rObj);
    if(!out)
    {
        cgi_errno = CGI_ERR_OTHER;
        goto end_proc;
    }

    webs_write(stdout, "%s", out);

end_proc:
    if(cgi_errno != CGI_ERR_OK)
    {
        webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }

    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    if(out)
    {
        free(out);
    }

    return 0;
}

int blk_service_ctrl(char *data, int len)
{
    int ret = 0;
    int ctrl_type = 0;
    cJSON *rObj = NULL;
    cJSON *rules = NULL;
        
    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    rules = cJSON_GetObjectItem(rObj, "blk_svc");
    if(!rules)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    ret = cjson_get_int(rules, "ctrl_type", &ctrl_type);
    if(ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    if(ctrl_type < 0 || ctrl_type > 2)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    config_set_int("blockserv_ctrl", ctrl_type);

    /* 保存配置 */
    config_commit();
    
err:
    if(!rObj)
    {
        cJSON_Delete(rObj);
    }
    
    webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);  

    return 0;
}

int blk_service_add(char *data, int len)
{
    int ret = 0;
    int idx = 0;
    int num = 0;
    cJSON *rObj = NULL;
    cJSON *item = NULL;
    struct blk_svc cfg;

    num = get_blk_svc_num();
    if(num >= MAX_BLK_SVC_NUM)
    {
        ret = -1;
        cgi_errno = CGI_ERR_LIMITED;
        goto end_proc;
    }

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto end_proc;
    }

    item = cJSON_GetObjectItem(rObj, "blk_svc");
    if(!item)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;        
    }

    memset(&cfg, 0x0, sizeof(struct blk_svc));
    
    ret = parse_json_blk_svc(item, &cfg);
    if(ret < 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }

    idx = num + 1;
    blk_svc_config_set(idx, &cfg);
    
    config_commit();
    
end_proc:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }

    webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return ret;
}

int blk_service_edit(char *data, int len)
{
    int ret = 0;
    int idx = 0;
    int num = 0;
    cJSON *rObj = NULL;
    cJSON *item = NULL;
    struct blk_svc cfg;

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto end_proc;
    }

    item = cJSON_GetObjectItem(rObj, "blk_svc");
    if(!item)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;        
    }

    num = get_blk_svc_num();

    ret = cjson_get_int(item, "id", &idx);
    if(ret < 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }

    if(idx <= 0 || idx > num)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }

    memset(&cfg, 0x0, sizeof(struct blk_svc));
    
    ret = parse_json_blk_svc(item, &cfg);
    if(ret < 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }

    blk_svc_config_set(idx, &cfg);

    config_commit();

end_proc:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }

    webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return ret;
}

int blk_service_del(char *data, int len)
{
    int ret = 0;
    int num = 0;
    int idx = 0;
    cJSON *rObj = NULL;
    cJSON *rules = NULL;
    
    num = get_blk_svc_num();
    
    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    rules = cJSON_GetObjectItem(rObj, "blk_svc");
    if(!rules)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    ret = cjson_get_int(rules, "id", &idx);
    if(ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    if(idx <= 0 || idx > num)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    cgi_debug("idx = %d\n", idx);

    blk_svc_config_del(idx);
    blk_svc_config_align(num);

    /* 保存配置 */
    config_commit();
    
err:
    if(!rObj)
    {
        cJSON_Delete(rObj);
    }
    
    webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);  

    return 0;
}

#define NET_ACL

#define FIREWALL_SNAT

int firewall_main(char *cmd, char *data)
{
    int ret = 0;
    int type = 0;

    if(!cmd)
    {
        return -1;
    }

    if(strcmp(cmd, "fw_rule_list") == 0)
    {
        return firewall_rule_list();
    }
    else if(strcmp(cmd, "blk_svc_list") == 0)
    {
        return blk_service_list();
    }

    if(data != NULL)
    {
        if(strcmp(cmd, "fw_rule_add") == 0)
        {
            type = CFG_FW_RULE;
            ret = firewall_rule_add(data, strlen(data));
        }
        else if(strcmp(cmd, "fw_rule_edit") == 0)
        {    
            type = CFG_FW_RULE;
            ret = firewall_rule_edit(data, strlen(data));
        }
        else if(strcmp(cmd, "fw_rule_del") == 0)
        {
            type = CFG_FW_RULE;                    
            ret = firewall_rule_del(data, strlen(data));
        }

        if(strcmp(cmd, "blk_svc_ctrl") == 0)
        {
            type = CFG_BLK_SVC;
            ret = blk_service_ctrl(data, strlen(data));
        }
        else if(strcmp(cmd, "blk_svc_add") == 0)
        {
            type = CFG_BLK_SVC;
            ret = blk_service_add(data, strlen(data));
        }
        else if(strcmp(cmd, "blk_svc_edit") == 0)
        {
            type = CFG_BLK_SVC;
            ret = blk_service_edit(data, strlen(data));
        }
        else if(strcmp(cmd, "blk_svc_del") == 0)
        {
            type = CFG_BLK_SVC;
            ret = blk_service_del(data, strlen(data));
        }

        if (ret == 0)
        {
            if (type == CFG_FW_RULE)
            {
                ret = wait_eval(1, "/usr/sbin/cgi_reload.sh firewall_config");
            }
            else if (type == CFG_BLK_SVC)
            {
                ret = wait_eval(1, "/www/cgi-bin/firewall.sh restart");
            }
        }
    }

    return ret;
}

