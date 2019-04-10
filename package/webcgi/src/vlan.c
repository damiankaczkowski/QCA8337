
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "vlan.h"
#include "utils.h"

struct sw_vlan_cfg sw_vlan;

#define GET_BIT(val, i) ((val & (1 << i)) >> i)

void vlan_config_get(int idx, struct vlan_attr *vlan)
{
    strncpy(vlan->name, config_get_ext("ct_vlan_name_x", idx), sizeof(vlan->name) - 1);
    vlan->vid = config_get_int_ext("ct_vlan_vid_x", idx);
    vlan->prio = config_get_int_ext("ct_vlan_prio_x", idx);
    strncpy(vlan->ports, config_get_ext("ct_vlan_ports_x", idx), sizeof(vlan->ports) - 1);
    strncpy(vlan->phyports, config_get_ext("ct_vlan_phyports_x", idx), sizeof(vlan->phyports) - 1);    
    strncpy(vlan->desc, config_get_ext("ct_vlan_desc_x", idx), sizeof(vlan->desc) - 1);
}

void vlan_config_set(int idx, struct vlan_attr *vlan)
{
    config_set_ext("ct_vlan_name_x", idx, vlan->name);
    config_set_int_ext("ct_vlan_vid_x", idx, vlan->vid);
    config_set_int_ext("ct_vlan_prio_x", idx, vlan->prio);
    config_set_ext("ct_vlan_ports_x", idx, vlan->ports);    
    config_set_ext("ct_vlan_phyports_x", idx, vlan->phyports);
    config_set_ext("ct_vlan_desc_x", idx, vlan->desc);
}

void vlan_config_del(int idx)
{
    config_unset_ext("ct_vlan_name_x", idx);
    config_unset_ext("ct_vlan_vid_x", idx);
    config_unset_ext("ct_vlan_prio_x", idx);
    config_unset_ext("ct_vlan_ports_x", idx);
    config_unset_ext("ct_vlan_phyports_x", idx);
    config_unset_ext("ct_vlan_desc_x", idx);
}

/*
 * 在进行删除操作后，必须执行对齐操作，nvram存储list结构决定
 */
int vlan_config_align(int orig_num)
{
    int skip = 0;
    int idx = 0;
    int r_idx = 0;
    struct vlan_attr vlan;

    for(idx = 0; idx < orig_num; idx ++)
    {
        memset(&vlan, 0x0, sizeof(struct vlan_attr));
        
        vlan_config_get(idx, &vlan);

        if(vlan.name[0] == '\0')
        {
            skip ++;
        }
        else
        {
            r_idx = idx - skip;

            if(skip > 0)
            {
                vlan_config_set(r_idx, &vlan);
                vlan_config_del(idx);
           }
        }
    }

    return 0;
}

int find_vlan_idx_by_vid(int vid)
{
    int i = 0;
    int num = 0;
    int intVal = 0;

    num = config_get_int("ct_vlan_num");

    for(i = 0; i < num; i ++)
    {
        intVal = config_get_int_ext("ct_vlan_vid_x", i);      
        if(intVal == vid)
        {
            break;
        }
    }

    if(i >= num)
        return -1;
    else
        return i;
}

int switch_vlan_cfg_init(struct sw_vlan_cfg *sw)
{
    int i = 0;
    char *delims = " ";
    char *result = NULL;
    int vid;
    int phyPort = 0;
    char ports[64] = {0};
    
    memset(sw, 0x0, sizeof(struct sw_vlan_cfg));

    sw->vlan_entry = config_get_int("ct_vlan_num");

    for(i = 0; i < sw->vlan_entry; i ++)
    {
        vid = config_get_int_ext("ct_vlan_vid_x", i);
        
        if(vid < MIN_VLAN_ID || vid > MAX_VLAN_ID)
        {
            continue;
        }
        
        sw->vlan_id[i] = vid;

        strncpy(ports, config_get_ext("ct_vlan_phyports_x", i), sizeof(ports) - 1);

        result = strtok(ports, delims); 
        while(result != NULL) 
        {
            int port = 0;
            char attr = 0;
        
            sscanf(result, "%d%c", &port, &attr);

            if(port < 0 || port > MAX_PHY_PORT)
            {
                continue;
            }
            
            sw->pbmp_vlan[i] |= (1 << port);
            if(attr == 't')
            {
                sw->tbmp_vlan[i] |= (1 << port);
            }
            
            result = strtok(NULL, delims);
        }

    }

    for(i = 1; i <= MAX_PANNEL_PORT; i ++)
    {
        phyPort = pannelPort_to_phyPort_xlate(i);
        sw->pvid[phyPort] = config_get_int_ext("ct_port_pvid_x", phyPort);
    }

    return 0;
}


cJSON *get_phyPort_vlans(struct sw_vlan_cfg *sw, int phyPort)
{
    int i = 0;
    int tag = 0;
    int cnt = 0;
    char vlan[10] = {0};
    char *vlans[MAX_VLAN_ENTRY];

    for(i = 0; i < sw->vlan_entry; i ++)
    {
        tag = 0;
        
        if(!GET_BIT(sw->pbmp_vlan[i], phyPort))
        {
            continue;
        }

        if(GET_BIT(sw->tbmp_vlan[i], phyPort))
        {
            tag = 1;
        }

        snprintf(vlan, sizeof(vlan), "%d%s", sw->vlan_id[i], (tag == 0) ? "" : "t");

        vlans[cnt] = strdup(vlan);
        
        cnt ++;
    }

    return cJSON_CreateStringArray(vlans, cnt);
}

int port_vlan_list()
{
    int i = 0;
    int ret = 0;
    cJSON *data = NULL;
    cJSON *entry = NULL;
    char *result = NULL;

    data = cJSON_CreateObject();
    if(!data)
    {
        cgi_errno = CGI_ERR_OTHER;
        return -1;
    }

    entry = cJSON_CreateArray();
    if(!entry)
    {
        cgi_errno = CGI_ERR_OTHER;
        return -1;
    }
    
    ret = switch_vlan_cfg_init(&sw_vlan);
    if(ret < 0)
    {
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    for(i = 1; i <= MAX_PANNEL_PORT; i ++)
    {
        int pvid = 0;
        cJSON *item = NULL;
        int phyPort = 0;
 
        item = cJSON_CreateObject();
        if(!item)
        {
            continue;
        }   

        phyPort = pannelPort_to_phyPort_xlate(i);
        pvid = sw_vlan.pvid[phyPort];

        cJSON_AddNumberToObject(item, "id", i);
        cJSON_AddNumberToObject(item, "pvid", pvid);
        cJSON_AddItemToObject(item, "vlans", get_phyPort_vlans(&sw_vlan, phyPort));

        cJSON_AddItemToArray(entry, item);
    }
    
    cJSON_AddNumberToObject(data, "num", MAX_PANNEL_PORT);
    cJSON_AddItemToObject(data, "port", entry);

    result = cJSON_PrintUnformatted(data);
    if(!result)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

err:
    if(ret < 0)
    {
        fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    else
    {
        fprintf(stdout, "{\"code\":%d,\"data\":%s}", cgi_errno, result);
    }
    
    if(result)
    {
        free(result);
    }

    if(data)
    {
        cJSON_Delete(data);
    }
    
    return ret;    
}

int port_pvid_edit(char *data, int len)
{
    int ret = 0;
    cJSON *rObj = NULL;
    cJSON *ports = NULL;
    int i = 0;
    int arrNum = 0;

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    ports = cJSON_GetObjectItem(rObj, "port");
    if(!ports || ports->type != cJSON_Array)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    arrNum = cJSON_GetArraySize(ports);

    for(i = 0; i < arrNum; i ++)
    {
        int pvid = 0;
        int phyPort = 0;
        int pannelPort = 0;
        cJSON *item = NULL;
        
        item = cJSON_GetArrayItem(ports, i);
        if(!item)
        {
            cgi_errno = CGI_ERR_PARAM;
            continue;
        }
        
        ret += cjson_get_int(item, "id", &pannelPort);
        ret += cjson_get_int(item, "pvid", &pvid);
        if(ret != 0)
        {
            cgi_errno = CGI_ERR_PARAM;
            continue;
        }

        /* 
         * TODO: PVID 设置需要做限制
         */

        phyPort = pannelPort_to_phyPort_xlate(pannelPort);
        
        config_set_int_ext("ct_port_pvid_x", phyPort, pvid);
    }

    config_commit();

    cgi_log_info("edit port pvid ok");
    
err:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }

    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return ret;
}

int ports_conv_to_phyPorts(char *ports, char *phyPorts, int len, int withCpuPort)
{
    int cnt = 0;
    int i = 0, n = 0;
    char *result = NULL;
    int cpuPort = 0;
    int phyPort = 0;
    char *delims = " ";
    uint16_t vlan_member = 0;
    uint16_t tagged_member = 0;

    result = strtok(ports, delims); 
    while(result != NULL) 
    {
        int port = 0;
        char attr = 0;

		sscanf(result, "%d%c", &port, &attr);
		
		phyPort = pannelPort_to_phyPort_xlate(port);        
		cpuPort = getCpuPort(phyPort);
                
		vlan_member |= (1 << phyPort);
        if(withCpuPort)
        {
		    vlan_member |= (1 << cpuPort);
            tagged_member |= (1 << cpuPort);
        }
        
		if(attr == 't')
		{
			tagged_member |= (1 << phyPort);
		}
		
		result = strtok(NULL, delims);
    }     

    for(i = 0; i < MAX_PHY_PORT; i ++)
	{		
		if(GET_BIT(vlan_member, i))
		{
			if(GET_BIT(tagged_member, i))
			{
				cnt += snprintf(phyPorts + cnt, len - cnt, "%s%dt", (n > 0) ? " " : "", i);
			}
			else
			{
				cnt += snprintf(phyPorts + cnt, len - cnt, "%s%d", (n > 0) ? " " : "", i);
			}
			n ++;
		}
	}

    return 0;
}

cJSON *ports_conv_to_json_arr(char *ports)
{
    char *r = NULL;
    char *delims = " ";
    int cnt = 0;
    char *portArr[MAX_PANNEL_PORT];

    r = strtok(ports, delims); 
    while(r != NULL) 
    {        
        if(cnt > MAX_PANNEL_PORT)
        {
            break;
        }
        
        portArr[cnt] = strdup(r);

        cnt ++;
		r = strtok(NULL, delims);
    }     

    return cJSON_CreateStringArray(portArr, cnt);
}

int ports_json_arr_conv_to_str(cJSON *arr, char *ports, int len)
{
    int i = 0;
    int size = 0;
    int cnt = 0;
    cJSON *item = NULL;

    if(!arr || arr->type != cJSON_Array)
    {
        return -1;
    }
    
    size = cJSON_GetArraySize(arr);
    
    for(i = 0; i < size; i ++)
    {
        item = cJSON_GetArrayItem(arr, i);
        if(!item)
        {
            break;
        }
        
        cnt += snprintf(ports + cnt, len - cnt, "%s%s", (i > 0) ? " " : "", item->valuestring);
        
    }

    return 0;
}

int vlan_entry_list()
{
    int i = 0;
    int ret = 0;
    cJSON *rObj = NULL;

    rObj = cJSON_CreateObject();
    if(!rObj)
    {
        cgi_errno = CGI_ERR_OTHER;
        return -1;        
    }

    cJSON *data = NULL;
    cJSON *entry = NULL;
    cJSON *item = NULL;

    struct vlan_attr vlan;

    data = cJSON_CreateObject();
    entry = cJSON_CreateArray();
    if(!data || !entry)
    {
        cgi_errno = CGI_ERR_OTHER;
        return -1;
    }

    int num = 0;
    num = config_get_int("ct_vlan_num");

    for(i = 0; i < num; i ++)
    {    
        item = cJSON_CreateObject();
        if(!item)
        {
            continue;
        }

        memset(&vlan, 0x0, sizeof(struct vlan_attr));

        vlan_config_get(i, &vlan);
        
        cJSON_AddNumberToObject(item, "id", i + 1);        
        cJSON_AddStringToObject(item, "name", vlan.name);
        cJSON_AddNumberToObject(item, "vid", vlan.vid);
        cJSON_AddNumberToObject(item, "prio", vlan.prio);
        cJSON_AddItemToObject(item, "ports", ports_conv_to_json_arr(vlan.ports)); 
        cJSON_AddStringToObject(item, "desc", vlan.desc);
        
        cJSON_AddItemToArray(entry, item);      
    }

    cJSON_AddNumberToObject(data, "num", i);
    cJSON_AddItemToObject(data, "entry", entry);
    cJSON_AddNumberToObject(rObj, "code", cgi_errno);
    cJSON_AddItemToObject(rObj, "data", data);

    char *res = NULL;

    res = cJSON_PrintUnformatted(rObj);
    if(!res)
    {
        return -1;
    }

    fprintf(stdout, "%s", res);
    free(res);

    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    
    return ret;
}

int vlan_entry_create(char *data, int len)
{
    int ret = 0;
    cJSON *rObj = NULL;
    cJSON *entry = NULL;
    int intVal = 0;
    char *strVal = NULL;
    int idx = 0;
    int vlan_num = 0;
    char pPorts[64] = {0};
    cJSON *portArr = NULL;
    struct vlan_attr vlan;
    
    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto end_proc;
    }

    vlan_num = config_get_int("ct_vlan_num");

    memset(&vlan, 0x0, sizeof(struct vlan_attr));
    
    entry = cJSON_GetObjectItem(rObj, "entry");
    if(!entry)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }
    
    strVal = cjson_get_string(entry, "name");
    if(strVal)
        strncpy(vlan.name, strVal, sizeof(vlan.name) -1);

    ret = cjson_get_int(entry, "vid", &intVal);
    vlan.vid = intVal;
    
    portArr = cJSON_GetObjectItem(entry, "ports");
    if(portArr)
    {
        ports_json_arr_conv_to_str(portArr, vlan.ports, sizeof(vlan.ports));        
    }
        
    strVal = cjson_get_string(entry, "desc");
    if(strVal)
        strncpy(vlan.desc, strVal, sizeof(vlan.desc) -1);

    idx = find_vlan_idx_by_vid(vlan.vid);
    if(idx >= 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_VLAN_EX;
        goto end_proc;
    }

    idx = vlan_num;

    strncpy(pPorts, vlan.ports, (sizeof(pPorts) - 1));

//    if(vlan.vid == 1 || vlan.vid == 2)
//    {
      ports_conv_to_phyPorts(pPorts, vlan.phyports, sizeof(vlan.phyports), 1);
//    }
//    else
//    {
//       ports_conv_to_phyPorts(pPorts, vlan.phyports, sizeof(vlan.phyports), 0);
//    }

    vlan_config_set(idx, &vlan);

    config_set_int("ct_vlan_num", (vlan_num + 1));

    config_commit();

    cgi_log_info("add vlan %d entry ok", vlan.vid);

end_proc:
    
    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    
    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return ret;
}

/* 配置删除后需要重新对齐 */
int vlan_entry_del(char *data, int len)
{
    int i = 0;
    int ret = 0;
    int arrNum = 0;
    cJSON *rObj = NULL;
    cJSON *entry = NULL;
    cJSON *item = NULL;

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto end_proc;
    }

    entry = cJSON_GetObjectItem(rObj, "entry");
    if(entry->type != cJSON_Array)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }

    int num, vlan_num = 0;
    num = vlan_num = config_get_int("ct_vlan_num");

    arrNum = cJSON_GetArraySize(entry);

    int vid, idx;
    
    for(i = 0; i < arrNum; i ++)
    {
        item = cJSON_GetArrayItem(entry, i);
        if(!item)
        {
            continue;
        }

        ret = cjson_get_int(item, "vid", &vid);
        if(ret < 0)
        {
            cgi_errno = CGI_ERR_PARAM;
            continue;
        }

        idx = find_vlan_idx_by_vid(vid);
        if(idx < 0)
        {   
            cgi_errno = CGI_ERR_VLAN_NF;
            continue;
        }

        vlan_config_del(idx);

        cgi_log_info("delete vlan %d entry ok", vid);

        vlan_num --;
    }

    vlan_config_align(num);

    config_set_int("ct_vlan_num", vlan_num);

    config_commit();

end_proc:

    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    
    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return ret;
}

int vlan_entry_edit(char *data, int len)
{
    int ret = 0;
    int idx = 0;
    cJSON *rObj = NULL;
    cJSON *entry = NULL;
    int intVal = 0;
    char *strVal = NULL;    
    char phyPorts[64] = {0};
    char pPorts[64] = {0};
    struct vlan_attr vlan;

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto end_proc;
    }


    memset(&vlan, 0x0, sizeof(struct vlan_attr));
    
    entry = cJSON_GetObjectItem(rObj, "entry");
    if(!entry)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }
    
    strVal = cjson_get_string(entry, "name");
    if(!strVal)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }
    strncpy(vlan.name, strVal, sizeof(vlan.name) -1);
    
    ret = cjson_get_int(entry, "vid", &intVal);
    if(ret < 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }
    
    vlan.vid = intVal;

    cJSON *portArr = NULL;
    
    portArr = cJSON_GetObjectItem(entry, "ports");
    if(!portArr)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto end_proc;
    }

    ports_json_arr_conv_to_str(portArr, vlan.ports, sizeof(vlan.ports));

    strVal = cjson_get_string(entry, "desc");
    if(strVal)
    {
        strncpy(vlan.desc, strVal, sizeof(vlan.desc) -1);
    }
    
    idx = find_vlan_idx_by_vid(vlan.vid);
    if(idx < 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_VLAN_NF;
        goto end_proc;
    }

    strncpy(pPorts, vlan.ports, sizeof(pPorts) - 1);

//    if(vlan.vid == 1 || vlan.vid == 2)
//    {
        ports_conv_to_phyPorts(pPorts, vlan.phyports, sizeof(vlan.phyports), 1);        
//    }
//    else
//    {
//        ports_conv_to_phyPorts(pPorts, vlan.phyports, sizeof(vlan.phyports), 0);
//    }

    vlan_config_set(idx, &vlan);

    config_commit();

    cgi_log_info("edit vlan %d entry info ok", vlan.vid);

end_proc:

    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    
    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return ret;
}

int vlan_main(char *cmd, char *param)
{
    int ret = 0;
    
    if(strcmp(cmd, "port_vlan_list") == 0)
    {
        return port_vlan_list();
    } 
    else if(strcmp(cmd, "vlan_entry_list") == 0)
    {
        return vlan_entry_list();            
    }

    if(param != NULL)
    {
        if(strcmp(cmd, "edit_port_vlan") == 0)
        {    
            ret = port_pvid_edit(param, strlen(param));
        }
        else if(strcmp(cmd, "create_vlan") == 0)
        {        
            ret = vlan_entry_create(param, strlen(param));
        } 
        else if(strcmp(cmd, "del_vlan") == 0)   
        {        
            ret = vlan_entry_del(param, strlen(param));
        }
        else if(strcmp(cmd, "edit_vlan") == 0)
        {
            ret = vlan_entry_edit(param, strlen(param));
        }

        if(ret == 0)
        {
            ret = wait_eval(1, "/usr/sbin/cgi_reload.sh switch_config");
        }
    }
    
    return ret;
}
