/*
 * ipsec web 与 cli 配置接口实现
 * 
 * 增，删，改，查
 * 
 * 存储基于nvram
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "utils.h"
#include "ipsec.h"

#define IPSEC_NVRAM

#define LIFETIME_MIN (10 * 60)
#define LIFETIME_MAX (604800)

static char *ipsec_ikev[] = {
    "ike",
    "ikev1",
    "ikev2",
    NULL
};

static char *ipsec_cipher[] = {
    "3des",
    "aes128",    
    "aes192",
    "aes256",  
    NULL
};

static char *ipsec_hash[] = {
    "md5",
    "sha1",
    "sha256",
    "sha384",
    "sha512",
    NULL
};

static char *ipsec_dhgroup[] = {
    "no",
    "dh1",  /* modp768 */
    "dh2",  /* modp1024 */   
    "dh5",  /* modp1536 */
    "dh14", /* modp2048 */
    "dh15", /* modp3072 */
    "dh16", /* modp4096 */
    "dh17", /* modp6144 */
    "dh18", /* modp8192 */
    "dh19", /* ecp256 */
    "dh20", /* ecp384 */
    "dh21", /* ecp521 */
    "dh22", /* modp1024s160 */
    "dh23", /* modp2048s224 */
    "dh24", /* modp2048s256 */
    NULL
};

static char *ipsec_exch[] = {
    "main",
    "aggressive",
    NULL
};

static char *ipsec_nego[] = {
    "initiator",
    "responder",
    NULL
};

static char *ipsec_proto[] = {
    "esp",
    "ah",
    NULL
};

static char *ipsec_encap[] = {
    "tunnel",
    "transport",
    NULL
};

void ipsec_policy_config_get(int idx, struct ipsec_policy *cfg)
{
    cfg->enabled = config_get_int_ext("ct_ipsec_enabled", idx);
    strncpy(cfg->name, config_get_ext("ct_ipsec_name", idx), sizeof(cfg->name) - 1);
    strncpy(cfg->ikev, config_get_ext("ct_ipsec_ikev", idx), sizeof(cfg->ikev) - 1);
    strncpy(cfg->mode, config_get_ext("ct_ipsec_mode", idx), sizeof(cfg->mode) - 1);
    strncpy(cfg->local_subnet, config_get_ext("ct_ipsec_leftsubnet", idx), sizeof(cfg->local_subnet) - 1);
    strncpy(cfg->local_netmask, config_get_ext("ct_ipsec_leftnetmask", idx), sizeof(cfg->local_netmask) - 1);
    strncpy(cfg->remote_host, config_get_ext("ct_ipsec_right", idx), sizeof(cfg->remote_host) - 1);
    strncpy(cfg->remote_subnet, config_get_ext("ct_ipsec_rightsubnet", idx), sizeof(cfg->remote_subnet) - 1);
    strncpy(cfg->remote_netmask, config_get_ext("ct_ipsec_rightnetmask", idx), sizeof(cfg->remote_netmask) - 1);
    strncpy(cfg->psk, config_get_ext("ct_ipsec_psk", idx), sizeof(cfg->psk) - 1);
    /* phase1 */
    strncpy(cfg->ike_proposal_1, config_get_ext("ct_ipsec_ike_proposal1", idx), sizeof(cfg->ike_proposal_1) - 1);
    strncpy(cfg->ike_proposal_2, config_get_ext("ct_ipsec_ike_proposal2", idx), sizeof(cfg->ike_proposal_2) - 1);
    strncpy(cfg->ike_proposal_3, config_get_ext("ct_ipsec_ike_proposal3", idx), sizeof(cfg->ike_proposal_3) - 1);
    strncpy(cfg->ike_proposal_4, config_get_ext("ct_ipsec_ike_proposal4", idx), sizeof(cfg->ike_proposal_4) - 1);
    strncpy(cfg->exchange_mode, config_get_ext("ct_ipsec_exchange_mode", idx), sizeof(cfg->exchange_mode) - 1);
    strncpy(cfg->negotiate_mode, config_get_ext("ct_ipsec_negotiate_mode", idx), sizeof(cfg->negotiate_mode) - 1);
    cfg->ikelifetime = config_get_int_ext("ct_ipsec_ikelifetime", idx);
    cfg->dpd_enable = config_get_int_ext("ct_ipsec_dpd_enable", idx);
    cfg->dpd_interval = config_get_int_ext("ct_ipsec_dpd_interval", idx);
    /* phase2 */
    strncpy(cfg->protocol, config_get_ext("ct_ipsec_protocol", idx), sizeof(cfg->protocol) - 1);
    strncpy(cfg->encap_mode, config_get_ext("ct_ipsec_encap_mode", idx), sizeof(cfg->encap_mode) - 1);
    strncpy(cfg->ph2_proposal_1, config_get_ext("ct_ipsec_ph2_proposal1", idx), sizeof(cfg->ph2_proposal_1) - 1);
    strncpy(cfg->ph2_proposal_2, config_get_ext("ct_ipsec_ph2_proposal2", idx), sizeof(cfg->ph2_proposal_2) - 1);
    strncpy(cfg->ph2_proposal_3, config_get_ext("ct_ipsec_ph2_proposal3", idx), sizeof(cfg->ph2_proposal_3) - 1);
    strncpy(cfg->ph2_proposal_4, config_get_ext("ct_ipsec_ph2_proposal4", idx), sizeof(cfg->ph2_proposal_4) - 1);
    strncpy(cfg->pfs, config_get_ext("ct_ipsec_pfs", idx), sizeof(cfg->pfs) - 1);
    cfg->salifetime = config_get_int_ext("ct_ipsec_salifetime", idx);

    /* 默认走ikev2 */
    if (cfg->ikev[0] == '\0')
    {
        strncpy(cfg->ikev, "ikev2", sizeof(cfg->ikev));
    }

    /* 高级参数默认值 */
    if (cfg->ike_proposal_1[0] == '\0' || cfg->ph2_proposal_1[0] == '\0')
    {
        strncpy(cfg->ike_proposal_1, "sha1-aes128-dh2", sizeof(cfg->ike_proposal_1) - 1);
        strncpy(cfg->exchange_mode, "main", sizeof(cfg->exchange_mode) - 1);
        strncpy(cfg->negotiate_mode, "initiator", sizeof(cfg->negotiate_mode) - 1);
        cfg->ikelifetime = 86400;
        cfg->dpd_enable = 1;
        cfg->dpd_interval = 30;

        strncpy(cfg->protocol, "esp", sizeof(cfg->protocol) - 1);
        strncpy(cfg->encap_mode, "tunnel", sizeof(cfg->encap_mode) - 1);
        strncpy(cfg->ph2_proposal_1, "sha1-aes128", sizeof(cfg->ph2_proposal_1) - 1);
        strncpy(cfg->pfs, "no", sizeof(cfg->pfs) - 1);
        cfg->salifetime = 3600;
    }
}

void ipsec_policy_config_set(int idx, struct ipsec_policy *cfg)
{
    config_set_int_ext("ct_ipsec_enabled", idx, cfg->enabled);
    config_set_ext("ct_ipsec_name", idx, cfg->name);
    config_set_ext("ct_ipsec_ikev", idx, cfg->ikev);
    config_set_ext("ct_ipsec_mode", idx, cfg->mode);
    config_set_ext("ct_ipsec_leftsubnet", idx, cfg->local_subnet);
    config_set_ext("ct_ipsec_leftnetmask", idx, cfg->local_netmask);
    config_set_ext("ct_ipsec_right", idx, cfg->remote_host);
    config_set_ext("ct_ipsec_rightsubnet", idx, cfg->remote_subnet);
    config_set_ext("ct_ipsec_rightnetmask", idx, cfg->remote_netmask);
    config_set_ext("ct_ipsec_psk", idx, cfg->psk);
    /* phase1 */
    config_set_ext("ct_ipsec_ike_proposal1", idx, cfg->ike_proposal_1);
    config_set_ext("ct_ipsec_ike_proposal2", idx, cfg->ike_proposal_2);
    config_set_ext("ct_ipsec_ike_proposal3", idx, cfg->ike_proposal_3);
    config_set_ext("ct_ipsec_ike_proposal4", idx, cfg->ike_proposal_4);
    config_set_ext("ct_ipsec_exchange_mode", idx, cfg->exchange_mode);
    config_set_ext("ct_ipsec_negotiate_mode", idx, cfg->negotiate_mode);
    config_set_int_ext("ct_ipsec_ikelifetime", idx, cfg->ikelifetime);
    config_set_int_ext("ct_ipsec_dpd_enable", idx, cfg->dpd_enable);
    config_set_int_ext("ct_ipsec_dpd_interval", idx, cfg->dpd_interval);
    /* phase2 */
    config_set_ext("ct_ipsec_protocol", idx, cfg->protocol);
    config_set_ext("ct_ipsec_encap_mode", idx, cfg->encap_mode);
    config_set_ext("ct_ipsec_ph2_proposal1", idx, cfg->ph2_proposal_1);
    config_set_ext("ct_ipsec_ph2_proposal2", idx, cfg->ph2_proposal_2);
    config_set_ext("ct_ipsec_ph2_proposal3", idx, cfg->ph2_proposal_3);
    config_set_ext("ct_ipsec_ph2_proposal4", idx, cfg->ph2_proposal_4);
    config_set_ext("ct_ipsec_pfs", idx, cfg->pfs);    
    config_set_int_ext("ct_ipsec_salifetime", idx, cfg->salifetime);
}

void ipsec_policy_config_del(int idx)
{
    config_unset_ext("ct_ipsec_enabled", idx);
    config_unset_ext("ct_ipsec_name", idx);
    config_unset_ext("ct_ipsec_ikev", idx);
    config_unset_ext("ct_ipsec_mode", idx);
    config_unset_ext("ct_ipsec_leftsubnet", idx);
    config_unset_ext("ct_ipsec_leftnetmask", idx);
    config_unset_ext("ct_ipsec_right", idx);
    config_unset_ext("ct_ipsec_rightsubnet", idx);
    config_unset_ext("ct_ipsec_rightnetmask", idx);
    config_unset_ext("ct_ipsec_psk", idx);
    /* phase1 */
    config_unset_ext("ct_ipsec_ike_proposal1", idx);
    config_unset_ext("ct_ipsec_ike_proposal2", idx);
    config_unset_ext("ct_ipsec_ike_proposal3", idx);
    config_unset_ext("ct_ipsec_ike_proposal4", idx);
    config_unset_ext("ct_ipsec_exchange_mode", idx);
    config_unset_ext("ct_ipsec_negotiate_mode", idx);
    config_unset_ext("ct_ipsec_ikelifetime", idx);
    config_unset_ext("ct_ipsec_dpd_enable", idx);
    config_unset_ext("ct_ipsec_dpd_interval", idx);
    /* phase2 */
    config_unset_ext("ct_ipsec_protocol", idx);
    config_unset_ext("ct_ipsec_encap_mode", idx);
    config_unset_ext("ct_ipsec_ph2_proposal1", idx);
    config_unset_ext("ct_ipsec_ph2_proposal2", idx);
    config_unset_ext("ct_ipsec_ph2_proposal3", idx);
    config_unset_ext("ct_ipsec_ph2_proposal4", idx);
    config_unset_ext("ct_ipsec_pfs", idx);
    config_unset_ext("ct_ipsec_salifetime", idx);
}

int ipsec_policy_config_align(int orig_num)
{
    int i = 0, j = 0;
    int r_idx = 0;
    struct ipsec_policy cfg;

    for(i = 0; i < orig_num; i ++)
    {
        memset(&cfg, 0x0, sizeof(ipsec_policy_t));

        ipsec_policy_config_get(i, &cfg);

        if(cfg.name[0] == '\0')
        {
            j ++;
        }
        else
        {
            r_idx = i - j;
            if(j > 0)
            {
                ipsec_policy_config_set(r_idx, &cfg);
                ipsec_policy_config_del(i);
            }
        }
    }

    return 0;
}

int parse_json_ipsec_config(struct ipsec_policy *cfg, cJSON *data)
{
    int ret = 0;
    int intVal = 0;
    char *strVal = NULL;

    ret = cjson_get_int(data, "status", &intVal);
    if (ret < 0)
    {
        ret = -1;
        goto err;
    }
    cfg->enabled = intVal;

    strVal = cjson_get_string(data, "name");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->name, strVal, sizeof(cfg->name) - 1);

    strVal = cjson_get_string(data, "ikev");
    if (!strVal)
    {
        ret = -1;
        goto err;
    }
    strncpy(cfg->ikev, strVal, sizeof(cfg->ikev) - 1);
    
    strVal = cjson_get_string(data, "mode");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->mode, strVal, sizeof(cfg->mode) - 1);

    strVal = cjson_get_string(data, "local_subnet");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->local_subnet, strVal, sizeof(cfg->local_subnet) - 1);

    strVal = cjson_get_string(data, "local_netmask");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->local_netmask, strVal, sizeof(cfg->local_netmask) - 1);

    strVal = cjson_get_string(data, "remote_host");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->remote_host, strVal, sizeof(cfg->remote_host) - 1);

    strVal = cjson_get_string(data, "remote_subnet");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->remote_subnet, strVal, sizeof(cfg->remote_subnet) - 1);

    strVal = cjson_get_string(data, "remote_netmask");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->remote_netmask, strVal, sizeof(cfg->remote_netmask) - 1);

    strVal = cjson_get_string(data, "psk");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->psk, strVal, sizeof(cfg->psk) - 1);

    /* 高级参数phase1 */
    strVal = cjson_get_string(data, "ike_proposal_1");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->ike_proposal_1, strVal, sizeof(cfg->ike_proposal_1) - 1);

    strVal = cjson_get_string(data, "ike_proposal_2");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->ike_proposal_2, strVal, sizeof(cfg->ike_proposal_2) - 1);

    strVal = cjson_get_string(data, "ike_proposal_3");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->ike_proposal_3, strVal, sizeof(cfg->ike_proposal_3) - 1);

    strVal = cjson_get_string(data, "ike_proposal_4");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->ike_proposal_4, strVal, sizeof(cfg->ike_proposal_4) - 1);

    strVal = cjson_get_string(data, "exchange_mode");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->exchange_mode, strVal, sizeof(cfg->exchange_mode) - 1);

    strVal = cjson_get_string(data, "negotiate_mode");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->negotiate_mode, strVal, sizeof(cfg->negotiate_mode) - 1);

    ret = cjson_get_int(data, "ikelifetime", &intVal);
    if (ret < 0)
    {
        ret = -1;
        goto err;
    }
    cfg->ikelifetime = intVal;

    ret = cjson_get_int(data, "dpd_enable", &intVal);
    if (ret < 0)
    {
        ret = -1;
        goto err;
    }
    cfg->dpd_enable = intVal;    

    ret = cjson_get_int(data, "dpd_interval", &intVal);
    if (ret < 0)
    {
        ret = -1;
        goto err;
    }
    
    cfg->dpd_interval = intVal;    

    /* 高级参数phase2 */
    strVal = cjson_get_string(data, "protocol");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->protocol, strVal, sizeof(cfg->protocol) - 1);

    strVal = cjson_get_string(data, "encap_mode");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->encap_mode, strVal, sizeof(cfg->encap_mode) - 1);
    
    strVal = cjson_get_string(data, "ph2_proposal_1");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->ph2_proposal_1, strVal, sizeof(cfg->ph2_proposal_1) - 1);

    strVal = cjson_get_string(data, "ph2_proposal_2");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->ph2_proposal_2, strVal, sizeof(cfg->ph2_proposal_2) - 1);

    strVal = cjson_get_string(data, "ph2_proposal_3");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->ph2_proposal_3, strVal, sizeof(cfg->ph2_proposal_3) - 1);

    strVal = cjson_get_string(data, "ph2_proposal_4");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->ph2_proposal_4, strVal, sizeof(cfg->ph2_proposal_4) - 1);

    strVal = cjson_get_string(data, "pfs");
    if(!strVal)
    {
        ret = -1;
        goto err;        
    }
    strncpy(cfg->pfs, strVal, sizeof(cfg->pfs) - 1);


    ret = cjson_get_int(data, "salifetime", &intVal);
    if (ret < 0)
    {
        ret = -1;
        goto err;
    }
    cfg->salifetime = intVal;
    
err:

    return ret;    
}

int check_enum_string(char **E_str, char *val2)
{
    char **val = NULL;

    for (val = E_str; *val != NULL; val ++)
    {
        if (strcmp(*val, val2) == 0)
        {
            return 0;
        }
    }

    return -1;
}

int check_ike_proposal(char *proposal)
{
    int ret = 0;
    char hash[10] = {0};
    char cipher[10] = {0};
    char dh[10] = {0};

    ret = sscanf(proposal, "%[^-]-%[^-]-%[^-]", hash, cipher, dh);
    if (ret != 3)
    {
        return -1;
    }

    ret = check_enum_string(ipsec_hash, hash);    
    ret += check_enum_string(ipsec_cipher, cipher);
    ret += check_enum_string(ipsec_dhgroup, dh);
    if (ret < 0)
    {
        return -1;       
    }

    return 0;
}

int check_ph2_proposal(char *proposal)
{
    int ret = -1;
    char hash[10] = {0};
    char cipher[10] = {0};

    ret = sscanf(proposal, "%[^-]-%[^-]", hash, cipher);
    if (ret == 1)
    {
        return check_enum_string(ipsec_hash, hash);
    }
    else if (ret == 2)
    {
        ret = check_enum_string(ipsec_hash, hash);
        ret += check_enum_string(ipsec_cipher, cipher);
    }

    return ret;
}

int check_lifetime(int lifetime, int min, int max)
{
    if (lifetime < min || lifetime > max)
    {
        return -1;
    }

    return 0;
}

int ipsec_conf_check(struct ipsec_policy *cfg)
{
    int ret = 0;

    ret += check_enum_string(ipsec_ikev, cfg->ikev);

    ret += check_lifetime(cfg->ikelifetime, LIFETIME_MIN, LIFETIME_MAX);
    
    ret += check_ike_proposal(cfg->ike_proposal_1);
    
    if (cfg->ike_proposal_2[0] != '\0') {
        ret += check_ike_proposal(cfg->ike_proposal_2);
    }
    if (cfg->ike_proposal_3[0] != '\0') {
        ret += check_ike_proposal(cfg->ike_proposal_3);
    }    
    if (cfg->ike_proposal_4[0] != '\0') {
        ret += check_ike_proposal(cfg->ike_proposal_4);
    }

    ret += check_enum_string(ipsec_exch, cfg->exchange_mode);
    ret += check_enum_string(ipsec_nego, cfg->negotiate_mode);
    ret += check_enum_string(ipsec_proto, cfg->protocol);
    ret += check_enum_string(ipsec_encap, cfg->encap_mode);

    ret += check_lifetime(cfg->salifetime, LIFETIME_MIN, LIFETIME_MAX);

    ret += check_ph2_proposal(cfg->ph2_proposal_1);
    
    if (cfg->ph2_proposal_2[0] != '\0') {
        ret += check_ph2_proposal(cfg->ph2_proposal_2);
    }
    if (cfg->ph2_proposal_3[0] != '\0') {
        ret += check_ph2_proposal(cfg->ph2_proposal_3);
    }
    if (cfg->ph2_proposal_4[0] != '\0') {
        ret += check_ph2_proposal(cfg->ph2_proposal_4);
    }
    
    ret += check_enum_string(ipsec_dhgroup, cfg->pfs);

    return ret;
}

#define IPSEC_API

/* ipsec status conn$idx */
int ipsec_cli_status(int idx, struct ipsec_status *stats)
{
    FILE *fp = NULL;
    char cmd[128] = {0};
    char buf[256] = {0};
    char *pt = NULL;

    snprintf(cmd, sizeof(cmd), "ipsec statusall conn%d 2>/dev/null", idx);

    fp = popen(cmd, "r");
    if (!fp)
    {
        return -1;
    }

    while(fgets(buf, sizeof(buf), fp) != NULL)
    {
        if (strstr(buf, "INSTALLED"))
        {
            stats->status = 1;    
        }

        if ((pt = strstr(buf, "ESP SPIs:")))
        {
            sscanf(pt, "ESP SPIs: %[^_]_i %[^_]_o", stats->spi_in, stats->spi_out);
        }
        else if (strstr(buf, "bytes_i") && strstr(buf, "bytes_o"))
        {
            sscanf(buf, "%*[^,], %lu %*[^,], %lu %*[^,]", &stats->bytes_in, &stats->bytes_out);
        }
    }

    pclose(fp);

    return 0;
}

int ipsec_status_get()
{    
    int i = 0;
    int num = 0;
    int ret = 0;
    struct ipsec_policy cfg;
    struct ipsec_status stats;

    num = config_get_int("ipsec_num");
    
    webs_write(stdout, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(stdout, "\"status\":[");

    for (i = 0; i < num; i ++)
    {
        memset(&cfg, 0x0, sizeof(ipsec_policy_t));
        
        ipsec_policy_config_get(i, &cfg);

        memset(&stats, 0x0, sizeof(struct ipsec_status));
        ret = ipsec_cli_status(i, &stats);
        if (ret < 0)
        {
            //do nothing
        }

        webs_write(stdout, "%s{", ((i > 0) ? "," : ""));
        webs_write(stdout, "\"id\":%d", i + 1);
        webs_write(stdout, ",\"name\":\"%s\"", cfg.name);
        webs_write(stdout, ",\"conn_status\":\"%d\"", stats.status);
        webs_write(stdout, ",\"bytes_in\":%lu", stats.bytes_in);
        webs_write(stdout, ",\"bytes_out\":%lu", stats.bytes_out);
        webs_write(stdout, ",\"spi_in\":\"%s\"", stats.spi_in);        
        webs_write(stdout, ",\"spi_out\":\"%s\"", stats.spi_out);
        webs_write(stdout, "}");
    }
    
    webs_write(stdout, "]}}");

    return 0;
}

int ipsec_log_get()
{
    int len = 0;
    char buff[1024] = {0};
    FILE *fp = NULL;

    fp = fopen("/var/log/ipsec.log", "r");
    if(!fp)
    {
        return -1;
    }

    while (1)
    {
        len = fread(buff, 1, sizeof(buff), fp);
        if(len <= 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            break;
        }

        fwrite(buff, 1, len, stdout);
    }

    fclose(fp);

    return 0;
}

int ipsec_log_flush()
{
    wait_eval(1, "echo \"\" >/var/log/ipsec.log");
    webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return 0;
}

int ipsec_policy_get()
{
    int i = 0;
    int num = 0;
    struct ipsec_policy cfg;

    num = config_get_int("ipsec_num");

    webs_write(stdout, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(stdout, "\"num\":%d,\"policy_list\":[", num);
    
    for (i = 0; i < num; i ++)
    {
        memset(&cfg, 0x0, sizeof(ipsec_policy_t));

        ipsec_policy_config_get(i, &cfg);

        webs_write(stdout, "%s{", ((i > 0) ? "," : ""));
        webs_write(stdout, "\"id\":%d"
            ",\"status\":%d"
            ",\"name\":\"%s\""
            ",\"ikev\":\"%s\""
            ",\"mode\":\"%s\""
            ",\"local_subnet\":\"%s\""
            ",\"local_netmask\":\"%s\""
            ",\"remote_host\":\"%s\""
            ",\"remote_subnet\":\"%s\""
            ",\"remote_netmask\":\"%s\""
            ",\"psk\":\"%s\""
        	",\"ike_proposal_1\":\"%s\""
			",\"ike_proposal_2\":\"%s\""
			",\"ike_proposal_3\":\"%s\""
			",\"ike_proposal_4\":\"%s\""
			",\"exchange_mode\":\"%s\""
			",\"negotiate_mode\":\"%s\""
			",\"ikelifetime\":%d"
			",\"dpd_enable\":%d"
			",\"dpd_interval\":%d"
			",\"protocol\":\"%s\""
			",\"encap_mode\":\"%s\""
			",\"ph2_proposal_1\":\"%s\""
			",\"ph2_proposal_2\":\"%s\""
			",\"ph2_proposal_3\":\"%s\""
			",\"ph2_proposal_4\":\"%s\""
			",\"pfs\":\"%s\""
			",\"salifetime\":%d",
            i + 1, 
            cfg.enabled, 
            cfg.name,
            cfg.ikev,
            cfg.mode, 
            cfg.local_subnet, 
            cfg.local_netmask, 
            cfg.remote_host,
            cfg.remote_subnet,
            cfg.remote_netmask,
            cfg.psk,
            cfg.ike_proposal_1,
            cfg.ike_proposal_2,
            cfg.ike_proposal_3,
            cfg.ike_proposal_4,
            cfg.exchange_mode,
            cfg.negotiate_mode,
            cfg.ikelifetime,
            cfg.dpd_enable,
            cfg.dpd_interval,
            cfg.protocol,
            cfg.encap_mode,
            cfg.ph2_proposal_1,
            cfg.ph2_proposal_2,
            cfg.ph2_proposal_3,
            cfg.ph2_proposal_4,
            cfg.pfs,
            cfg.salifetime
        );
        
        webs_write(stdout, "}");
    }
    
    webs_write(stdout, "]}}");

    return 0;
}

int ipsec_policy_add(char *data, int len)
{
    int ret = 0;
    int idx = 0;
    cJSON *rObj = NULL;
    int ipsec_num = 0;
    struct ipsec_policy cfg;

    ipsec_num = config_get_int("ipsec_num");
    if (ipsec_num >= MAX_IPSEC_TUNNEL)
    {
        cgi_errno = CGI_ERR_LIMITED;
        goto _exit;
    }

    rObj = cJSON_Parse(data);
    if (!rObj)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto _exit;
    }

    memset(&cfg, 0x0, sizeof(ipsec_policy_t));
    ret = parse_json_ipsec_config(&cfg, rObj);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto _exit;
    }

    /* config check */
    ret = ipsec_conf_check(&cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto _exit;
    }
    
    idx = ipsec_num;
    ipsec_policy_config_set(idx, &cfg);
    
    ipsec_num ++;
    config_set_int("ipsec_num", ipsec_num);

    config_commit();
    
_exit:
    if (cgi_errno == CGI_ERR_OK)
    {
        cgi_log_ipsec("Add IPSec Policy %s Success.", cfg.name);    
    }
    else
    {
        cgi_log_ipsec("Add IPSec Policy %s Failed.", cfg.name);
    }

    if(!rObj)
    {
        cJSON_Delete(rObj);
    }
    
    webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return 0;
}

int ipsec_policy_edit(char *data, int len)
{
    int ret = 0;
    int idx = 0;
    cJSON *rObj = NULL;
    int ipsec_num = 0;
    struct ipsec_policy cfg;

    ipsec_num = config_get_int("ipsec_num");

    rObj = cJSON_Parse(data);
    if (!rObj)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto _exit;
    }

    ret = cjson_get_int(rObj, "id", &idx);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto _exit;
    }

    if (idx <= 0 || idx > ipsec_num)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto _exit;
    }

    memset(&cfg, 0x0, sizeof(ipsec_policy_t));
    ret = parse_json_ipsec_config(&cfg, rObj);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto _exit;
    }

    /* config check */
    ret = ipsec_conf_check(&cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto _exit;
    }

    idx = idx - 1;
    ipsec_policy_config_set(idx, &cfg);

    config_commit();

_exit:

    if (cgi_errno == CGI_ERR_OK)
    {
        cgi_log_ipsec("Edit IPSec Policy %s Success.", cfg.name);    
    }
    else
    {
        cgi_log_ipsec("Edit IPSec Policy %s Failed.", cfg.name);
    }

    if(!rObj)
    {
        cJSON_Delete(rObj);
    }

    webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return 0;
}

int ipsec_policy_del(char *data, int len)
{
    int i = 0;
    int idx = 0;
    int ret = 0;
    cJSON *rObj = NULL;
    cJSON *jsonVal = NULL;
    cJSON *item = NULL;
    int del_num = 0;
    int orig_num = 0;
    int ipsec_num = 0;

    ipsec_num = config_get_int("ipsec_num");
    orig_num = ipsec_num;

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        cgi_errno = CGI_ERR_OTHER;
        goto _exit;
    }

    jsonVal = cJSON_GetObjectItem(rObj, "policy_list");
    if(!jsonVal || jsonVal->type != cJSON_Array)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto _exit;
    }

    del_num = cJSON_GetArraySize(jsonVal);
    
    for(i = 0; i < del_num; i ++)
    {
        item = cJSON_GetArrayItem(jsonVal, i);
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

        if (idx <= 0 || idx > orig_num)
        {
            cgi_errno = CGI_ERR_PARAM;
            continue;
        }

        ipsec_policy_config_del(idx - 1);

        ipsec_num --;
    }

    config_set_int("ipsec_num", ipsec_num);
    ipsec_policy_config_align(orig_num);
 
    config_commit();
    
_exit:
    if (cgi_errno == CGI_ERR_OK)
    {
        cgi_log_ipsec("Delete IPSec Policy Success.");
    }
    else
    {
        cgi_log_ipsec("Delete IPSec Policy Failed.");
    }

    if(!rObj)
    {
        cJSON_Delete(rObj);
    }
    
    webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return 0;
}

int ipseclog_main(char *cmd, char *data)
{
    return ipsec_log_get();
}

int ipsec_main(char *cmd, char *data)
{
    int ret = 0;

    if (!cmd)
    {
        return -1;
    }

    if (strcmp(cmd, "get_ipsec_policy") == 0)
    {
        return ipsec_policy_get();
    } 
    else if (strcmp(cmd, "get_ipsec_status") == 0)
    {
        return ipsec_status_get();
    }
    else if (strcmp(cmd, "get_ipsec_log") == 0)
    {
        return ipsec_log_get();
    }
    else if (strcmp(cmd, "flush_ipsec_log") == 0)
    {
        return ipsec_log_flush();
    }

    if (data != NULL)
    {
        if (strcmp(cmd, "add_ipsec_policy") == 0)
        {
            ret = ipsec_policy_add(data, strlen(data));
        }
        else if (strcmp(cmd, "edit_ipsec_policy") == 0)
        {
            ret = ipsec_policy_edit(data, strlen(data));
        }
        else if (strcmp(cmd, "del_ipsec_policy") == 0)
        {
            ret = ipsec_policy_del(data, strlen(data));
        }

        if (ret == 0)
        {
            ret = wait_eval(1, "/etc/init.d/ipsec restart");
        }
    }

    return 0;
}
