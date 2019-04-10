#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "nmap_scan.h"

void nmap_web_config_get(nmap_config_t *cfg)
{    
    cfg->enable = config_get_int("nmap_enable");
    cfg->manual = config_get_int("manual");
    cfg->scan_depth = config_get_int("scan_depth");
    cfg->process_num = config_get_int("process_num");
    cfg->retry_count = config_get_int("retry_count");
    cfg->timeout = config_get_int("scan_timeout");
    cfg->scan_rate = config_get_int("scan_rate");
    strncpy(cfg->port_pool, config_get("port_pool"), sizeof(cfg->port_pool) - 1);
    strncpy(cfg->ip_pool, config_get("ip_pool"), sizeof(cfg->ip_pool) - 1);
}

void nmap_web_config_set(nmap_config_t *cfg)
{
    config_set_int("nmap_enable", cfg->enable);
	if(cfg->enable == 1)
	{
		config_set_int("manual", cfg->manual);
	    config_set_int("scan_depth", cfg->scan_depth);
	    config_set_int("process_num", cfg->process_num);
	    config_set_int("retry_count", cfg->retry_count);
	    config_set_int("scan_timeout", cfg->timeout);
	    config_set_int("scan_rate", cfg->scan_rate);
	    config_set("ip_pool", cfg->ip_pool);
	    config_set("port_pool", cfg->port_pool);
	}
}

int web_nmap_get()
{
    nmap_config_t cfg;

    memset(&cfg, 0x0, sizeof(nmap_config_t));
    nmap_web_config_get(&cfg);
    
    webs_write(stdout, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(stdout, "\"web_nmap\":{"
							"\"enable\":%d,"
							"\"manual\":%d," 
							"\"ip_pool\":\"%s\","
							"\"scan_depth\":%d,"
							"\"process_num\":%d,"
							"\"retry_count\":%d,"
							"\"timeout\":%d,"
							"\"scan_rate\":%d,"
							"\"port_pool\": \"%s\"}}}",
						cfg.enable, cfg.manual, cfg.ip_pool, cfg.scan_depth,
						cfg.process_num, cfg.retry_count, cfg.timeout,
						cfg.scan_rate, cfg.port_pool);
    
    return 0;
}

int parse_json_web_nmap(cJSON *item, nmap_config_t *cfg)
{
    int ret = 0;
    int intVal = 0;
	char *charVal = NULL;

    ret = cjson_get_int(item, "enable", &intVal);
    if(ret < 0)
    {
        return -1;
    }
    cfg->enable = intVal;

	if(cfg->enable == 1)
	{
	    ret = cjson_get_int(item, "manual", &intVal);
	    if(ret < 0)
	    {
	        return -1;
	    }
	    cfg->manual = intVal;
		
	    ret = cjson_get_int(item, "scan_depth", &intVal);
	    if(ret < 0)
	    {
	        return -1;
	    }
	    cfg->scan_depth = intVal;
		
	    ret = cjson_get_int(item, "process_num", &intVal);
	    if(ret < 0)
	    {
	        return -1;
	    }
	    cfg->process_num = intVal;
		
		ret = cjson_get_int(item, "retry_count", &intVal);
	    if(ret < 0)
	    {
	        return -1;
	    }
	    cfg->retry_count = intVal;
		
	    ret = cjson_get_int(item, "timeout", &intVal);
	    if(ret < 0)
	    {
	        return -1;
	    }
	    cfg->timeout = intVal;
		
		ret = cjson_get_int(item, "scan_rate", &intVal);
	    if(ret < 0)
	    {
	        return -1;
	    }
	    cfg->scan_rate = intVal;
		
	    charVal = cjson_get_string(item, "ip_pool");
	    if(charVal == NULL)
	    {
	        return -1;
	    }
		strncpy(cfg->ip_pool, charVal, sizeof(cfg->ip_pool) - 1);
		
	    charVal = cjson_get_string(item, "port_pool");
	    if(charVal == NULL)
	    {
	        return -1;
	    }
		strncpy(cfg->port_pool, charVal, sizeof(cfg->port_pool) - 1);
	}
    return 0;
}


int web_nmap_set(char *data, int len)
{
    int ret = 0;
    cJSON *rObj = NULL;
    cJSON *config = NULL;
    nmap_config_t cfg;
        
    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    config = cJSON_GetObjectItem(rObj, "web_nmap");
    if(!config)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    cgi_debug("\n");

    memset(&cfg, 0x0, sizeof(nmap_config_t));
    ret = parse_json_web_nmap(config, &cfg);
    if(ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }
    
    cgi_debug("\n");

    nmap_web_config_set(&cfg);

    config_commit();

	system("/etc/init.d/nmap-scan.init restart");
	
err:
    if(!rObj)
    {
        cJSON_Delete(rObj);
    }
    
    webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);  

    return 0;
}


int nmap_scan_main(char *cmd, char *data)
{
    int ret = 0;

    if(!cmd)
    {
        return -1;
    }

    if(strcmp(cmd, "web_nmap_get") == 0)
    {
        return web_nmap_get();
    }

    if(data != NULL)
    {
        if(strcmp(cmd, "web_nmap_set") == 0)
        {
            ret = web_nmap_set(data, strlen(data));
        }
    }
    
    return ret;
}

