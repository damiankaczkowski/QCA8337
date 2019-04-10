
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "system.h"

void web_mngt_config_get(web_mngt_t *cfg)
{
    char *val = NULL;
    
    cfg->http_port = config_get_int("http_port");
    cfg->https_port = config_get_int("https_port");
    cfg->idle_time = config_get_int("idle_time");
    val = config_get("redirect_https");
    cfg->redirect_https = ((val[0] != '\0') ? atoi(val) : 1);
}

void web_mngt_config_set(web_mngt_t *cfg)
{
    config_set_int("http_port", cfg->http_port);
    config_set_int("https_port", cfg->https_port);
    config_set_int("redirect_https", cfg->redirect_https);
    config_set_int("idle_time", cfg->idle_time);
}

int parse_json_web_mngt(cJSON *item, web_mngt_t *cfg)
{
    int ret = 0;
    int intVal = 0;

    cfg->http_port = 80;
    cfg->https_port = 443;
    cfg->idle_time = 5;

    ret = cjson_get_int(item, "redirect_https", &intVal);
    if(ret < 0)
    {
        return -1;
    }
    cfg->redirect_https = intVal;
    
    return 0;
}


int sys_web_mngt_get()
{
    web_mngt_t cfg;

    memset(&cfg, 0x0, sizeof(web_mngt_t));
    web_mngt_config_get(&cfg);
    
    webs_write(stdout, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(stdout, "\"web_mngt\":{\"redirect_https\":%d}}}", cfg.redirect_https);
    
    return 0;
}

int sys_web_mngt_set(char *data, int len)
{
    int ret = 0;
    cJSON *rObj = NULL;
    cJSON *config = NULL;
    web_mngt_t cfg;
        
    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    config = cJSON_GetObjectItem(rObj, "web_mngt");
    if(!config)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    cgi_debug("\n");

    memset(&cfg, 0x0, sizeof(web_mngt_t));
    ret = parse_json_web_mngt(config, &cfg);
    if(ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }
    
    cgi_debug("\n");

    web_mngt_config_set(&cfg);

    config_commit();
    
err:
    if(!rObj)
    {
        cJSON_Delete(rObj);
    }
    
    webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);  

    return 0;
}

int system_main(char *cmd, char *data)
{
    int ret = 0;

    if(!cmd)
    {
        return -1;
    }

    if(strcmp(cmd, "web_mngt_get") == 0)
    {
        return sys_web_mngt_get();
    }

    if(data != NULL)
    {
        if(strcmp(cmd, "web_mngt_set") == 0)
        {
            ret = sys_web_mngt_set(data, strlen(data));
        }
    }
    
    return ret;
}
