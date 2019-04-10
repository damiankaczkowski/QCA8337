
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"

int cgi_type = 0;
int cgi_errno = CGI_ERR_OK;
int cgi_cmd = 0;

#define CONFIG_API

int config_get_int(const char *name)
{
    char *value = config_get(name);
    if(value[0] != '\0')
        return atoi(value);
    else
        return 0;
}

int config_set_int(const char *name, int value)
{
    char int_str[16] = {0};
    snprintf(int_str, sizeof(int_str), "%d", value);
    return config_set(name, int_str);
}

char *config_get_ext(const char *prefix, int idx)
{
    char name[32] = {0};
    snprintf(name, sizeof(name), "%s%d", prefix, idx);
    return config_get(name);
}

int config_get_int_ext(const char *prefix, int idx)
{
    char name[32] = {0};
    snprintf(name, sizeof(name), "%s%d", prefix, idx);
    return config_get_int(name);
}

int config_set_ext(const char *prefix, int idx, char *value)
{
    char name[32] = {0};
    snprintf(name, sizeof(name), "%s%d", prefix, idx);
    return config_set(name, value);
}

int config_set_int_ext(const char *prefix, int idx, int value)
{
    char name[32] = {0};
    snprintf(name, sizeof(name), "%s%d", prefix, idx);
    return config_set_int(name, value);    
}

int config_unset_ext(const char *prefix, int idx)
{
    char name[32] = {0};
    snprintf(name, sizeof(name), "%s%d", prefix, idx);
    return config_unset(name);  
}

#define CJSON_API

int cjson_get_int(cJSON *obj, char *key, int *val)
{
    cJSON *tmp = NULL;

    tmp = cJSON_GetObjectItem(obj, key);
    if(!tmp || tmp->type != cJSON_Number)
    {
        return -1;
    }

    *val = tmp->valueint;

    return 0;
}

int cjson_get_double(cJSON *obj, char *key, double *val)
{
    cJSON *tmp = NULL;

    tmp = cJSON_GetObjectItem(obj, key);
    if(!tmp || tmp->type != cJSON_Number)
    {
        return -1;
    }

    *val = tmp->valuedouble;

    return 0;
}

char *cjson_get_string(cJSON *obj, char *key)
{
    cJSON *tmp = NULL;

    tmp = cJSON_GetObjectItem(obj, key);
    if(!tmp || tmp->type != cJSON_String)
    {
        return NULL;
    }

    return tmp->valuestring;
}

#define PARAM_CHECK

int is_valid_port(int port)
{
    if(port < 0 || port > 65535)
        return INVALID_PARAM;
    return VALID_PARAM;
}

#define WEB_API

void webs_json_header(wp_t *wp)
{
    fprintf(wp, "HTTP/1.0 200 OK\r\n");
    fprintf(wp, "Content-type: application/json; charset=utf-8\r\n");
    fprintf(wp, "Pragma: no-cache\r\n");
    fprintf(wp, "Cache-Control: no-cache\r\n");
    fprintf(wp, "\r\n");
}

void webs_text_header(wp_t *wp)
{
    fprintf(wp, "HTTP/1.0 200 OK\r\n");
    fprintf(wp, "Content-type: text/plain; charset=utf-8\r\n");
    fprintf(wp, "Pragma: no-cache\r\n");
    fprintf(wp, "Cache-Control: no-cache\r\n");
    fprintf(wp, "\r\n");
}

void webs_write(wp_t *wp, char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(wp, fmt, args);
    va_end(args);
}

#define DATALEN 65

void unencode(char *src, char *last, char *dest)
{
    for(; src != last; src++, dest++)
        if(*src == '+')
            *dest = ' ';
        else if(*src == '%') {
            int code;
            if(sscanf(src+1, "%2x", &code) != 1) code = '?';
            *dest = code;
            src +=2;
        } else
            *dest = *src;
    *dest = '\0';
}

char *web_get(char *tag, char *input, int dbg)
{
    char *e_begin, *v_begin, *v_end;
    static char ret[DATALEN];
    int v_len;

    sprintf(ret, "&%s=", tag);
    
    if (NULL == (e_begin = strstr(input, ret))) {
        sprintf(ret, "%s=", tag);
    if (NULL == (e_begin = strstr(input, ret)) || e_begin != input)
        return "";
    }
    
    memset(ret, 0, DATALEN);
    v_begin = strchr(e_begin, '=') + 1;
    
    if (v_begin == NULL) v_begin = "";
    if ((NULL != (v_end = strchr(v_begin, '&')) ||
        NULL != (v_end = strchr(v_begin, '\0'))) &&
        (0 < (v_len = v_end - v_begin)))
            unencode(v_begin, v_end, ret);
    
    /* for WebUI debug*/
    if (dbg == 1)
        printf("%s = %s\n", tag, ret);
    else if (dbg == 2)
        cgi_debug("[DBG]%s = %s\n", tag, ret);

    return ret;
}

#define SYSTEM_API

int do_system(const char *fmt, ...)
{
    va_list args;
    char cmdbuf[512] = {0};

    va_start(args, fmt);
    vsnprintf(cmdbuf, sizeof(cmdbuf), fmt, args);
    va_end(args);
    
    return system(cmdbuf);
}

/*
 * 子进程延时执行
 * 对于cgi来说有些操作需要在返回前端处理之后再初始化，
 * 这样初始化动作需要后台延时执行
 */
int wait_eval(int wait, const char *fmt, ...)
{
    int i;    
    pid_t pid;
    va_list args;
    char cmdbuf[512] = {0};

    pid = fork();
    if(pid <  0)
    {
        exit(1);
    }
    else if(pid == 0)
    {
        setsid();

        for(i = 0; i <= 2; i ++)
        {
            close(i);
        }      
        umask(0);

        sleep(wait);

        va_start(args, fmt);
        vsnprintf(cmdbuf, sizeof(cmdbuf), fmt, args);
        va_end(args);

        return system(cmdbuf);
    }

    return 0;
}
