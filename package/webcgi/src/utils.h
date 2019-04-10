
#ifndef __UTILS_H_
#define __UTILS_H_

#include <syslog.h>
#include "cjson.h"

extern int cgi_errno;
extern int cgi_type;

typedef FILE wp_t;

enum CGI_ERRNO {
    CGI_ERR_OK = 0,
    CGI_ERR_PARAM = 1,
    CGI_ERR_OTHER = 2,
    CGI_ERR_LIMITED = 3,
    CGI_ERR_VLAN_NF = 101,
    CGI_ERR_VLAN_EX = 102,
    CGI_ERR_PORT_NEX = 103
};

enum CGI_TYPE {
    CGI_HTTP = 0,
    CGI_CLI
};

enum {
    INVALID_PARAM = 0,
    VALID_PARAM
};

#define CGI_SUFFIX ".cgi"
#define CLI_SUFFIX ".cli"

/* nvram相关, 取自DNI libconfig.so
 *
 * 其他未知函数参数
 *      config_getall 获取某种name为name1，name2, ..., nameN的所有配置
 *      config_default 复位到出厂配置
 *      config_backup 备份当前配置
 *      config_restore 载入配置文件
 */

extern char *config_get(const char *name);
int config_get_int(const char *name);
char *config_get_ext(const char * prefix, int idx);
int config_get_int_ext(const char * prefix, int idx);
extern int config_set(const char *name, const char *value);
int config_set_int(const char *name, int value);
int config_set_ext(const char * prefix, int idx, char * value);
int config_set_int_ext(const char * prefix, int idx, int value);
extern int config_match(const char *name, char *match);
extern int config_inmatch(const char *name, char *invmatch);
extern int config_unset(const char *name);
int config_unset_ext(const char *prefix, int idx);
extern int config_commit(void);
extern int config_uncommit(void);

int cjson_get_int(cJSON * obj, char * key, int * val);
int cjson_get_double(cJSON * obj, char * key, double * val);
char *cjson_get_string(cJSON * obj, char * key);

int is_valid_port(int port);

void webs_json_header(wp_t * wp);
void webs_text_header(wp_t * wp);
void webs_write(wp_t *wp, char *fmt, ...);

char *web_get(char * tag, char * input, int dbg);
int do_system(const char *fmt, ...);
int wait_eval(int wait, const char *fmt, ...);

#if 0
#define cgi_debug(fmt, args...) \
	{ \
		FILE *dout; \
		dout = fopen("/tmp/webcgi.log", "a"); \
		fprintf(dout, "[%25s]:[%05d] "fmt, __FUNCTION__, __LINE__, ##args); \
		fclose(dout); \
	}
#else
#define cgi_debug(fmt, args...)
#endif

#define cgi_log_info(fmt, args...) \
    { \
       syslog(LOG_INFO, "[Web Operation] INFO "fmt, ##args); \
    }

#define cgi_log_warn(fmt, args...) \
    { \
       syslog(LOG_INFO, "[Web Operation] WARN "fmt, ##args); \
    }

#define cgi_log_error(fmt, args...) \
    { \
        syslog(LOG_INFO, "[Web Operation] ERROR "fmt, ##args); \
    }

#define cgi_log_ipsec(fmt, args...) \
    { \
        syslog(LOG_INFO, "[IPSec VPN] "fmt, ##args); \
    }

#endif

