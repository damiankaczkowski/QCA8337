
#ifndef __SYSTEM_H_
#define __SYSTEM_H_

typedef struct {
    int http_port;
    int https_port;
    int redirect_https;
    int idle_time;
} web_mngt_t;

int system_main(char *cmd, char *data);

#endif
