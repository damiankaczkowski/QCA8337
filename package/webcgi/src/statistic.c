

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "statistic.h"
#include "utils.h"

int get_traffic_meters(char *data, int len)
{
    int ret = 0;
    int i = 0;
    char cmd[128] = {0};
    cJSON *rObj = NULL;
    FILE *fp = NULL;
    char buff[128] = {0};
    int start = 0;
    int end = 0;

    if((rObj = cJSON_Parse(data)) != NULL)
    {
        ret = cjson_get_int(rObj, "start", &start);
        ret = cjson_get_int(rObj, "end", &end);
        if(ret < 0)
        {
            start = 0;
            end = 0;
        }
    }

    if(end != 0 || start != 0)
    {
        snprintf(cmd, sizeof(cmd), "echo \"start:%d end:%d\" > /tmp/rstats.query", start, end);
        system(cmd);
    }
    
    system("killall -USR1 rstats");

    usleep(200000);

	for(i = 0; i < 6; i ++)
    {
        fp = fopen("/tmp/rstats.json", "r");
        if(!fp)
        {
            usleep(200000);
        }
        else
        {
            while(1)
            {
                len = fread(buff, 1, sizeof(buff), fp);
                if(len <= 0)
                {
                    break;
                }
                else
                {
                    fwrite(buff, 1, len, stdout);
                }
            }
            break;
        }
	}

end_proc:
    if(fp)
    {
        fclose(fp);
    }
    
    //unlink("/tmp/rstats.json");
    unlink("/tmp/rstats.query");

    return 0;
}

int get_attached_devices()
{
    int i = 0;
    int ret = 0;
    FILE *fp = NULL;
    int len = 0;
    char buff[128] = {0};

    system("killall -USR1 lan-scan");
    sleep(1);
    
    for(i = 0; i < 6; i ++)
    {
        fp = fopen("/tmp/lan-scan.json", "r");
        if(!fp)
        {
            usleep(200000);
        }
        else
        {        
            webs_write(stdout, "{\"code\":%d,\"data\":{", cgi_errno);
            webs_write(stdout, "\"device_list\":");
            while(1)
            {
                len = fread(buff, 1, sizeof(buff), fp);
                if(len <= 0)
                {
                    break;
                }
                else
                {
                    fwrite(buff, 1, len, stdout);
                }
            }
            webs_write(stdout, "}}");
            break;
        }
    }

    if(!fp)
    {
        webs_write(stdout, "{\"code\":2,\"data\":{}}");
    }

end_proc:
    if(fp)
    {
        fclose(fp);
    }
    
    unlink("/tmp/lan-scan.json");

    return 0;
}

int statistic_main(char *cmd, char *param)
{
    int ret = 0;

    if(!cmd)
    {
        return -1;
    }

    if(strcmp(cmd, "traffic_meters") == 0)
    {
        return get_traffic_meters(param, strlen(param));
    }
    else if(strcmp(cmd, "attached_devices") == 0)
    {
        return get_attached_devices();
    }

    return ret;
}
