#ifndef __NMAP_SCAN_H
#define __NMAP_SCAN_H

typedef struct nmap_scan_config{
	int enable;      // 开关
	int manual;      // 自动，或者手动输入主机IP
	int scan_rate;   // 扫描频率
	int retry_count; // 重试次数
	int scan_depth;  // 扫描深度
	int process_num; // 并行进程数
	int timeout;     // 超时时间
	char ip_pool[64];   // 扫描网段池
	char port_pool[128]; // 常用端口池
}nmap_config_t;

int nmap_scan_main(char *cmd, char *param);
#endif // __NMAP_SCAN_H
