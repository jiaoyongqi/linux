#ifndef _DEVICE_MANAGER_H
#define _DEVICE_MANAGER_H
#include <stdio.h> 
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h> 
#include <netdb.h> 
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include "chemiao/curl/curl.h"
#include "chemiao/cjson/cJSON.h"
#include "src/debug.h"

#ifndef MAX_BUF
#define MAX_BUF 		4096
#endif

#ifndef LENGTH
#define LENGTH  		4096
#endif

#define ETHERNETNAME 		"br0" // "lmi40"
#define IMEI_ADDR_FILE		"/amt/imei.txt"
//#define ICCID_FILE		"/data/var/boa/iccid.txt"
#define ICCID_FILE		"/data/var/iccid.txt"//changed by liubofei
#define TRANSMIT		"/data/var/transmit"
#define RECEIVE			"/data/var/receive"
#define UPDATEFILE		"/cache/update.zip"
#define DOWN_STATUS_FILE	"/data/var/downstatus.txt"

int t_printf(const char *format, ...);

int t_sprintf(char *out, const char *format, ...);

int t_snprintf( char *buf, unsigned int count, const char *format, ... );


int getDeviceMac(char *buf);
int getDeviceIP(char *buf);
int getCpuRatio(char *buf);
int getMemRatio(char *buf);

int reboot(void);
int reset(void);
int get_imsi(char * imsi_string);
int get_sim_ip(char *ip, int ip_len);

int changeWifiMode(int mode);
// 函数介绍:获取当前设备磁盘占用
int getDiscRatio(char *used_perc);

// 函数介绍:获取当前设备iccid
int getICCID(char * iccid_string);

// 函数介绍:获取当前设备消耗流量
int getTTraffic(char *buf);
//函数介绍:获取当前设备imei信息
int getIMEI(char * value);
// 函数介绍:获取当前设备版本信息
int get_Version(int type, char * fwversion);

//size_t boa_POST(char *response,char *url);
size_t boa_GET(char *url,char *outstream);
static size_t handleBoaResponse(void *ptr,size_t size, size_t nitems, void *stream);
int changeSSIDResult(char *strJson);//parse boa response
int getBaseInfo(char *strJson,char *retCardinfo,char *retSig_strength,char *retNetwork);

int get_file_md5(char *path, char *md5, int buf_len);

int downstatus(int *down_status);

void clear_crlf(char *str);

void thread_update(void *arg);

int distinguish_client(const char *mac);

#endif
