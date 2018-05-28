#ifndef _SENTINEL_H
#define _SENTINEL_H

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
 
#include "curl/curl.h"
#include "chemiao/cjson/cJSON.h" 
#include "chemiao/b64/cencode.h"
#include "chemiao/b64/cdecode.h"
#include "chemiao/md5/md5.h"
#include "chemiao/device_manager/device_manager.h"

#ifndef MAX_ALLOWED_USER_COUNTS 
#define MAX_ALLOWED_USER_COUNTS 5
#endif

typedef enum _cmd_level {REBOOT_AVOID,REBOOT_DELAY,REBOOT_NOW} cmd_level;

typedef struct _t_cmd{
    cmd_level   level;
    char        *name;
    struct _t_cmd *next;
}dev_command;


typedef struct ST_blacklist{
	char * host;
	struct ST_blacklist * next;
} blacklist;	

typedef struct ST_ssid{
	int id;
	char* name;	
	char* pwd;	
	int safemode;	
	int hiddenmode; 
}ssid_t;


//用户结构体
 struct ST_user{
	char mac[LENGTH];         //用户设备mac地址
	char ip[LENGTH];          //用户设备IP地址
	int  onlinetime;  //上线时间
	char uploadspeed[LENGTH]; //实时上传速度
	char downloadspeed[LENGTH];//实时下载速度
	};

//Json结构体
 struct ST_Json{
	char firm[LENGTH];
	char identifier[LENGTH];
	char version[LENGTH];
	char operator[LENGTH];
	char serial[LENGTH];
	char ttraffic[LENGTH];
	char sversion[LENGTH];
	char hversion[LENGTH];
	char mac[LENGTH];         //WiFiDog的MAC
	char ip[LENGTH];          //wifidog的ip
	char cpuratio[LENGTH];    //CPU使用率
	char memratio[LENGTH];    //RAM使用率
	char discratio[LENGTH];   //DISC使用率
	char sigintens[LENGTH];   //信号强度
	char netstandard[LENGTH]; //网络制式
	char iccid[LENGTH];       //SIM卡中的唯一识别码
	char imsi[LENGTH];        //SIM卡中的唯一识别码
//	int  usercounts;       //用户人数
//	struct ST_user user[MAX_ALLOWED_USER_COUNTS];	 //JSON Object,用户数据 
	};

int pingserver();
#endif
	
