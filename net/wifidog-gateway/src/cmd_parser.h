#ifndef _POSTJSON_H
#define _POSTJSON_H

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include "curl/curl.h"
#include "chemiao/cjson/cJSON.h" 
#include <stdlib.h>
 
#include "chemiao/b64/cencode.h"
#include "chemiao/b64/cdecode.h"
#include "chemiao/md5/md5.h"
#include "chemiao/getJson/getJson.h"

#include "chemiao/getdevice/get_api.h"
#include "chemiao/getdevice/getdevice.h"

#ifndef MAX_BUF
#define MAX_BUF 4096
#endif

#ifndef LENGTH
#define LENGTH  128
#endif

#ifndef MAX_ALLOWED_USER_COUNTS 
#define MAX_ALLOWED_USER_COUNTS 5
#endif

//

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
	};
#endif
	
