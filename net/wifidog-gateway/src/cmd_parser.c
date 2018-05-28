/* 
* 功能：封装及post json，解析json并执行命令
* 
* 
*/

#include "postJson.h"
#include "src/conf.h"
#include "src/debug.h"
#include "src/client_list.h"
#include "src/auth.h"
#include "src/fw_iptables.h"
#include "src/centralserver.h"
#include "chemiao/cjson/cJSON.h"
#include <syslog.h>


/** \brief  封装一个 Json
 *
 * \param 
 * \param  
 * \return 
 *
 */  

char returnBuffer[LENGTH];//存储返回的json数据
static int opset_index = 0;
static cJSON * opstates = NULL; 
static cJSON * opStateSet = NULL;

int packageJson(char *str)
{
	int i = 0;
	char *out;
	struct ST_Json st_json;
	cJSON *heartbeat,*data,*users;
	t_client *p1,*p2,*worklist;

	char *urlGetBaseInfo = "192.168.0.1/webapp/getBaseInfo.asp";

	char retCardinfo[20];    //cardinfo
	char retSig_strength[10]; //signal strength
	char retNetwork[5];       //

	memset(returnBuffer,0,sizeof(returnBuffer));

	boa_GET(urlGetBaseInfo);
	debug(LOG_INFO,returnBuffer);
	getBaseInfo(returnBuffer,retCardinfo,retSig_strength,retNetwork);
	memset(returnBuffer,0,sizeof(returnBuffer));

	strcpy(st_json.firm,"iton");//获取厂商信息 *
	strcpy(st_json.operator,retCardinfo);
	getTTraffic(st_json.ttraffic);      //获取设备当次流量*
	get_Version(0, st_json.sversion);//获取软件版本号*
	get_Version(1, st_json.hversion);//获取硬件版本号*
	strcpy(st_json.version,st_json.hversion);//获取设备版本
	strcat(st_json.version,st_json.sversion);
	getDeviceMac(st_json.mac);          //WiFiDog的MAC *
	get_sim_ip(st_json.ip, sizeof(st_json.ip));
	//getDeviceIP(st_json.ip);            //wifidog的ip  *
	getCpuRatio(st_json.cpuratio);      //CPU使用率    *
	getMemRatio(st_json.memratio);      //memratio
	getDiscRatio(st_json.discratio);    //RAM使用率   *
	strcpy(st_json.sigintens,retSig_strength);
	strcpy(st_json.netstandard,retNetwork);
	getICCID(st_json.iccid);              //获取iccid  *
	get_imsi(st_json.imsi);			//获取imsi   *,there we use the get_imsi();
	getIMEI(st_json.identifier);               //获取imei   *,there we use the getIMEI();
	strcpy(st_json.serial,st_json.identifier);

	heartbeat = cJSON_CreateObject();
	cJSON_AddItemToObject(heartbeat,"data",data=cJSON_CreateObject());
	cJSON_AddStringToObject(data,"firm",st_json.firm);
	cJSON_AddStringToObject(data,"identifier",st_json.identifier);
	cJSON_AddStringToObject(data,"version",st_json.version);
	cJSON_AddStringToObject(data,"operator",st_json.operator);
	cJSON_AddStringToObject(data,"serial",st_json.serial);
	cJSON_AddNumberToObject(data,"ttraffic",atol(st_json.ttraffic));
	cJSON_AddStringToObject(data,"sversion",st_json.sversion);
	cJSON_AddStringToObject(data,"hversion",st_json.hversion);
	cJSON_AddStringToObject(data,"mac",st_json.mac);
	cJSON_AddStringToObject(data,"ip",st_json.ip);
	cJSON_AddStringToObject(data,"cpuratio",st_json.cpuratio);
	cJSON_AddStringToObject(data,"memratio",st_json.memratio);
	cJSON_AddStringToObject(data,"discratio",st_json.discratio);
	cJSON_AddNumberToObject(data,"sigintens",atoi(st_json.sigintens));
	cJSON_AddStringToObject(data,"netstandard",st_json.netstandard);
	cJSON_AddStringToObject(data,"iccid",st_json.iccid);
	//cJSON_AddStringToObject(data,"imsi",st_json.imsi);
	cJSON_AddStringToObject(data,"imsi",st_json.iccid);//imsi --> iccid 20161220
	if(opStateSet != NULL) cJSON_AddItemToObject(data,"opStateSet",cJSON_Duplicate(opStateSet,1));
	out=cJSON_Print(heartbeat);
	cJSON_Minify(out); strcpy(str,out);
	cJSON_Delete(heartbeat);
	printf("device heart beat:\n------\n%s\n------\n",str);
	free(out);
	return 1;
}


/** \brief 回调函数，curl接收返回的json数据
 *
 * \param 
 * \param     
 * \return  
 *
 */    
//curl定义的回调函数格式
//typedef size_t (*curl_write_callback)       (char *buffer, size_t size, size_t nitems, void *outstream);

static size_t serverReturn(void *ptr,size_t size, size_t nitems, void *stream)
{
	int res_size;
	res_size = size * nitems;
	memset(returnBuffer,0,strlen(returnBuffer));
	strcpy(returnBuffer,ptr);
	return size * nitems;
} 

/** \brief 调用curl函数进行POST操作，并且接收返回来的json数据
 *
 * \param strJson:传入json内容
 * \param     url:目标链接参数
 * \return  url 为 NULL return -1;url 非 null 且 post 成功 	
            return 1 
 *
 */    
  
size_t curlPostJson(char *strJson,char *url)
{
	CURL *curl;   //定义CURL类型的指针
	CURLcode res; //定义CURLcode类型的变量
	int sockfd;
	char szDigest[16] = {0};
	char HEXDigest[40] = {0};
	static int authdown = 0;
	
	//如果参数不对，返回0
	if(url==NULL) return -1;
	sockfd = connect_auth_server();
	if (sockfd == -1) 
	{
		if (!authdown) 
		{
		    fw_set_authdown();
		    authdown = 1;
		}
		return -1;
	}

	curl=curl_easy_init();//初始化一个CURL类型的指针

	if(curl!=NULL)
	{
		//设置curl选项，CURLOPT_URL
		curl_easy_setopt(curl,CURLOPT_URL,url);
		//设置超时时间为1秒  
		curl_easy_setopt(curl, CURLOPT_TIMEOUT,1);  
		
		memset(szDigest,0,strlen(szDigest));
		MD5Digest(strJson,strlen(strJson),szDigest);

		snprintf(HEXDigest,sizeof(HEXDigest)-1,\
		"HASH:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",\
		(unsigned char)szDigest[0],\
		(unsigned char)szDigest[1],\
		(unsigned char)szDigest[2],\
		(unsigned char)szDigest[3],\
		(unsigned char)szDigest[4],\
		(unsigned char)szDigest[5],\
		(unsigned char)szDigest[6],\
		(unsigned char)szDigest[7],\
		(unsigned char)szDigest[8],\
		(unsigned char)szDigest[9],\
		(unsigned char)szDigest[10],\
		(unsigned char)szDigest[11],\
		(unsigned char)szDigest[12],\
		(unsigned char)szDigest[13],\
		(unsigned char)szDigest[14],\
		(unsigned char)szDigest[15]);
		//设置http发送的内容类型为JSON  
		struct curl_slist *plist = curl_slist_append(NULL,HEXDigest); 	
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, plist);  
		//设置要POST的JSON数据  
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, strJson); 
		//可以使用下面的语句来注册回调函数，回调函数将会在接收到数据的时候被调用：
		memset(returnBuffer,0,sizeof(returnBuffer));
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, serverReturn);
		//执行设置，进行相关操作
		res = curl_easy_perform(curl);

		if (res != CURLE_OK)  
		{  
			debug(LOG_ERR,"curl_easy_perform() failed:%s\n", curl_easy_strerror(res));  
			//清除curl操作
			curl_easy_cleanup(curl);
			if (!authdown) 
			{
			    fw_set_authdown();
			    authdown = 1;
			}

			return -1;
		} 
		else 
		{
			if (authdown)
			{
				fw_set_authup();
				authdown = 0;
			}
			curl_easy_cleanup(curl);
		}
	}
	return 1;
}


/* 相关功能测试函数->>>>>>>>*/

int resetDevice()
{
	printf("i am in resetDevice()\n");
	return reset();
}
int restartDevice()
{
	printf("i am in restartDevice()\n");
	return reboot();
}
int updateSoftwareFromUrl(char *soft_url,char *md5_value)
{
	printf("i am in updateSoftwareFromUrl()\n");
	return 0;
}

int changeSSID( int id, char* name, char* pwd, int safemode, int hiddenmode)
{
	char * data = NULL;
	char *urlSetSSID = "http://192.168.0.1/webapp/set_wifi.asp";
	char url[1024] = {0};
	pwd = strlen(pwd) < 8 ? "12345678":pwd;
	sprintf(url,"%s?id=%d&name=%s&pwd=%s&safemode=%d&hiddenmode=%d",
		urlSetSSID,id,name,pwd,safemode,hiddenmode);
	memset(returnBuffer,0,sizeof(returnBuffer));
	boa_GET(url);
	return changeSSIDResult(returnBuffer);
}

int setBlackList(char *items)
{
	printf("i am in setBlackList()\n");
	return 0;
}

int setWhiteList(char *items)
{
	printf("i am in setWhiteList()\n");
	return 0;
}
int shutdownAuth()
{
	printf("i am in shutdownAuth()()\n");
	return 0;
}
int setHeartBeatInterval(int sec)
{
	printf("i am in setHeartBeatInterval()\n");
	return 0;
}
/* <<<<<<<<<<<-相关功能测试函数*/

/** \brief Command parsing,指令解析并执行相应的行为*/  
int cmdParsing(char *strJson)
{

	if(strJson==NULL)
	{
		debug(LOG_ERR,"can't parse a null string\n"); 
		return -1;
	}

	printf("#### iton %s:%d\n",__func__,__LINE__);//jyqi
	
	cJSON *params;
	//调用库函数进行解析
	cJSON *root=cJSON_Parse(strJson);
	
	if(root==NULL)
	{
		debug(LOG_ERR,"Provided is an invalid JSON string!\n"); 
		return -1;
	}

	printf("%s:%d\n",__func__,__LINE__);//jyqi add
	cJSON *response_data = cJSON_GetObjectItem(root,"data");
	if(response_data->type == cJSON_NULL)
	{
		debug(LOG_ERR,"Data required,but the parser miss it!\n"); 
		 return -1 ;
	}
	cJSON * serv_status = cJSON_GetObjectItem(response_data,"status");
	if(serv_status->type == cJSON_NULL) 
	{
		debug(LOG_ERR,"Response without status is a fatal error!");
		return -1;
	}
	debug(LOG_INFO,"Startting to get the server command set...");
	cJSON * serv_commands = cJSON_GetObjectItem(response_data,"opSet");
	if(serv_commands->type == cJSON_NULL)
	{
		debug(LOG_INFO,"server is alive and no operation on this device!");
		if(opStateSet) {cJSON_Delete(opStateSet);opStateSet = NULL;}	
		return 0;
	}
	else
	{
		debug(LOG_INFO,"Whether the server wants to operate this device \
			depends on the inner operations!");
		if(opStateSet == NULL) opStateSet = cJSON_CreateObject();
	}
	debug(LOG_INFO,"Every server command set has an unique index...");
	cJSON *op_index = cJSON_GetObjectItem(serv_commands,"opIndex");
	if(op_index->type == cJSON_NULL)
	{
		debug(LOG_INFO,"opset index is required if opSet is not empty!");
		return -1;
	}
	opset_index = op_index->valueint ;
	debug(LOG_INFO,"lets see if this message is an server ACK or a server command set...");	
	cJSON * operations = cJSON_GetObjectItem(serv_commands,"operations");
	if(operations->type == cJSON_NULL)
	{
		debug(LOG_INFO,"means that this message is for ACK because there is no real operations!");
		if(opStateSet) 
		{
			printf("\n-----------\n%s\n",cJSON_Print(opStateSet));
			cJSON_Delete(opStateSet);
			printf("\n------------------------\n");
			opStateSet = NULL;
		}	
		return 0;
	}
	else
	{
		if(opStateSet == NULL) opStateSet = cJSON_CreateObject();
	}

	printf("#### iton %s:%d\n",__func__,__LINE__);
	debug(LOG_INFO,"init the commands response json objects...");
	cJSON_AddNumberToObject(opStateSet,"opIndex",opset_index); 
	cJSON_AddItemToObject(opStateSet,"opStates",opstates = cJSON_CreateObject()); 

	if(params = cJSON_GetObjectItem(operations,"resetDevice"))
	{
		//重置设备系统
		cJSON_AddNumberToObject(opstates,"resetDevice",resetDevice()); 
	}

	if(params = cJSON_GetObjectItem(operations,"restartDevice"))
	{
		//重启设备系统
		cJSON_AddNumberToObject(opstates,"restartDevice",restartDevice()); 

	}

	if(params=cJSON_GetObjectItem(operations,"updateSoftwareFromUrl"))
	{
		printf("#### iton %s:%d\n",__func__,__LINE__);//jyqi add
		char *soft_url = cJSON_GetObjectItem(params,"url")->valuestring;
		char *md5_value = cJSON_GetObjectItem(params,"md5")->valuestring;
		//更新软件
		cJSON_AddNumberToObject(opstates,"updateSoftwareFromUrl",\
				updateSoftwareFromUrl(soft_url,md5_value));
	}

	if(params=cJSON_GetObjectItem(operations,"changeSSID"))
	{
		printf("#### iton %s:%d\n",__func__,__LINE__);//jyqi add
		//修改ssid设置
		int ret = 0;
		char ssid[] ="ssid";
		char newName[] = "ssid name";
		cJSON * ssid1 = cJSON_GetObjectItem(params,"ssid1");
		//{"ssid1":{"name":"chengke","pwd":"","safemode":0,"hiddenmode":0}}
		if(ssid1 != NULL && ssid1->type != cJSON_NULL)
		{
			ret = changeSSID(1,	
				cJSON_GetObjectItem(ssid1,"name")->valuestring,
				cJSON_GetObjectItem(ssid1,"pwd")->valuestring,
				cJSON_GetObjectItem(ssid1,"safemode")->valueint,
				cJSON_GetObjectItem(ssid1,"hiddenmode")->valueint
				);
			debug(LOG_INFO,"change ssid1");
		}	

		cJSON * ssid2 = cJSON_GetObjectItem(params,"ssid2");
		if(ssid2 != NULL && ssid2->type != cJSON_NULL)
		{
			ret = -1 == ret ? -1 : changeSSID(2,	
				cJSON_GetObjectItem(ssid1,"name")->valuestring,
				cJSON_GetObjectItem(ssid1,"pwd")->valuestring,
				cJSON_GetObjectItem(ssid1,"safemode")->valueint,
				cJSON_GetObjectItem(ssid1,"hiddenmode")->valueint
				);
		}	

		debug(LOG_INFO,"before change ssid1 result added to opstats");
		cJSON_AddNumberToObject(opstates,"changeSSID",ret); 
	}


	if(params=cJSON_GetObjectItem(operations,"setBlackList"))
	{
		char items[] = "aaaa";
		//设置黑名单
		cJSON_AddNumberToObject(opstates,"setBlackList",setBlackList(items));   
	}

	if(params=cJSON_GetObjectItem(operations,"setWhiteList"))
	{
		char items[] = "bbbb";
		//设置白名单
		cJSON_AddNumberToObject(opstates,"setWhiteList",setWhiteList(items));  
	}

	if(params=cJSON_GetObjectItem(operations,"shutdownAuth"))
	{
		//关闭设备认证
		cJSON_AddNumberToObject(opstates,"shutdownAuth",shutdownAuth());			 
	}

	if(params=cJSON_GetObjectItem(operations,"setHeartBeatInterval"))
	{
		//设置心跳周期
		int sec = cJSON_GetObjectItem(params,"sec")->valueint;
		cJSON_AddNumberToObject(opstates,"setHeartBeatInterval",setHeartBeatInterval(sec) );
	}

	debug(LOG_INFO,cJSON_Print(opStateSet));
	return 0;
}

int pingserver()
{
	char strJson[LENGTH]={0};
	char strJsonBase64[MAX_BUF]={0};
	char decode_out[MAX_BUF]={0};
	base64_encodestate state;
	base64_decodestate state_d;
	char url[100]="http://test.bestlinks.com.cn/chemiao/device/ping";

	packageJson(strJson);
	base64_init_encodestate(&state);
	memset(strJsonBase64,0,sizeof(strJsonBase64));
	base64_encode_block(strJson,strlen(strJson),strJsonBase64,&state);
	base64_encode_blockend(strJsonBase64,&state);
	base64_init_encodestate(&state);
	curlPostJson(strJsonBase64,url);
	base64_init_decodestate(&state_d);
	base64_decode_block(returnBuffer, strlen(returnBuffer), decode_out, &state_d);
	base64_init_decodestate(&state_d);
	printf("#### iton server pingserver cmd_parser.c 1111\n");//jyqi add
	printf("server response is:%s\n",decode_out);
	return cmdParsing(decode_out);
}
