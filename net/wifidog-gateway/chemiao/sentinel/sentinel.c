#include <syslog.h>
#include "sentinel.h"
#include "src/conf.h"
#include "src/debug.h"
#include "src/safe.h"
#include "src/client_list.h"
#include "src/util.h"
#include "src/auth.h"
#include "src/fw_iptables.h"
#include "src/firewall.h"
#include "src/centralserver.h"
#include "src/client_list.h"
#include "src/tc_qos.h"
#include "src/conf.h"

static int tmp_flag = 1;

//classify commands into three catagory...
static dev_command * cmds[3] ={0};
//0 means no need to reboot;
//1 means to reboot;
//2 means to update the software,and reboot;
//3 means to reset;
//4 means to change ssid;
//5 means to show driver ssid;
static int reboot_flag = 0;
static char* new_software_url = NULL;
static char* new_software_md5 = NULL;


static int opset_index = 0;
static cJSON * opstates = NULL; 
static cJSON * opStateSet = NULL;


static char *base64_encode(char * data)
{
	char strJsonBase64[MAX_BUF]={0};
	char decode_out[MAX_BUF]={0};
	char *ptr = strJsonBase64;
	base64_encodestate state;

	base64_init_encodestate(&state);
	memset(strJsonBase64,0,sizeof(strJsonBase64));
	base64_encode_block(data,strlen(data),strJsonBase64,&state);
	base64_encode_blockend(strJsonBase64,&state);
	base64_init_encodestate(&state);
	for(;*ptr != '\n'&&*ptr != '\0';ptr++);
		*ptr = '\0';
	return safe_strdup(strJsonBase64);
}


int packageJson(char *str)
{
	int i = 0;
	char *out;
	struct ST_Json st_json;
	cJSON *heartbeat,*data,*users;
	t_client *p1,*p2,*worklist;
	s_config *config = config_get_config();
	char *urlGetBaseInfo = "192.168.0.1/webapp/getBaseInfo.asp";

	char boa_response[LENGTH]={0};
	boa_GET(urlGetBaseInfo,boa_response);
	getBaseInfo(boa_response,st_json.operator,st_json.sigintens,st_json.netstandard);

	strcpy(st_json.firm,"iton");//获取厂商信息 *
	getTTraffic(st_json.ttraffic);      //获取设备当次流量*
	get_Version(0, st_json.sversion);//获取软件版本号*
	get_Version(1, st_json.hversion);//获取硬件版本号*
	strcpy(st_json.version,st_json.sversion);//获取设备版本

	LOCK_CONFIG();
	strcpy(st_json.mac,config->gw_id);
	UNLOCK_CONFIG();

    /*
	get_device_mac(st_json.mac,64); //WiFiDog的MAC *

    char* mac_temp = mac_delete_colon(st_json.mac);
	if(NULL != mac_temp)
	{	
		memset(st_json.mac,0x00,64);
		memcpy(st_json.mac,mac_temp,strlen(mac_temp));
		free(mac_temp);
	}
	//getDeviceMac(st_json.mac);          //WiFiDog的MAC *
    */
	get_sim_ip(st_json.ip, sizeof(st_json.ip));
	getCpuRatio(st_json.cpuratio);      //CPU使用率    *
	getMemRatio(st_json.memratio);      //memratio
	getDiscRatio(st_json.discratio);    //RAM使用率   *
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
//	cJSON_AddStringToObject(data,"imsi",st_json.imsi);
	cJSON_AddStringToObject(data,"imsi",st_json.iccid);//imsi-->iccid 20161220
				
	if(opStateSet != NULL) 
	{
		cJSON_AddItemToObject(data,"opStateSet",cJSON_Duplicate(opStateSet,1));
	}

	out=cJSON_Print(heartbeat);cJSON_Minify(out); strcpy(str,out);
	debug(LOG_DEBUG,str);
	cJSON_Delete(heartbeat);free(out);
	return 0;
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
	strcat(stream,ptr);
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
  
size_t curlPostJson(char *strJson,char *url,char* outstream)
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
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2);  
		
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
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, serverReturn);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, outstream);  
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
	if(tmp_flag) 
	{
		//shutdownAuth() ;tmp_flag = 0;
	}

	return 1;
}


/* 相关功能测试函数->>>>>>>>*/

int resetDevice()
{
	printf("i am in resetDevice()\n");
	system("cp /etc/wifidog.conf.bak /etc/wifidog.conf");
	return reset();
}
int restartDevice()
{
	printf("i am in restartDevice()\n");
	return reboot();
}

int updateSoftwareFromUrl(char *soft_url,char *md5_value)
{
	int result;
	void **params;
	pthread_t tid;
	if (!soft_url || !md5_value) 
	{
		printf("parameter error!");
		return -1;
	}

	params = safe_malloc(2 * sizeof(void *));
	*params = safe_strdup(soft_url);
	*(params + 1) = safe_strdup(md5_value);

	// Start update thread
	result = pthread_create(&tid, NULL, (void *)thread_update, (void *)params);
	if (result != 0) {
	    printf("FATAL: Failed to create a new thread (thread_update) - exiting\n");
	    return -2;
	}
	pthread_detach(tid);
	return 0;
}

int set_wifidog_status(int state)
{
	s_config *config = config_get_config();
	LOCK_CONFIG();
    config->auth_required = state;
	char *config_file = safe_strdup(config->configfile);
    UNLOCK_CONFIG();

    if(state == 0)
    {
        fw_destroy();
    }
    else
    {
        if(!fw_init())
        {
            exit(1);
        }
    }

    config_write(config_file);free(config_file);
    return 0;
}
int setAuthServer(t_auth_serv * s)
{
	if(!s) return -1;	
	//step 1:find the server in config.auth_servers by hostname
	//step 2:if find it,modifiy it 
	//step 3:otherwise,add it as a new auth_server,and add the new server to iptables 
	//step 4:save your change to config file

	s_config *config = config_get_config();
	LOCK_CONFIG();
	char *config_file = safe_strdup(config->configfile);

	debug(LOG_INFO,"step 1:find the server in config.auth_servers by hostname");

	t_auth_serv *tmp,*tmp_pre,**head = &config->auth_servers;
	tmp = tmp_pre = *head;
	while(tmp)
	{
		if(!strcmp(tmp->authserv_hostname,s->authserv_hostname))break;
		tmp_pre = tmp;tmp = tmp->next;	
	}

	debug(LOG_INFO,"step 2:if find it,modifiy it");

	if(tmp)
	{
		/*we finally find the host ,just modify the params of 
		 *the server and save it to wifidog.conf
		 */
		if(tmp == *head) 
		{//find it in the front,
			s->next = tmp->next;
			*head = s;
		}
		else 
		{
			s->next = tmp->next;	
			tmp_pre->next = s;
		}
		AUTH_SERV_FREE(tmp);
	}
	else
	{
		debug(LOG_INFO,"step 3:otherwise,add it as a new auth_server,and add the new server to iptables");
		if(!(*head))
		{	
			/*this should never happen,for wifidog requires
			 *at least on auth server,if we got here,head is
			 *not null,add this in case!
			 */
			*head = s;
		}
		else
		{
			s->next = (*head)->next;	
			(*head)->next = s->next;
		}
		fw_clear_authservers();
		fw_set_authservers();
	}

	debug(LOG_INFO,"step 4:save your change to config file");
	UNLOCK_CONFIG();
	config_write(config_file);free(config_file);
	return 0;
}



static cJSON *CHANGESSID_JSON = NULL;


void apply_changeSSID()
{
	cJSON * ssid1 = cJSON_GetObjectItem(CHANGESSID_JSON,"ssid1");
	if(ssid1 != NULL && ssid1->type != cJSON_NULL)
	{
		changeSSID(1,	
			cJSON_GetObjectItem(ssid1,"name")->valuestring,
			cJSON_GetObjectItem(ssid1,"pwd")->valuestring,
			cJSON_GetObjectItem(ssid1,"safemode")->valueint,
			cJSON_GetObjectItem(ssid1,"hiddenmode")->valueint
			);
		debug(LOG_INFO,"change ssid1");
	}	

	cJSON * ssid2 = cJSON_GetObjectItem(CHANGESSID_JSON,"ssid2");
	if(ssid2 != NULL && ssid2->type != cJSON_NULL)
	{
		changeSSID(2,	
			cJSON_GetObjectItem(ssid2,"name")->valuestring,
			cJSON_GetObjectItem(ssid2,"pwd")->valuestring,
			cJSON_GetObjectItem(ssid2,"safemode")->valueint,
			cJSON_GetObjectItem(ssid2,"hiddenmode")->valueint
			);
	}
}

int changeSSID( int id, char* name, char* pwd, int safemode, int hiddenmode)
{
	char * data = NULL;
	char *urlSetSSID = "http://192.168.0.1/webapp/set_wifi.asp";
	char url[1024] = {0};
	name = NULL == name ? name : base64_encode(name);
	sprintf(url,"%s?id=%d&name=%s&safemode=%d&pwd=%s&hiddenmode=%d",
	urlSetSSID,id,name,safemode,pwd,hiddenmode);
	//sprintf(url,"%s?id=%d&name=%s&safemode=%d&pwd=%s&hiddenmode=%d",
		//urlSetSSID,id,"shenzhou",safemode,pwd,hiddenmode);
	debug(LOG_DEBUG,"********************************************");
	unsigned char *l = url;
	while(*l != '\0')printf("%.2x\n",*(l++));
	debug(LOG_DEBUG,url);
	debug(LOG_DEBUG,"********************************************");
	char boa_response[2048] = {0};
	boa_GET(url,boa_response);
	return changeSSIDResult(boa_response);
}

//this interface is reserved...
int handle_mac_wb(const char *wb_flag,maclist *head)
{
	if (!wb_flag && !head) return -1;

	//step 1 : update or add to global ruleset
	//step 2 : demonish rules in global chain
	//step 3 : apply them in global chain 

	return 0;
//
	maclist * p = head;
	while(p)
	{	
		//iptables_fw_handle_black_host(1,p->host);
		LOCK_CLIENT_LIST();
		t_client * client = client_dup(client_list_find_by_mac(p->mac));
		UNLOCK_CLIENT_LIST();

		if(!client && !strcmp(wb_flag,"white"))
		{
			LOCK_CONFIG();
			s_config * config = config_get_config();
		        //add_or_update_maclist(config->trustedmaclist,p->mac);	
			UNLOCK_CONFIG();
			fw_allow(client,FW_MARK_KNOWN);
		}
		else if(!client && !strcmp(wb_flag,"black"))
		{
			LOCK_CONFIG();
			s_config * config = config_get_config();
		       // remove_from_maclist(config->trustedmaclist,p->mac);	
			UNLOCK_CONFIG();
			fw_deny(client);
			LOCK_CLIENT_LIST();
			t_client * client = client_dup(client_list_find_by_mac(p->mac));
			UNLOCK_CLIENT_LIST();
		}
		else
		{
			debug(LOG_ERR,"wb_flag should be black/white");
		}

		if(client) free(client);

		p = p->next;
	}
	return 0;
}
static int
_set_mac(const char *wb_flag,cJSON *params,int (*mac_wb_setter)(const char *,maclist *))
{
	//设置mac黑白名单
	maclist * items = NULL;
	char cmd[20] = {0}; 
	sprintf(cmd,"setMAC%sList",wb_flag);
	cJSON * hosts = cJSON_GetObjectItem(params,"items");
	if(hosts == NULL || hosts->type != cJSON_Array)
	{
		debug(LOG_DEBUG,"array required");
		cJSON_AddNumberToObject(opstates,"cmd",0);   
	}
	else
	{
		debug(LOG_DEBUG,"yes it is an array");
		int i = 0;
		int host_size = cJSON_GetArraySize(hosts);	
		for(i = 0;i < host_size;i++)
		{
			maclist *item = (maclist *)malloc(sizeof(maclist));
			if(NULL == item)
			{
				cJSON_AddNumberToObject(opstates,"cmd",-1);   
				return 0;
			}
			
			debug(LOG_DEBUG,"in get array item");
			item->mac = cJSON_GetArrayItem(hosts,i)->valuestring;
			item->next = items == NULL ? NULL : items->next;
			if(!items) items = item;
			else items->next = item;	
			debug(LOG_DEBUG,item->mac);
		}
		cJSON_AddNumberToObject(opstates,"cmd",mac_wb_setter(wb_flag,items));   
	}		
	return 0;
}

int handle_host_wb(const char * wb_flag,hostlist *head)
{
	hostlist * p = head;
	s_config * config = config_get_config();

	//step 1 : update or add to global ruleset
	//step 2 : demonish rules in global chain
	//step 3 : apply them in global chain 
	
	LOCK_CONFIG();
	debug(LOG_INFO,"update or add to global ruleset!");
	t_firewall_ruleset * global_ruleset =get_theRuleSet("global"); 

	debug(LOG_INFO,"after got global ruleset");
	if(!global_ruleset)
	{
		debug(LOG_INFO,"global ruleset is not set,set it!");
		global_ruleset = safe_malloc(sizeof(t_firewall_ruleset));
		global_ruleset->name = "global";	
		
		if(!config->rulesets) config->rulesets = global_ruleset;
        //modified by vtpp ,
		else  {global_ruleset->next = config->rulesets;config->rulesets = global_ruleset;}
	}

	t_firewall_rule *rule = NULL;
	while(p)
	{	
		//iptables_fw_handle_black_host(1,p->host);
		for(rule = global_ruleset->rules;rule != NULL ;rule = rule->next)
		{
			debug(LOG_DEBUG,"rule mask:[%s],p->hostname:[%s]",rule->mask,p->hostname);
			if(!strcmp(rule->mask,p->hostname))
			{
				rule->target = !strcmp(wb_flag,"white") ? TARGET_ACCEPT : TARGET_REJECT;
				break;
			}
		}
		//this host is a new added,create it and add it...
		debug(LOG_INFO,"didn't find the host,this host is a new added,create it and add it...");

		if(!rule)
		{
			t_firewall_rule * new = safe_malloc(sizeof(t_firewall_rule));
			new->target = !strcmp(wb_flag,"white") ? TARGET_ACCEPT : TARGET_REJECT;
			safe_asprintf(&new->mask,"%s",p->hostname);
			new->mask_is_ipset = 0;

			if(!global_ruleset->rules) 
			{
                debug(LOG_INFO,"aaaaaaaaaaa");
				global_ruleset->rules = new;
			}
			else 
			{
				new->next = global_ruleset->rules;
				//global_rules->next = new;
				global_ruleset->rules = new;
                debug(LOG_INFO,"aaaabbbbbbbbbbbbbbbbbbbbbbbbbbbb");
			}
		}

		p = p->next;
	}

    debug(LOG_INFO,"before get ruleset of global");

    rule = get_ruleset("global");

    while(rule)
    {
        debug(LOG_INFO,"rule:%d",rule->mask);
        rule = rule->next; 
    }

    debug(LOG_INFO,"after get ruleset of global");


	UNLOCK_CONFIG();

	debug(LOG_INFO,"demonish rules in global chain");
	iptables_demonish_chain(CHAIN_GLOBAL);

	debug(LOG_INFO,"apply them in global chain");
	iptables_create_chain(FWRULESET_GLOBAL, CHAIN_GLOBAL);

	LOCK_CONFIG();
	char *config_file = safe_strdup(config->configfile);
	UNLOCK_CONFIG();
	config_write(config_file);free(config_file);

	return 0;
}

static int
_set_host(const char *wb_flag,cJSON *params,int (*host_wb_setter)(const char *,hostlist *))
{
	//设置白名单
	hostlist * items = NULL;
	char cmd[20] = {0}; 
	sprintf(cmd,"set%sList",wb_flag);
	cJSON * hosts = cJSON_GetObjectItem(params,"items");
	if(hosts == NULL || hosts->type != cJSON_Array)
	{
		debug(LOG_DEBUG,"array required");
		return -1;
	}
	else
	{
		debug(LOG_DEBUG,"yes it is an array");
		int i = 0;
		int host_size = cJSON_GetArraySize(hosts);	
		for(i = 0;i < host_size;i++)
		{
			hostlist *item = (hostlist *)malloc(sizeof(hostlist));
			if(NULL == item)
			{
				return -1;
			}
			
			debug(LOG_DEBUG,"in get array item");
			item->hostname = cJSON_GetArrayItem(hosts,i)->valuestring;
			item->next = items == NULL ? NULL : items->next;
			if(!items) items = item;
			else items->next = item;	
			debug(LOG_DEBUG,item->hostname);
		}
		return handle_host_wb(wb_flag,items);
	}		
}

int showDriverSSID()
{
    return changeSSID(1,NULL,NULL,2,0);
}

int shutdownAuth(int authswitch)
{
	s_config *config = config_get_config();
	LOCK_CONFIG();
	char *config_file = safe_strdup(config->configfile);
	config->require_auth = authswitch;
	UNLOCK_CONFIG();
	if(authswitch == 1)
	{
		iptables_fw_init();
	}
	else
	{
		iptables_shutdown_auth();
	}

	config_write(config_file);free(config_file);
	return 0;
}

int setHeartBeatInterval(int sec)
{
	s_config *config = config_get_config();
	LOCK_CONFIG();
	char *config_file = safe_strdup(config->configfile);
	config->checkinterval = sec;
	UNLOCK_CONFIG();
	config_write(config_file);free(config_file);
	return 0;
}


int setBandwidth(int type,int upload,int download)
{

	s_config *config = config_get_config();
	LOCK_CONFIG();
	char *config_file = safe_strdup(config->configfile);
	if(1 == type)
	{	
		printf("#### iton %s:%d type==1 upload=%d,download=%d\n",__func__,__LINE__,upload,download);
		config->clientupload = upload;
		config->clientdownload = download;
	}
	else
	{
		printf("#### iton %s:%d type=!=1 upload=%d,download=%d\n",__func__,__LINE__,upload,download);
		config->deviceupload = upload;
		config->devicedownload = download;
	}
	UNLOCK_CONFIG();

	printf("#### iton %s:%d\n",__func__,__LINE__);
	tc_init_rules();
	config_write(config_file);free(config_file);
	printf("#### iton %s:%d\n",__func__,__LINE__);
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
		debug(LOG_ERR, "##############strJson=%s\n", strJson);
		debug(LOG_ERR,"Provided is an invalid JSON string!\n"); 
		return -1;
	}

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
			cJSON * boot_flag = cJSON_GetObjectItem(opstates,"restartDevice");
			
			if(boot_flag && boot_flag->type != cJSON_NULL) 
			{
				debug(LOG_DEBUG,"this cmd session require device to reboot!Set the reboot flag!");
				reboot_flag = 1;
			}

			cJSON * update_soft_flag = cJSON_GetObjectItem(opstates,"updateSoftwareFromUrl");
			
			if(update_soft_flag && update_soft_flag->type != cJSON_NULL) 
			{
				debug(LOG_DEBUG,"this cmd session require device to update software,this action will reboot the device!");
				reboot_flag = 2;
			}
			cJSON * reset_flag = cJSON_GetObjectItem(opstates,"resetDevice");
			
			if(reset_flag && reset_flag->type != cJSON_NULL) 
			{
				debug(LOG_DEBUG,"this cmd session require device to reset,this action will reboot the device!");
				reboot_flag = 3;
			}
			cJSON * changessid_flag = cJSON_GetObjectItem(opstates,"changeSSID");
			
			if(changessid_flag && changessid_flag->type != cJSON_NULL) 
			{
				debug(LOG_DEBUG,"this cmd session require device to reboot,this action will reboot the device!");
				reboot_flag = 4;
			}

			cJSON * showdriverssid_flag = cJSON_GetObjectItem(opstates,"showDriverSSID");
			
            if(showdriverssid_flag && showdriverssid_flag->type != cJSON_NULL) 
			{
				debug(LOG_DEBUG,"this cmd session require device to reboot,this action will reboot the device!");
				reboot_flag = 5;
			}

			cJSON_Delete(opStateSet);opStateSet = NULL;
		}	
		return 0;
	}
	else
	{
		if(opStateSet == NULL) opStateSet = cJSON_CreateObject();
		reboot_flag = 0;
	}

	debug(LOG_INFO,"init the commands response json objects...");
	cJSON_AddNumberToObject(opStateSet,"opIndex",opset_index); 
	cJSON_AddItemToObject(opStateSet,"opStates",opstates = cJSON_CreateObject()); 

	if((params = cJSON_GetObjectItem(operations,"resetDevice")))
	{
		//重置设备系统
		cJSON_AddNumberToObject(opstates,"resetDevice",0); 
		//cJSON_AddNumberToObject(opstates,"resetDevice",resetDevice()); 
	}

	printf("#### iton %s:%d\n",__func__,__LINE__);//jyqi	
	if((params = cJSON_GetObjectItem(operations,"restartDevice")))
	{
		//重启设备系统
		//cJSON_AddNumberToObject(opstates,"restartDevice",restartDevice()); 
		cJSON_AddNumberToObject(opstates,"restartDevice",0); 

	}

// TO FIX:suppose update will succeed is stupid,but temporally I'm a fool! 

	if((params=cJSON_GetObjectItem(operations,"updateSoftwareFromUrl")))
	{
		printf("#### iton %s:%d\n",__func__,__LINE__);//jyqi	
		new_software_url = cJSON_GetObjectItem(params,"url")->valuestring;
		new_software_md5 = cJSON_GetObjectItem(params,"md5")->valuestring;
		cJSON_AddNumberToObject(opstates,"updateSoftwareFromUrl",0);
//		cJSON_AddNumberToObject(opstates,"updateSoftwareFromUrl",updateSoftwareFromUrl(soft_url,md5_value));
	}


	if((params=cJSON_GetObjectItem(operations,"changeWifiMode")))
	{
		int wifi_mode = cJSON_GetObjectItem(params,"mode")->valueint;
		cJSON_AddNumberToObject(opstates,"changeWifiMode",\
                                changeWifiMode(wifi_mode));
	}

	if((params=cJSON_GetObjectItem(operations,"changeSSID")))
	{
		//修改ssid设置
		int ret = 0;
		CHANGESSID_JSON = cJSON_Duplicate(params,1);
		cJSON_AddNumberToObject(opstates,"changeSSID",0); 
	}

	if((params=cJSON_GetObjectItem(operations,"setHostBlackList")))
	{
		cJSON_AddNumberToObject(opstates,"setHostBlackList",\
					_set_host("black",params,handle_host_wb));   

	}

	if((params=cJSON_GetObjectItem(operations,"setHostWhiteList")))
	{
		cJSON_AddNumberToObject(opstates,"setHostWhiteList",\
					_set_host("white",params,handle_host_wb));   
	}

	if((params=cJSON_GetObjectItem(operations,"setMACBlackList")))
	{
		cJSON_AddNumberToObject(opstates,"setMACBlackList",\
					_set_mac("black",params,handle_mac_wb));   
	}

	if((params=cJSON_GetObjectItem(operations,"setMACWhiteList")))
	{
		cJSON_AddNumberToObject(opstates,"setMACWhiteList",\
					_set_mac("white",params,handle_mac_wb));   
	}

	if((params=cJSON_GetObjectItem(operations,"shutdownAuth")))
	{
		//关闭设备认证
		int authswitch = cJSON_GetObjectItem(params,"authflag")->valueint;
		cJSON_AddNumberToObject(opstates,"shutdownAuth",shutdownAuth(authswitch));			 
	}

	if((params=cJSON_GetObjectItem(operations,"setHeartBeatInterval")))
	{
		//设置心跳周期
		int sec = cJSON_GetObjectItem(params,"sec")->valueint;
		cJSON_AddNumberToObject(opstates,"setHeartBeatInterval",setHeartBeatInterval(sec) );
	}

	if((params=cJSON_GetObjectItem(operations,"showDriverSSID")))
	{
		cJSON_AddNumberToObject(opstates,"showDriverSSID",0);
	}

	if((params=cJSON_GetObjectItem(operations,"changeAuthServer")))
	{
		cJSON * hostname = cJSON_GetObjectItem(params,"hostname");
		cJSON * path = cJSON_GetObjectItem(params,"path");
		cJSON * login = cJSON_GetObjectItem(params,"loginscriptpathfragment");
		cJSON * driver = cJSON_GetObjectItem(params,"driverscriptpathfragment");
		cJSON * portal = cJSON_GetObjectItem(params,"portalscriptpathfragment");
		cJSON * msg = cJSON_GetObjectItem(params,"msgscriptpathfragment");
		cJSON * ping = cJSON_GetObjectItem(params,"pingscriptpathfragment");
		cJSON * auth = cJSON_GetObjectItem(params,"authscriptpathfragment");

		if(hostname == NULL || hostname->type == cJSON_NULL || 
					path == NULL || path->type == cJSON_NULL)
		{
			debug(LOG_ERR,"neither of hostname and path be null and their values be null!");
			cJSON_AddNumberToObject(opstates,"changeAuthServer",-1);
		}

		if(!login || !driver || !portal || !msg || !ping || !auth)
		{
			debug(LOG_ERR,"neither of login/driver/portal/msg/ping/auth should be null!");
			cJSON_AddNumberToObject(opstates,"changeAuthServer",-1);
		}

		t_auth_serv * s = (t_auth_serv *)safe_malloc(sizeof(t_auth_serv));
		if(!hostname->valuestring)
		{
			debug(LOG_ERR,"fatal error:hostname should never be null...");
			cJSON_AddNumberToObject(opstates,"changeAuthServer",-1);
			free(s);
			return 0;
		}
			
		s->authserv_hostname = safe_strdup(hostname->valuestring);

		s->authserv_path  = path->valuestring \
				?	safe_strdup(path->valuestring) \
				:	safe_strdup(DEFAULT_AUTHSERVPATH);
		s->authserv_login_script_path_fragment = login->valuestring \
				?	safe_strdup(login->valuestring)\
				:	safe_strdup(DEFAULT_AUTHSERVLOGINPATHFRAGMENT);
		s->authserv_driver_script_path_fragment = driver->valuestring\
				?	safe_strdup(driver->valuestring)\
				:	safe_strdup(DEFAULT_AUTHSERVDRIVERPATHFRAGMENT);
		s->authserv_portal_script_path_fragment = portal->valuestring\
				?	safe_strdup(portal->valuestring)\
				:	safe_strdup(DEFAULT_AUTHSERVPORTALPATHFRAGMENT);
		s->authserv_msg_script_path_fragment = msg->valuestring\
				?	safe_strdup(msg->valuestring)\
				:	safe_strdup(DEFAULT_AUTHSERVMSGPATHFRAGMENT);
		s->authserv_ping_script_path_fragment =ping->valuestring\
				?	safe_strdup(ping->valuestring)\
				:	safe_strdup(DEFAULT_AUTHSERVPINGPATHFRAGMENT);
		s->authserv_auth_script_path_fragment = auth->valuestring\
				?	safe_strdup(auth->valuestring)\
				:	safe_strdup(DEFAULT_AUTHSERVAUTHPATHFRAGMENT);

		t_auth_serv *auth_server = NULL;
		auth_server = get_auth_server();
		
		s->authserv_use_ssl 	=	DEFAULT_AUTHSERVSSLAVAILABLE;
		s->authserv_http_port 	= 	auth_server->authserv_http_port;
		s->authserv_ssl_port 	= 	DEFAULT_AUTHSERVSSLPORT;

		cJSON_AddNumberToObject(opstates,"changeAuthServer",setAuthServer(s));
	}

	if((params=cJSON_GetObjectItem(operations,"setBandwidth")))
	{		
		cJSON * qos0 = cJSON_GetObjectItem(params,"chemiaoqos0");
		int result = 0;
		if(qos0 != NULL && qos0->type != cJSON_NULL)
		{
			printf("#### iton %s:%d\n",__func__,__LINE__);//jyqi	
			result = setBandwidth(0,	
				cJSON_GetObjectItem(qos0,"upload")->valueint,
				cJSON_GetObjectItem(qos0,"download")->valueint
				);
		}
		if(0==result)
		{
			cJSON * qos1 = cJSON_GetObjectItem(params,"chemiaoqos1");
			if(qos1 != NULL && qos1->type != cJSON_NULL)
			{
				printf("#### iton %s:%d\n",__func__,__LINE__);//jyqi	
				result = setBandwidth(1,	
					cJSON_GetObjectItem(qos1,"upload")->valueint,
					cJSON_GetObjectItem(qos1,"download")->valueint
					);
			}
		}

		cJSON_AddNumberToObject(opstates,"setBandwidth",result);
	}

	debug(LOG_INFO,cJSON_Print(opStateSet));
	return 0;
}


int pingserver()
{
	char strJson[LENGTH]={0};
	char strJsonBase64[MAX_BUF]={0};
	char decode_out[MAX_BUF]={0};
	char server_response[2048]={0};
	base64_encodestate state;
	base64_decodestate state_d;
	t_auth_serv *auth_server = NULL;
	auth_server = get_auth_server();
	static int authdown = 0;
	int sockfd;

	sockfd = connect_auth_server();
	if (sockfd == -1) {
		/*
		 * No auth servers for me to talk to
		 */
		if (!authdown) {
		    fw_set_authdown();
		    authdown = 1;
		}
		return -1;
	}

	char url[100]={0};

//	sprintf(url,"http://%s/chemiao/device/ping",auth_server->authserv_hostname);

	sprintf(url, "http://%s:%d%sdevice/ping", auth_server->authserv_hostname,
		auth_server->authserv_http_port, auth_server->authserv_path);

	printf("$$$$$$$$$$$$$$$url=%s\n", url);

	packageJson(strJson);

	base64_init_encodestate(&state);
	memset(strJsonBase64,0,sizeof(strJsonBase64));
	base64_encode_block(strJson,strlen(strJson),strJsonBase64,&state);
	base64_encode_blockend(strJsonBase64,&state);
	base64_init_encodestate(&state);
	curlPostJson(strJsonBase64,url,server_response);

	if(1 == reboot_flag) 
	{
		debug(LOG_DEBUG,"Server already stop the current session,it's time to reboot the system!");
		return reboot();
	}
	else if(2 == reboot_flag)
	{
		debug(LOG_DEBUG,"Server already stop the current session,it's time to update the software!");
		reboot_flag = 0;
		updateSoftwareFromUrl(new_software_url,new_software_md5);
	}
	else if(3 == reboot_flag)
	{
		debug(LOG_DEBUG,"Server already stop the current session,it's time to reset the device!");
        resetDevice();
	}
	else if(4 == reboot_flag)
	{
		debug(LOG_DEBUG,"Server already stop the current session,it's time to change the ssid!");
        apply_changeSSID();  
	}
	else if(5 == reboot_flag)
	{
		debug(LOG_DEBUG,"Server already stop the current session,it's time to change the ssid!");
        showDriverSSID();  
	}

	base64_init_decodestate(&state_d);
	base64_decode_block(server_response, strlen(server_response), decode_out, &state_d);
	base64_init_decodestate(&state_d);
	printf("#### iton server sentinel.c %s:%d \n",__func__,__LINE__);
	printf("server response is:%s\n",decode_out);
	return cmdParsing(decode_out);
};
