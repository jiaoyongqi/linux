#include "device_manager.h"

#include <stdarg.h>

static void t_printchar(char **str, int c)
{
	//extern int putchar(int c);
	
	if (str) {
		**str = c;
		++(*str);
	}
	else (void)putchar(c);
}

#define PAD_RIGHT 1
#define PAD_ZERO 2

static int t_prints(char **out, const char *string, int width, int pad)
{
	register int pc = 0, padchar = ' ';

	if (width > 0) {
		register int len = 0;
		register const char *ptr;
		for (ptr = string; *ptr; ++ptr) ++len;
		if (len >= width) width = 0;
		else width -= len;
		if (pad & PAD_ZERO) padchar = '0';
	}
	if (!(pad & PAD_RIGHT)) {
		for ( ; width > 0; --width) {
			t_printchar (out, padchar);
			++pc;
		}
	}
	for ( ; *string ; ++string) {
		t_printchar (out, *string);
		++pc;
	}
	for ( ; width > 0; --width) {
		t_printchar (out, padchar);
		++pc;
	}

	return pc;
}

/* the following should be enough for 32 bit int */
#define PRINT_BUF_LEN 12

static int t_printi(char **out, int i, int b, int sg, int width, int pad, int letbase)
{
	char print_buf[PRINT_BUF_LEN];
	register char *s;
	register int t, neg = 0, pc = 0;
	register unsigned int u = i;

	if (i == 0) {
		print_buf[0] = '0';
		print_buf[1] = '\0';
		return t_prints (out, print_buf, width, pad);
	}

	if (sg && b == 10 && i < 0) {
		neg = 1;
		u = -i;
	}

	s = print_buf + PRINT_BUF_LEN-1;
	*s = '\0';

	while (u) {
		t = u % b;
		if( t >= 10 )
			t += letbase - '0' - 10;
		*--s = t + '0';
		u /= b;
	}

	if (neg) {
		if( width && (pad & PAD_ZERO) ) {
			t_printchar (out, '-');
			++pc;
			--width;
		}
		else {
			*--s = '-';
		}
	}

	return pc + t_prints (out, s, width, pad);
}

static int t_print( char **out, const char *format, va_list args )
{
	register int width, pad;
	register int pc = 0;
	char scr[2];

	for (; *format != 0; ++format) {
		if (*format == '%') {
			++format;
			width = pad = 0;
			if (*format == '\0') break;
			if (*format == '%') goto out;
			if (*format == '-') {
				++format;
				pad = PAD_RIGHT;
			}
			while (*format == '0') {
				++format;
				pad |= PAD_ZERO;
			}
			for ( ; *format >= '0' && *format <= '9'; ++format) {
				width *= 10;
				width += *format - '0';
			}
			if( *format == 's' ) {
				register char *s = (char *)va_arg( args, int );
				pc += t_prints (out, s?s:"(null)", width, pad);
				continue;
			}
			if( *format == 'd' ) {
				pc += t_printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
				continue;
			}
			if( *format == 'x' ) {
				pc += t_printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
				continue;
			}
			if( *format == 'X' ) {
				pc += t_printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
				continue;
			}
			if( *format == 'u' ) {
				pc += t_printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
				continue;
			}
			if( *format == 'c' ) {
				/* char are converted to int then pushed on the stack */
				scr[0] = (char)va_arg( args, int );
				scr[1] = '\0';
				pc += t_prints (out, scr, width, pad);
				continue;
			}
		}
		else {
		out:
			t_printchar (out, *format);
			++pc;
		}
	}
	if (out) **out = '\0';
	va_end( args );
	return pc;
}

int t_printf(const char *format, ...)
{
        va_list args;
        
        va_start( args, format );
        return t_print( 0, format, args );
}

int t_sprintf(char *out, const char *format, ...)
{
        va_list args;
        
        va_start( args, format );
        return t_print( &out, format, args );
}


int t_snprintf( char *buf, unsigned int count, const char *format, ... )
{
        va_list args;
        
        ( void ) count;
        
        va_start( args, format );
        return t_print( &buf, format, args );
}



/** \brief  获取wifidog的MAC地址 */  
int getDeviceMac(char *buf)
{
	int sock_mac;
	struct ifreq ifr_mac;
	struct sockaddr_in  sinMac;
	unsigned char mac[6];
	sock_mac=socket(AF_INET,SOCK_DGRAM,0);
	if(sock_mac<0)
	{
		//debug(LOG_ERR, "create socket false\n");
		printf("create socket false\n");		
		return 0;
	}
	strncpy(ifr_mac.ifr_name,ETHERNETNAME,IFNAMSIZ);

	if((ioctl(sock_mac,SIOCGIFHWADDR,&ifr_mac))<0)
	{
		//debug(LOG_ERR, "mac ioctl false\n");
		printf("mac ioctl false\n");
		return 0;
	}
	memcpy(mac, ifr_mac.ifr_hwaddr.sa_data, 6);
	
	sprintf(buf,"%02x%02x%02x%02x%02x%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	printf("in macRatio the buf is:%s\n",buf);	
	close(sock_mac);
	return 1;
}
 
 
/** \brief  获取wifidog的ip地址
 *
 * \param 
 * \param  
 * \return 0
 *
 */  	
 
int getDeviceIP(char *buf)
{
	int sock_get_ip;
	struct sockaddr_in sin;
	struct ifreq ifr_ip;
	
	if((sock_get_ip=socket(AF_INET,SOCK_STREAM,0))==-1)
	{
		//debug(LOG_ERR, "socket create error\n");
		printf("socket create error\n");
		return 0;		
	}
	
	memset(&ifr_ip,0,sizeof(ifr_ip));
	strncpy(ifr_ip.ifr_name,ETHERNETNAME,IFNAMSIZ);
	
	if(ioctl(sock_get_ip,SIOCGIFADDR,&ifr_ip)<0)
	{
		//debug(LOG_ERR, "ip ioctl error\n");
		printf("ip ioctl error\n");
		return 0;
	}
	memcpy(&sin,&ifr_ip.ifr_addr,sizeof(ifr_ip.ifr_addr));
	strcpy(buf,inet_ntoa(sin.sin_addr));
	close(sock_get_ip);
	
	return 1;
}	

/** \brief  获取CPU信息，计算CPU使用率
 *
 * \param 
 * \param  
 * \return 0
 *
 */  
int getCpuRatio(char *buf)	
{
	FILE *fp;
	char buff[128];
	char cpu[10];
	char temp[20];
	
	long int user,nice,sys,idle,iowait,irq,softirq;
	
	long int all1,all2,idle1,idle2;
	//float usage;
	int usage;
	printf("------cpu Ratio-----\n");	
	if((fp=fopen("/proc/stat","r"))==NULL){
		//debug(LOG_ERR, "open /proc/stat error\n");
		printf("open /proc/stat error\n");
		return 0;
	}

		fgets(buff,sizeof(buff),fp);

		sscanf(buff,"%s%d%d%d%d%d%d%d",cpu,&user,&nice,&sys,&idle,&iowait,&irq,&softirq);
		all1=user+nice+sys+idle+iowait+irq+softirq;
		idle1=idle;
		
		usage=100*(all1-idle1)/all1;
	
		sprintf(temp,"%d%%",usage);
	
	strcpy(buf,temp);
	fclose(fp);

	return 1;	
}	
	
/** \brief  获取内存信息，计算内存使用率
 *
 * \param 
 * \param  
 * \return 0
 *
 */ 
int getMemRatio(char *buf)
{
	FILE *fp;
	char buff_line1[30];
	char buff_line2[30];
	unsigned long int MemTotal,MemFree;
	int memUsage;
	char name[10];
	char kb1[3];
	char kb2[3];
	char temp[10];
	if((fp=fopen("/proc/meminfo","r"))==NULL){
		debug(LOG_ERR, "open /proc/meminfo error\n");
		return 0;
	}
	fgets(buff_line1,sizeof(buff_line1),fp);
	fgets(buff_line2,sizeof(buff_line2),fp);
	
	sscanf(buff_line1,"%s %d %s",name,&MemTotal,kb1);
	sscanf(buff_line2,"%s %d %s",name,&MemFree,kb2);
	memUsage=100*(MemTotal-MemFree)/MemTotal;
		
	sprintf(temp,"%d%%",memUsage);
	strcpy(buf,temp);
	fclose(fp);
	return 1;
}

long int lmi40_receive_basic = 0;
long int lmi40_transmit_basic = 0;

//=================================================================================
// 函数介绍：	WIFI开关
// 参数:		mode值为0表示关掉wifi，为1表示开
// 返回值: 		0表示操作成功，<0 表示操作异常
//=================================================================================

int changeWifiMode(int mode)
{
	// open the radio if mode equal 1 else close it
	char cmd[128] = {0};
	sprintf(cmd,"busybox ifconfig wlan0 %s",mode ? "up" : "down");
	return -1 == system(cmd) ? -1 : 0;
}

int reboot(void)
{
        printf("system will reboot!\n");
        system("sync"); sleep(1);
        return -1 == system("reboot") ? -1 : 0;
}

int reset(void)
{
        printf("device will be recovery!\n");
        sleep(1);
        return -1 == system("/system/bin/tinyrecovery --wipe_data --locale=zh_CN") ?  -1: 0;
}

int get_sim_ip(char *ip, int ip_len)
{
        FILE *fp = NULL;
        char cmd[128] = {0};
        char buf[128] = {0};
        char ip_temp[32] = {0};

        if (NULL == ip) {
                printf("error parameter!\n");
                return -2;
        }

        //   inet addr:10.229.93.50  P-t-P:10.229.93.50  Mask:255.255.255.255
        snprintf(cmd, sizeof(cmd), "busybox ifconfig lmi40 | grep inet");
        fp = popen(cmd, "r");
        if (NULL != fp) {
                fgets(buf, sizeof(buf), fp);
                pclose(fp);
                if (sscanf(buf, "%*[^:]:%s", ip_temp) == 0) {
                        printf("get_sim_ip failed\n");
                        return -1;
                }
                strncpy(ip, ip_temp, ip_len < sizeof(ip_temp)? ip_len : sizeof(ip_temp));
                return 0;
        } else {
                printf("read df msg error\n");
                return -1;
        }
}

int get_imsi(char * imsi_string)
{
        FILE * iccid = NULL;

        //iccid = fopen("/data/var/boa/imsi.txt", "r+");
        iccid = fopen("/data/var/imsi.txt", "r+");//changed by liubofei
        char    line_a[30] = {0};

        if (iccid == NULL)
        {
                printf("open /data/var/boa/imsi.txt fail\n");
                fclose(iccid);
                return -1;
        }
        fseek(iccid,0,0);
        if(fgets(line_a, sizeof(line_a), iccid) != NULL)
        {
                strcpy(imsi_string, line_a);
                fclose(iccid);
                return 0;
        }
        return -1;
}

int get_iccid(char * iccid_string)
{
        FILE * iccid = NULL;

        iccid = fopen(ICCID_FILE, "r+");

        char    line_a[30] = {0};

        if (iccid == NULL)
        {
                printf("open %s fail",ICCID_FILE);
                fclose(iccid);
                return -1;
        }
        fseek(iccid,0,0);
        if(fgets(line_a, sizeof(line_a), iccid) != NULL)
        {
                strcpy(iccid_string, line_a);
                fclose(iccid);
                return 0;
       }
        return -1;
}

//======================================
// 函数介绍：	获取当前设备磁盘占用


//int get_df_msg(char *used_perc)
int getDiscRatio(char *used_perc)
{
	FILE *fp = NULL;
	char cmd[128] = {0};
	char buf[128] = {0};
	float size, used, percent;
	char unit_s, unit_u;
	if (NULL == used_perc) {
		printf("error parameter!\n");
		return -2;
	}

//   /data 415.5M   170.3M   245.2M   4096
	snprintf(cmd, sizeof(cmd), "df | grep data");
	fp = popen(cmd, "r");
	if (NULL != fp) {
		fgets(buf, sizeof(buf), fp);
		pclose(fp);
		if (sscanf(buf, "%*[^ ]%f%c %f%c", &size, &unit_s, &used, &unit_u) == 0)
		{	printf("get_df_msg failed\n");
			return -1;
		}
//		printf("#########size=%f,used=%f\n", size, used);
		if ('M'==unit_s)
			size = size * 1000;
		else if ('G'==unit_s)
			size = size * 1000 * 1000;

		if ('M'==unit_u)
			used = used * 1000;
		else if ('G'==unit_u)
			used = used * 1000 * 1000;


		percent = used / size * 100;
//		printf("percent=%f\n", percent);
		sprintf(used_perc, "%2.0f%%", percent);
		return 0;
	} else {
		printf("read df msg error\n");
		return -1;
	}
}


//=====================================
// 函数介绍：	获取当前设备iccid

//int get_iccid(char * iccid_string)
int getICCID(char * iccid_string)
{
	FILE * iccid = NULL;

	iccid = fopen(ICCID_FILE, "r+");

	char line_a[30] = {0};

	if (iccid == NULL)
	{
		printf("open %s fail",ICCID_FILE);
		fclose(iccid);
		return -1;
	}
	fseek(iccid,0,0);
	if(fgets(line_a, sizeof(line_a), iccid) != NULL)
	{
		strcpy(iccid_string, line_a);
		fclose(iccid);
		return 0;
	}

	return -1;
}

/******get flow********/
 
//long *my_ipconfig(char *ath0) 
long *my_ipconfig(char *ath0) 
{ 
     
    int nDevLen = strlen(ath0); 
    if (nDevLen < 1 || nDevLen > 100) 
    { 
        printf("dev length too long\n"); 
        return NULL; 
    } 
    int fd = open("/proc/net/dev", O_RDONLY | O_EXCL); 
    if (-1 == fd) 
    { 
        printf("/proc/net/dev not exists!\n"); 
        return NULL; 
    } 
     
        char buf[1024*5]; 
        lseek(fd, 0, SEEK_SET); 
        int nBytes = read(fd, buf, sizeof(buf)-1); 
        if (-1 == nBytes) 
        { 
            perror("read error"); 
            close(fd); 
            return NULL; 
        } 
        buf[nBytes] = '\0'; 
        //返回第一次指向ath0位置的指针  
        char* pDev = strstr(buf, ath0); 
        if (NULL == pDev) 
        { 
            printf("don't find dev %s\n", ath0); 
            return NULL; 
        } 
        char *p; 
        char *ifconfig_value; 
        int i = 0; 
        static long rx2_tx10[2]; 
        //去除空格，制表符，换行符等不需要的字段 
        for (p = strtok(pDev, " \t\r\n"); p; p = strtok(NULL, " \t\r\n")) 
        { 
            i++; 
            ifconfig_value = (char*)malloc(20); 
            strcpy(ifconfig_value, p); 
           //得到的字符串中的第二个字段是接收流量 
            if(i == 2) 
            { 
                rx2_tx10[0] = atol(ifconfig_value); 
            } 
            //得到的字符串中的第十个字段是发送流量 
            if(i == 10) 
            { 
                rx2_tx10[1] = atol(ifconfig_value); 
                break; 
            } 
            free(ifconfig_value); 
        }
            close(fd);
        return rx2_tx10; 
}

//=====================================================
// 函数介绍：	获取当前设备消耗流量

//int costed_flow(char *buf, int length)
int getTTraffic(char *buf)//, int length)
{
	long *ifconfig_result;
	long int lmi40_receive_basic = 0;
	long int lmi40_transmit_basic = 0;
	long int receive_get = 0;   
	long int transmit_get = 0;
	long int receive_flow = 0;   
	long int transmit_flow = 0;
	char total_flow[128] = {0};
	FILE *fp_t, *fp_r;

	if (NULL == buf) {
		printf("error parameter!\n");
		return -1;
	}
	
	// first we can get the total cost of flow
	if (NULL == (ifconfig_result = my_ipconfig("lmi40"))) {
		puts("get lmi40 value error!");
		return -3;
	}
	
	receive_get = ifconfig_result[0];
	transmit_get = ifconfig_result[1];

	printf("#### iton111 %s:%d receive_get=%d,transmit_get=%d,lmi40_transmit_basic=%d,lmi40_receive_basic=%d\n",__func__,__LINE__,receive_get,transmit_get,lmi40_transmit_basic,lmi40_receive_basic);


	
	// 	if the file is not existence,the first cost
	if ((0 != access(TRANSMIT, F_OK)) && (0 != access(RECEIVE, F_OK))) {
		
		lmi40_transmit_basic = transmit_flow = transmit_get;
		lmi40_receive_basic = receive_flow = receive_get;
		
		printf("#### iton222 %s:%d receive_get=%d,transmit_get=%d,lmi40_transmit_basic=%d,lmi40_receive_basic=%d\n",__func__,__LINE__,receive_get,transmit_get,lmi40_transmit_basic,lmi40_receive_basic);

			
		fp_t = fopen(TRANSMIT, "wb");
		fp_r = fopen(RECEIVE, "wb");
//
		if (!fp_t || !fp_r ) {
			printf("(line%d:)File open error!\n", __LINE__);
			return -2;
		}
		if((fwrite(&lmi40_transmit_basic, sizeof(lmi40_transmit_basic), 1, fp_t) != 1) ||
			(fwrite(&lmi40_receive_basic, sizeof(lmi40_receive_basic), 1, fp_r) != 1)) {
    		printf("(line%d:)fwrite file error!\n", __LINE__);

		}
		
		fclose(fp_t);
		fclose(fp_r);
	}
	else {
		printf("#### iton333 %s:%d receive_get=%d,transmit_get=%d,lmi40_transmit_basic=%d,lmi40_receive_basic=%d\n",__func__,__LINE__,receive_get,transmit_get,lmi40_transmit_basic,lmi40_receive_basic);

		fp_t = fopen(TRANSMIT, "rb");
		fp_r = fopen(RECEIVE, "rb");
		if (!fp_t || !fp_r ) {
			printf("(line%d:)File open error!\n", __LINE__);
			return -2;
		}
	
		// read the last cost
		if((fread(&lmi40_transmit_basic, sizeof(lmi40_transmit_basic), 1, fp_t) != 1) ||
			(fread(&lmi40_receive_basic, sizeof(lmi40_receive_basic), 1, fp_r) != 1)) {
			printf("(line%d:)fread file error!\n", __LINE__);

		}
		fclose(fp_t);
		fclose(fp_r);
		
		// 大于之前的值为累加的流量
		if (receive_get >= lmi40_receive_basic)
			receive_flow = receive_get - lmi40_receive_basic;
		// 掉线，流量重新计算
		else
			receive_flow = receive_get;
		lmi40_receive_basic = receive_get;
	
		if (transmit_get >= lmi40_transmit_basic)
			transmit_flow = transmit_get - lmi40_transmit_basic;
		else
			transmit_flow = transmit_get;
		lmi40_transmit_basic = transmit_get;

		system("rm -rf "TRANSMIT);
		system("rm -rf "RECEIVE);
		fp_t = fopen(TRANSMIT, "wb");
		fp_r = fopen(RECEIVE, "wb");
		if (!fp_t || !fp_r ) {
			printf("(line%d:)File open error!\n", __LINE__);
			return -2;
		}

		// save the cost flow on the device
		if((fwrite(&lmi40_transmit_basic, sizeof(lmi40_transmit_basic), 1, fp_t) != 1) ||
			(fwrite(&lmi40_receive_basic, sizeof(lmi40_receive_basic), 1, fp_r) != 1)) {
			printf("(line%d:)fwrite file error!\n", __LINE__);

		}

		fclose(fp_t);
		fclose(fp_r);

	}

	sprintf(total_flow,"%ld",(receive_flow+transmit_flow));
	strcpy(buf, total_flow);
	return 0;
}




int parsed_string_enter(char * string,char **num)
{
	char *p = NULL;
	char old_space[12] = "***1*2*3***";
	char new_space[1] ={0};	
	char* src[256*3] = {string, NULL};
	int i=0;
	for(i=0;(num[i]=strtok(src[i!=0],"\n\r")); i++)
	{
		if(strcmp(num[i],old_space)== 0)
		{
			strcpy(num[i],new_space);		
		}
		// printf("num[%d] =%s\n",i,num[i]);
	}
	return 0;
}

//=================================================================================
// 函数介绍：	获取当前设备imei信息
// 输出参数：	待写入imei信息的地址 value
// 输入参数:	
// 返回值：		0:成功	-1:参数错误	-2:获取失败=================================================================================
int getIMEI(char * value)
{
	FILE	*fp = NULL;
	char	line_a[32] = {0};
	char * num[10] = {0};
	char   get_string[32] = {0};

	fp = fopen(IMEI_ADDR_FILE, "r");
	if (fp == NULL) {
		printf("open %s fail\n",IMEI_ADDR_FILE);
		fclose(fp);
		return -1;
	}
	fseek(fp,0,0);
	if (fgets(line_a, sizeof(line_a) - 1, fp) != NULL) {
		strcpy(get_string, line_a);
		fclose(fp);
		parsed_string_enter(get_string, num);
		printf("***********value:%s\n",*num);
		//strncpy(value, num[0], sizeof(value));
		strcpy(value, num[0]);
		return 0;	
	}
	fclose(fp);
	return -1;
}

//=================================================================================
// 函数介绍：	获取当前设备版本信息
// type = 0，软件。 type 非 0，硬件 
int get_Version(int type, char * fwversion)
{

	char ch[20]={0};
	char *st=NULL;
	char* bufTmp = NULL;
	char *destBuf = NULL;
	char destBuf_t[100] = {0x00};
	
	FILE *fp;
	struct stat statbuf;

	if((fp=fopen("/system/build.prop","r"))==NULL)
	{
		printf("fwVersion open file error!\n");
	}
	
	//ALOGE("fwVersion 0 open file error!\n");
	stat("/system/build.prop", &statbuf);
	//ALOGE("fwVersion 1 open file error!\n");
	
	
	st=(char*)malloc(statbuf.st_size);
	destBuf=(char*)malloc(2048);
	
	//printf("fwVersion 2 open file error  %d!\n" ,statbuf.st_size);
	
	fread(st,1,statbuf.st_size,fp);
	
	//printf("fwVersion 3 open file error  %d!\n" ,statbuf.st_size);
	fclose(fp);

	if (type) {
		bufTmp = strstr(st,"ro.product.hardware.version=");
	} else {
		bufTmp = strstr(st,"ro.build.display.id=");
	}

	//	strncat(destBuf,bufTmp,100);
	
	sscanf(bufTmp, "%[^/\n]", destBuf); 
	//	sscanf(destBuf, "%*[^=]=%[]",destBuf_t); 
	if(type){
		strncpy(destBuf_t,destBuf+28,strlen(destBuf+28));
	}else{
		strncpy(destBuf_t,destBuf+20,strlen(destBuf+20));
	}
	
//	printf("fwVersion:%s n",destBuf_t);
	free(st);
	free(destBuf);

	strcpy(fwversion,destBuf_t);

	return 0;
}

static size_t handleBoaResponse(void *ptr,size_t size, size_t nitems, void *stream)
{
	int res_size;
	res_size = size * nitems;
	strcat(stream,ptr);
	return size * nitems;
}

size_t boa_GET(char *url,char *outstream)
{
	CURL *curl;
	CURLcode res;
	
	if(url==NULL) return -1;
	if (CURLE_OK != (res=curl_global_init(CURL_GLOBAL_ALL))) return -1;

	//初始化一个CURL类型的指针
	if(NULL == (curl=curl_easy_init())) return -1;

	//设置curl选项，CURLOPT_URL
	curl_easy_setopt(curl,CURLOPT_URL,url);
	//设置超时时间为1秒 
	curl_easy_setopt(curl, CURLOPT_TIMEOUT,1);  
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, handleBoaResponse);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, outstream);

	//执行设置，进行相关操作
	if (CURLE_OK != (res = curl_easy_perform(curl)))  
	{  
		curl_easy_cleanup(curl);
		curl_global_cleanup();
		return -1;
	} 

	curl_easy_cleanup(curl);curl_global_cleanup();
	return 1;
}

int getBaseInfo(char *strJson,char *retCardinfo,char *retSig_strength,char *retNetwork)
{
	if(strJson == NULL) return -1;
	printf("getBaseInfo:%s\n",strJson);
	int sig_strength,card_status,num_phone;
	char card_info[30]; char use_flow[20]; char plmn[15]; char network[20];
		
	cJSON *root=cJSON_Parse(strJson);
	if(root == NULL) return -1;
	
	cJSON *code = cJSON_GetObjectItem(root,"code");
	cJSON *params = cJSON_GetObjectItem(root,"result");

	if(code->type == cJSON_NULL || params->type == cJSON_NULL) return -1;
	
	sig_strength=cJSON_GetObjectItem(params,"sig_strength")->valueint;
	card_status=cJSON_GetObjectItem(params,"card_status")->valueint;
	num_phone=cJSON_GetObjectItem(params,"num_phone")->valueint;
	strcpy(card_info,cJSON_GetObjectItem(params,"card_info")->valuestring);
	strcpy(use_flow,cJSON_GetObjectItem(params,"use_flow")->valuestring);
	strcpy(plmn,cJSON_GetObjectItem(params,"plmn")->valuestring);
	strcpy(network,cJSON_GetObjectItem(params,"network")->valuestring);
	
	if(!strlen(card_info))
	{
		strcpy(retCardinfo,plmn);
		strcat(retCardinfo,network);
	}
	else
	{
		strcpy(retCardinfo,card_info);
	}

	sprintf(retSig_strength,"%d",sig_strength);
	strcpy(retNetwork,network);
	return 1;
}



/** \brief getBaseInfo解析
 * \param     strJson:要解析的
 * \param     retCardinfo:要返回的运营商信息
 * \param     retSig_strength:要返回的信号强度
 * \param     retNetwork：要返回的网络制式
 * \return  
 *
 */  

int changeSSIDResult(char *strJson)
{
	if(strJson==NULL) return -1;
	printf("response is:%s\n",strJson);
	printf("\nhahahahaha\n");
	cJSON *root=cJSON_Parse(strJson);
	if(root == NULL) return -1;
	printf("\nhahahahaha\n");
	cJSON *code = cJSON_GetObjectItem(root,"code");
	if(code->type == cJSON_NULL) return -1;
	printf("\nhahahahaha:%d\n",code->valueint);
	return code->valueint == 1 ? 0 : -1;
}


int 
downstatus(int *down_status) 
{
	FILE * svr_addr = NULL;
	char line_a[8] = {0};

	system("chmod 777 /data/var/downstatus.txt");
	svr_addr = fopen(DOWN_STATUS_FILE, "r");
	if (svr_addr == NULL) {
		printf("open %s fail\n", DOWN_STATUS_FILE);
		fclose(svr_addr);
		return -1;
	}

	fseek(svr_addr, 0, 0);
	fgets(line_a, sizeof(line_a), svr_addr);
	fclose(svr_addr);
	
	printf("atoi downstatus file stat=%d\n", atoi(line_a));
	*down_status = atoi(line_a);
	
	return 0;
}

void clear_crlf(char *str)
{
	if(!str)
		return;
	
	while(*str++ != '\0'){
		if(*str == '\n')
			*str ='\0';
	}

	return;
}


//=================================================================================
// 函数介绍：	获取指定文件的 md5 值
// 输入参数：	文件路径	path
// 输出参数:	待写入 md5 值的地址	md5
//				写入的长度 buf_len
// 返回值：		0:成功	-1:参数错误	-2:文件不存在
//=================================================================================
int get_file_md5(char *path, char *md5, int buf_len)
{
	FILE *fp = NULL;
	char cmd_sum[256] = {0};
	char real_md5[64] = {0};
	
	if(!path || !md5) {
//		debug(LOG_ERR, "get md5 func: arg error.");
		return -1;
	}
	
	if(0 != access(path, F_OK)) {
//		debug(LOG_ERR, "get md5 func: file %s not found.", path);
		return -2;
	}
	
	snprintf(cmd_sum, sizeof(cmd_sum), "busybox md5sum %s | busybox awk -F\" \" '{print $1}'", path);
	
	fp = popen(cmd_sum, "r");
	if(NULL != fp){
		fgets(real_md5, sizeof(real_md5), fp);	
		clear_crlf(real_md5);
		pclose(fp);
		fp = NULL;
//		debug(LOG_INFO, "real md5=%s.", real_md5);
		strncpy(md5, real_md5, buf_len < sizeof(real_md5)?buf_len:sizeof(real_md5));
	}else{
//		debug(LOG_ERR, "read real md5 error.");
	}
	
	return 0;
}


void
thread_update(void *arg)
{
	char md5_server[64] = {0};
	char md5[64] = {0};
	char soft_url[128] = {0};
	char cmd[128] = {0};
	int file_stat;
	void **params = NULL;

	params = (void **)arg;
	strncpy(soft_url, *params, 128);
	strncpy(md5_server, *(params + 1), 32);
	free(*params);
	free(params + 1);
	free(params);

//	printf("soft_url=%s\n", soft_url);
//	printf("server md5=%s\n", md5_server);
	
	// At first, we must download the firmware from the url
	snprintf(cmd, sizeof(cmd)-1, "/system/bin/download %s > /data/var/download.log", soft_url);

	system(cmd);
	printf("wait to download the firmware...\n");
	
	// check the rate of progress of download
//	for (downstatus(&file_stat); 1 != file_stat; sleep(10), downstatus(&file_stat));
	
	downstatus(&file_stat);
	if (file_stat) {
		if (0 == get_file_md5(UPDATEFILE, md5, sizeof(md5))) {
			if (0 == strcasecmp(md5, md5_server)) {
				printf("sleep 2 && reboot recovery\n");
				system("/system/bin/tinyrecovery --update_package=CACHE:update.zip --locale=zh_CN");
			}
			else
				printf("md5 is no the same!\n");
		}
	}
	else
		printf("error, download file failed!\n");
	
}




#define		DRIVER		1
#define 	PASSENGER	2


static char *mac_delete_colon(const char *mac)
{
	if(!mac) {
//		debug(LOG_ERR, "convert_mac param ERROR!");
		return NULL;
	}

	char mac_min[28] = {0};
	char *ptr_mac, *ptr_mac_min;

	for (ptr_mac = mac, ptr_mac_min = mac_min; *ptr_mac != '\0'; ptr_mac++) {
		if (*ptr_mac != ':') {
			*ptr_mac_min = *ptr_mac;
			ptr_mac_min++;
		}
	}	
	return safe_strdup(mac_min);
}

//=================================================================================
// 函数介绍：	区分当前连接设备的ssid
// 输出参数：	
// 输入参数:	设备mac地址
// 返回值：	1:DRIVER  2:PASSENGER	-1:失败	-2:参数错误
//=================================================================================

int distinguish_client(const char *mac)
{

	FILE *fp = NULL;
	char cmd[128] = {0};
	char wlan0_hw[1024] = {0};
	char wlan0_va0_hw[1024] = {0};
	char *ptr_mac = NULL;
	
	if (NULL == mac) {
		printf("error parameter!\n");
		return -2;
	}
	
	// we can get the infomation of wlan0
	snprintf(cmd, sizeof(cmd), "cat /proc/wlan0/sta_queinfo | grep hwaddr");
	fp = popen(cmd, "r");
	if (NULL != fp) {
		fread(wlan0_hw, sizeof(wlan0_hw), 1, fp);
		pclose(fp);
//		printf("wlan0_hw=%s\n", wlan0_hw);
	} else {
		printf("read proc msg error\n");
		return -1;
	}

	// we can get the infomation of wlan0-va0
	snprintf(cmd, sizeof(cmd), "cat /proc/wlan0-va0/sta_queinfo | grep hwaddr");
	fp = popen(cmd, "r");
	if (NULL != fp) {
		fread(wlan0_va0_hw, sizeof(wlan0_va0_hw), 1, fp);
		pclose(fp);
	} else {
		printf("read proc msg error\n");
		return -1;
	}

	ptr_mac = mac_delete_colon(mac);
		
	if (NULL != strstr(wlan0_va0_hw, ptr_mac)) {
		free(ptr_mac);
		return DRIVER;
	}
	else if (NULL != strstr(wlan0_hw, ptr_mac)) {
		free(ptr_mac);
		return PASSENGER;
	}
	else {
		free(ptr_mac);
		return -1;
	}
	
}


