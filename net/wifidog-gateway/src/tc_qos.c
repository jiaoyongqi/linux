/* vim: set et ts=4 sts=4 sw=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id$ */
/** @file tc_qos.c 
    @author Copyright (C) 2016 vtpp
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"
#include "fw_iptables.h"
#include "tc_qos.h"
static int tc_quiet = 0;

//可借用带宽
int  max_up = 450;
int  max_down = 2000;


//jyqi add
static int fw_quiet=0;
static int iptables_time = 0;
static int iptables_clientupload = 0;

static int iptables_do_command(const char *format, ...);

static void
iptables_insert_gateway_id(char **input)
{
    char *token;
    const s_config *config;
    char *buffer;

    if (strstr(*input, "$ID$") == NULL)
        return;

    while ((token = strstr(*input, "$ID$")) != NULL)
        /* This string may look odd but it's standard POSIX and ISO C */
        memcpy(token, "%1$s", 4);

    config = config_get_config();
    safe_asprintf(&buffer, *input, config->gw_interface);

    debug(LOG_DEBUG,buffer);
    free(*input);
    *input = buffer;
}

/** @internal 
 * */
static int
iptables_do_command(const char *format, ...)
{
    va_list vlist;
    char *fmt_cmd;
    char *cmd;
    int rc;

    va_start(vlist, format);
    safe_vasprintf(&fmt_cmd, format, vlist);
    va_end(vlist);

    safe_asprintf(&cmd, "iptables %s", fmt_cmd);
    free(fmt_cmd);

    iptables_insert_gateway_id(&cmd);

    debug(LOG_DEBUG, "Executing command: %s", cmd);

    rc = execute(cmd, fw_quiet);

    if (rc != 0) {
        // If quiet, do not display the error
        if (fw_quiet == 0)
            debug(LOG_ERR, "iptables command failed(%d): %s", rc, cmd);
        else if (fw_quiet == 1)
            debug(LOG_DEBUG, "iptables command failed(%d): %s", rc, cmd);
    }

    debug(LOG_DEBUG, "iptables get here?");
    free(cmd);
    debug(LOG_DEBUG, "iptables get here,too?");

    return rc;
}


//jyqi add end



static int
tc_do_command(const char *format, ...)
{
    va_list vlist;char *fmt_cmd;char *cmd;int rc;

    va_start(vlist, format);
    safe_vasprintf(&fmt_cmd, format, vlist);
    va_end(vlist);

    safe_asprintf(&cmd, "tc %s", fmt_cmd);
    free(fmt_cmd);

    debug(LOG_DEBUG, "Executing command: %s", cmd);

    rc = execute(cmd, 1);

    if (rc != 0) {
        // If quiet, do not display the error
        if (tc_quiet == 0)
            debug(LOG_ERR, "tc command failed(%d): %s", rc, cmd);
        else if (tc_quiet == 1)
            debug(LOG_DEBUG, "tc command failed(%d): %s", rc, cmd);
    }

    free(cmd);
    return rc;
}

void 
tc_init_rules()
{
    tc_clear_rules();
    tc_create_root_rule();
    tc_create_device_rule();
    tc_create_client_rules();
}

void
tc_clear_rules(void)
{
    s_config *config = config_get_config();
    LOCK_CONFIG();
    //tc_do_command("qdisc del dev %s root 2>/dev/null",config->external_interface);
    tc_do_command("qdisc del dev %s root 2>/dev/null",config->gw_interface);
    UNLOCK_CONFIG();
}

// create root rules...
void 
tc_create_root_rule(void)
{	
    s_config *config = config_get_config();
    LOCK_CONFIG();
    //tc_do_command("qdisc add dev %s root handle 1: htb default 256",config->external_interface);
    tc_do_command("qdisc add dev %s root handle 1: htb default 256",config->gw_interface);
    UNLOCK_CONFIG();
}

void
tc_create_device_rule(void)
{
    s_config *config = config_get_config();
    LOCK_CONFIG();
    //tc_do_command("class add dev %s parent 1: classid 1:1 htb rate %dkbit ceil %dkbit",config->external_interface,config->deviceupload*8,config->deviceupload*8);
    //tc_do_command("class add dev %s parent 1: classid 1:2 htb rate %dkbit ceil %dkbit",config->gw_interface,config->devicedownload*8,config->devicedownload*8);
   
    tc_do_command("class add dev %s parent 1: classid 1:1 htb rate %dkbit ceil %dkbit",config->gw_interface,config->devicedownload*8,config->devicedownload*8);
    UNLOCK_CONFIG();
}


static unsigned int ip_start = 100;
//static unsigned int ip_end = 120;
static unsigned int ip_end = 200;


void 
tc_create_client_rules()
{
    s_config *config = config_get_config();
    LOCK_CONFIG();
    unsigned int p = 0;
    char buf[100];

    //先全部删除之前的FORWARD规则
    sprintf(buf,"-F FORWARD",p);
    printf("%s:%d %s\n",__func__,__LINE__,buf);
    iptables_do_command(buf);

    //设置全局上行限速规则
    sprintf(buf,"-A FORWARD -o br0 -m limit --limit %d/s -j ACCEPT",config->deviceupload);
    printf("%s:%d %s\n",__func__,__LINE__,buf);
    iptables_do_command(buf);
    sprintf(buf,"-A FORWARD -o br0 -j DROP");
    printf("%s:%d %s\n",__func__,__LINE__,buf);
    iptables_do_command(buf);
   

    for(p = ip_start;p < ip_end;p++)
    {
  
        //download...
        tc_do_command("class add dev %s parent 1:2 classid 1:2%d htb rate %dkbit ceil %dkbit prio 1",
                            config->gw_interface,p,config->clientdownload*8,config->clientdownload*8);
        tc_do_command("filter add dev %s parent 1: protocol ip prio 100  u32 match ip dst 192.168.0.%d/32 flowid 1:2%d",
                            config->gw_interface,p,p);

	//upload
	iptables_clientupload = ((config->clientupload*2)/3);
	printf("%s:%d %d\n",__func__,__LINE__,iptables_clientupload);
		
	sprintf(buf,"-A FORWARD -s 192.168.0.%d -m limit --limit %d/s -j ACCEPT",p,iptables_clientupload);
	printf("%s:%d %s\n",__func__,__LINE__,buf);
	iptables_do_command(buf);
	sprintf(buf,"-A FORWARD -s 192.168.0.%d -j DROP",p);
	printf("%s:%d %s\n",__func__,__LINE__,buf);
	iptables_do_command(buf);	

    }    
    UNLOCK_CONFIG();
}

