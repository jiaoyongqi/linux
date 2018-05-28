/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free:Software Foundation; either version 2 of   *
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

/** @internal
  @file main.c
  @brief Entry point only
  @author Copyright (C) 2015 Alexandre Carmel-Veilleux <acv@miniguru.ca>
 */

#include "gateway.h"

/**
  @ changed by liubofei
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <utils/Log.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <android/log.h>
#include <android/log.h>
#define WIFIDOG_LOG  ALOGD
#define  ALOGE(...)  __android_log_print(ANDROID_LOG_ERROR,"egl_fence",__VA_ARGS__)

#define LOGE ALOGE
#define WIFIDOG_LOG  ALOGD
#define TAG "WIFIDOG"

#if 0
int check_call_success()
{
	FILE *fp;
	char str[1024];

	WIFIDOG_LOG(TAG "check_call_success() -----000000\n");             

	system("busybox ifconfig lmi40> /data/var/boa/lmi40_call");
	
    WIFIDOG_LOG(TAG "check_call_success() -----111111\n");             

	fp = fopen("/data/var/boa/lmi40_call", "r");

    WIFIDOG_LOG(TAG "check_call_success() -----222222\n");             

	if (fp < 0 )
	{
		WIFIDOG_LOG(TAG "file open error\n");         
		return 0;
	}

	while (!feof(fp))
	{
		str[0] = '\0';
		fgets(str,1024,fp);

		if ((strstr(str, "Mask")!=NULL) && (strstr(str, "inet addr")!=NULL) && (strstr(str, "P-t-P")!=NULL))
		{
			fclose(fp);
			WIFIDOG_LOG(TAG "---------- call successed ----------\n");			
			//g_call_success = 1; 
			return 1;
		}
	}

	WIFIDOG_LOG(TAG "don't have IP address\n");
	fclose(fp);
	//g_call_success = 0;
	return 0;

		
}

int
main(int argc, char **argv)
{
    int check_call_success_ret = -1;
	        WIFIDOG_LOG(TAG "TAG wifidog----MAIN----start");
    while(1)
    {
        check_call_success_ret = check_call_success();
        if(1 == check_call_success_ret)
        {
	        WIFIDOG_LOG(TAG "TAG have address---main--->call  gw_main(argc, argv);\n");
            sleep(3);
            gw_main(argc, argv);
            break;
        }
        else
        {
	        WIFIDOG_LOG(TAG "TAG don't have IP address---main\n");
            sleep(3);
        }
    }
	        WIFIDOG_LOG(TAG "TAG wifidog----MAIN----exit");
    return 0;
}
#endif

#if 1
int
main(int argc, char **argv)
{
	WIFIDOG_LOG(TAG "-----WIFIDOG-----MAIN----START------\n");
         return gw_main(argc, argv);
	WIFIDOG_LOG(TAG "-----WIFIDOG-----MAIN----ERROR------\n");
}

#endif
