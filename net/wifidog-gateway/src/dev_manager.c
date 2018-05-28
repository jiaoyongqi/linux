#include "dev_manager.h"
#include "stdlib.h"
int updateSoftwareFromUrl(char *url,char *md5)
{
     if(url == NULL || md5 == NULL) return -1;
     //download software package
     //check the md5 value of the package
     return 0;
}
int resetDevice()
{
     return 0;
}
int restartDevice()
{
    return 0;
} 
int changeSSIDName(char* ssid,char* newName)
{
    return 0;
}
int changeSSIDPwd(char* ssid,char* newPwd)
{
    return 0;
}
int setBlackList(char* items[])
{
    return 0;
}

int setWhiteList(char* items[])
{
    return 0;
}
int changeWifiMode(int mode)
{
    return 0;
}
int changeSSIDSafeMode(int mode)
{
    return 0;
}
int changeSSIDHiddenMode(int mode)
{
    return 0;
}
int shutdownAuth()
{
    return 0;
}

int setHeartBeatInterval(int sec)
{
    return 0;
}
