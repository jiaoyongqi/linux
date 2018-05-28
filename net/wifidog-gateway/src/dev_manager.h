#ifndef DEVICE_MANAGER_H
#define DEVICE_MANAGER_H
int updateSoftwareFromUrl(char *url,char *md5);
int resetDevice();
int restartDevice();
int changeSSIDName(char* ssid,char* newName);
int changeSSIDPwd(char* ssid,char* newPwd);
int setBlackList(char* items[]);
int setWhiteList(char* items[]);
int changeWifiMode(int mode);
int changeSSIDSafeMode(int mode);
int changeSSIDHiddenMode(int mode);
int shutdownAuth();
int setHeartBeatInterval(int sec);
 

#endif
