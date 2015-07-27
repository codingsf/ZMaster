#ifndef ZAPKLSOCKETCLIENT_H
#define ZAPKLSOCKETCLIENT_H

#include "zmsg2.h"

class ZApkLSocketClient
{
    int fd;
public:
    ZApkLSocketClient();
    ~ZApkLSocketClient();

    bool recv(ZMsg2 &msg);
    bool sendAndRecv(ZMsg2 &msg);

    bool resetStatus();
    bool setConnType(u16 index, u16 type);
    bool addLog(char *str);
    bool setHint(char *str);
    bool setProgress(u16 value, u16 subValue, u16 total);
    bool setAlert(u16 type);
};

#endif // ZAPKLSOCKETCLIENT_H
