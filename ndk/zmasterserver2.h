#ifndef ZMASTERSERVER2_H
#define ZMASTERSERVER2_H
#if !defined(_WIN32)

#include "zctools.h"
#include "qmutex.h"
#include "zmaster2config.h"
#include "zmsg2.h"

typedef struct ZMINFO {
    int euid;
    int sdk_int;
    int cpu_abi;
    unsigned long long sys_free;
    unsigned long long sys_total;
    unsigned long long tmp_free;
    unsigned long long tmp_total;
    unsigned long long store_free;
    unsigned long long store_total;
    long long mem_freeKB;
    long long mem_totalKB;
    char tmp_dir[256];
    char store_dir[256];
} ZMINFO;

class ZMasterServer2
{
    int server_fd;
    int server_port;
    char server_name[128];
public:
    ZMINFO server_info;
    bool needsQuit;
    bool postDeleteApk;

    QMutex taskMutex;
    QList<ZMsg2 *> taskList;
    pthread_t taskTid;
    bool taskHasError;

    u16 alertType;

    static int getSdkInt();
    bool init();
    ZMasterServer2();
    ~ZMasterServer2();

    bool listen(int port);
    bool listen(char *name);
    void stop();
};

#endif
#endif // ZMASTERSERVER2_H
