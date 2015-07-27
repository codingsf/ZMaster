#ifndef ZMSG2_H
#define ZMSG2_H

#include "zbytearray.h"

#define ZMSG2_MAGIC 0x47534d5a
#define ZMSG2_VERSION 0x0001 // 0.01

// apk local socket cmds
#define ZMSG2_CMD_RESET_STATUS  0x1001
#define ZMSG2_CMD_SET_CONN_TYPE 0x1002
#define ZMSG2_CMD_ADD_LOG       0x1003
#define ZMSG2_CMD_SET_HINT      0x1004
#define ZMSG2_CMD_SET_PROGRESS  0x1005
#define ZMSG2_CMD_SET_ALERT     0x1006
#define ZMSG2_CMD_ADD_INSTLOG   0x1007;

#define ZMSG2_CMD_GET_CURTIME         0x1009;
#define ZMSG2_CMD_SET_TIMEGAP         0x1010;
#define ZMSG2_CMD_GET_BASICINFO       0x1011
#define ZMSG2_CMD_GET_APPINFO         0x1012
#define ZMSG2_CMD_GET_APPINFO_NOICON  0x1013

#define ZMSG2_CMD_GET_CALLLOG         0x1014
#define ZMSG2_CMD_SET_CALLLOG         0x1015
#define ZMSG2_CMD_GET_SMSLOG          0x1016
#define ZMSG2_CMD_SET_SMSLOG          0x1017
#define ZMSG2_CMD_GET_CONTACTS        0x1018
#define ZMSG2_CMD_SET_CONTACTS        0x1019

// zmaster2 shell/root (l)socket cmds
#define ZMSG2_SWITCH_ROOT       0x2000
#define ZMSG2_SWITCH_QUEUE      0x2001

#define ZMSG2_CMD_GET_ZMINFO    0x4000
#define ZMSG2_CMD_QUIT          0x4001
#define ZMSG2_CMD_EXEC_QUEUE    0x4002
#define ZMSG2_CMD_CANCEL_QUEUE  0x4003

#define ZMSG2_CMD_PUSH          0x4010
#define ZMSG2_CMD_PULL          0x4011
#define ZMSG2_CMD_SYSCALL       0x4012
#define ZMSG2_CMD_EXEC          0x4013
#define ZMSG2_CMD_RM            0x4014

#define ZMSG2_CMD_INSTALL_APK   0x4020
#define ZMSG2_CMD_INST_APK_SYS  0x4021
#define ZMSG2_CMD_MOVE_APK      0x4022
#define ZMSG2_CMD_SET_ALERT_TYPE 0x4028

#define ZMSG2_CMD_GET_PROPS     0x4030
#define ZMSG2_CMD_GET_FREESPACE 0x4031
#define ZMSG2_CMD_GET_FILEMD5   0x4032
#define ZMSG2_CMD_GET_APKSAMPLE 0x4033
#define ZMSG2_CMD_SEARCH_APKSTR 0x4034
#define ZMSG2_CMD_GET_FILESIZE  0x4035
#define ZMSG2_CMD_GET_FILELIST  0x4036
#define ZMSG2_CMD_GET_SDCARDLIST 0x4037

#define ZMSG2_CMD_INVOKE_PROTECT 0x4040
#define ZMSG2_CMD_INVOKE_SU      0x4041

class ZMsg2
{
public:
    u16 ver;
    u16 cmd;
    ZByteArray data;

    ZMsg2();

    bool parse(ZByteArray &source);
    ZByteArray getPacket();
};

#endif // ZMSG2_H
