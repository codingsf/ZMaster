package com.dx.service;

import com.dx.utils.ZByteArray;

// [int magic][int len]{[short ver][short cmd][var data ... ]}[short crc]
public class ZMsg2 {
    public final static int ZMSG2_MAGIC = 0x47534d5a;
    public final static int ZMSG2_VERSION = 0x0001; // 0.01

    public final static int ZMSG2_SOCKET_PORT = 19002;
    public final static String ZMSG2_BROADCAST_ACTION = "com.dx.zmsg2_action";

    // .... ..xx last 2 bits for conntype
    // xxxx xx device_index
    public final static short ZMSG2_CONNTYPE_LOST = 0;
    public final static short ZMSG2_CONNTYPE_USB = 1;
    public final static short ZMSG2_CONNTYPE_WIFI = 2;

    // flags for alert
    public final static short ZMSG2_ALERT_NONE = 0;
    public final static short ZMSG2_ALERT_ASYNC_DONE = 1;
    public final static short ZMSG2_ALERT_INSTALL_DONE = 2;
    public final static short ZMSG2_ALERT_INSTALL_FAIL = 4;

    public final static short ZMSG2_ALERT_SOUND = 16;
    public final static short ZMSG2_ALERT_VIBRATE = 32;

    public final static short ZMSG2_CMD_RESET_STATUS = 0x1001;
    public final static short ZMSG2_CMD_SET_CONN_TYPE = 0x1002;
    public final static short ZMSG2_CMD_ADD_LOG = 0x1003;
    public final static short ZMSG2_CMD_SET_HINT = 0x1004;
    public final static short ZMSG2_CMD_SET_PROGRESS = 0x1005;
    public final static short ZMSG2_CMD_SET_ALERT = 0x1006;
    public final static short ZMSG2_CMD_ADD_INSTLOG = 0x1007;

    public final static short ZMSG2_CMD_GET_CURTIME = 0x1009;
    public final static short ZMSG2_CMD_SET_TIMEGAP = 0x1010;
    public final static short ZMSG2_CMD_GET_BASICINFO = 0x1011;
    public final static short ZMSG2_CMD_GET_APPINFO = 0x1012;
    public final static short ZMSG2_CMD_GET_APPINFO_NOICON = 0x1013;
    public final static short ZMSG2_CMD_GET_CALLLOG = 0x1014;
    public final static short ZMSG2_CMD_SET_CALLLOG = 0x1015;
    public final static short ZMSG2_CMD_GET_SMSLOG = 0x1016;
    public final static short ZMSG2_CMD_SET_SMSLOG = 0x1017;
    public final static short ZMSG2_CMD_GET_CONTACTS = 0x1018;
    public final static short ZMSG2_CMD_SET_CONTACTS = 0x1019;
    public final static short ZMSG2_CMD_GET_IMAGES = 0x1020;
    public final static short ZMSG2_CMD_GET_VIDEOS = 0x1021;
    public final static short ZMSG2_CMD_GET_IMAGE_THUMBNAIL = 0x1022;

    // zmaster2 shell/root (l)socket cmds
    public final static short ZMSG2_SWITCH_ROOT = 0x2000;
    public final static short ZMSG2_SWITCH_QUEUE = 0x2001;

    public final static short ZMSG2_CMD_GET_ZMINFO = 0x4000;
    public final static short ZMSG2_CMD_QUIT = 0x4001;
    public final static short ZMSG2_CMD_EXEC_QUEUE = 0x4002;

    public final static short ZMSG2_CMD_PUSH = 0x4010;
    public final static short ZMSG2_CMD_PULL = 0x4011;
    public final static short ZMSG2_CMD_SYSCALL = 0x4012;
    public final static short ZMSG2_CMD_EXEC = 0x4013;
    public final static short ZMSG2_CMD_RM = 0x4014;

    public final static short ZMSG2_CMD_INSTALL_APK = 0x4020;
    public final static short ZMSG2_CMD_INST_APK_SYS = 0x4021;
    public final static short ZMSG2_CMD_MOVE_APK = 0x4022;

    public final static short ZMSG2_CMD_GET_PROPS = 0x4030;
    public final static short ZMSG2_CMD_GET_FREESPACE = 0x4031;
    public final static short ZMSG2_CMD_GET_FILEMD5 = 0x4032;
    public final static short ZMSG2_CMD_GET_APKSAMPLE = 0x4033;
    public final static short ZMSG2_CMD_SEARCH_APKSTR = 0x4034;

    public short ver;
    public short cmd;
    public ZByteArray data;

    public ZMsg2() {
        ver = ZMSG2_VERSION;
        cmd = 0;
        data = new ZByteArray();
    }

    public boolean parse(ZByteArray source) {
        if (source.size() < 14) {
            return false;
        }

        int magic = source.getInt(0);
        int len = source.getInt(4);
        if (magic != ZMSG2_MAGIC) {
            int n = source.indexOf(ZByteArray.intToByteArray(ZMSG2_MAGIC));
            if (n != -1) {
                source.remove(0, n);
            } else {
                source.clear();
            }
            return false;
        }

        if (source.size() < len + 10) {
            return false;
        }

        ver = source.getShort(8);
        cmd = source.getShort(10);
        data = source.mid(12, len - 4);

        short crc1 = source.getShort(len + 8);
        short crc2 = source.checksum(8, len);
        if (crc1 != crc2) {
            return false;
        }
        source.remove(0, len + 10);
        return true;
    }

    public ZByteArray getPacket() {
        ZByteArray p = new ZByteArray();
        int len = 4 + data.size();
        p.putInt(ZMSG2_MAGIC);
        p.putInt(len);
        p.putShort(ver);
        p.putShort(cmd);
        p.putBytes(data.getBytes());
        short crc = p.checksum(8, len);
        p.putShort(crc);
        return p;
    }
}
