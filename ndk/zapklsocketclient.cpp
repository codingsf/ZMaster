#if !defined(_WIN32)
#include "zapklsocketclient.h"
#include "zmaster2config.h"
#include "msocket.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include "zlog.h"

ZApkLSocketClient::ZApkLSocketClient() {
    DBG("ZApkLSocketClient + %p\n", this);
    fd = -1;
}

ZApkLSocketClient::~ZApkLSocketClient() {
    DBG("ZApkLSocketClient ~ %p\n", this);
    if(fd != -1) {
        ::close(fd);
    }
}

bool ZApkLSocketClient::recv(ZMsg2 &msg) {
    msg.data.clear();
    if(fd == -1) {
        fd = socket_connect("127.0.0.1", ZMASTER2_APK_PORT, 200);
        if(fd == -1) {
            return false;
        }
        socket_setblock(fd, 1);
    }

    u32 magic, left;
    if(read(fd, &magic, sizeof(magic)) != sizeof(magic)) {
        DBG("cannot read magic!\n");
        return false;
    }
    if(read(fd, &left, sizeof(left)) != sizeof(left)) {
        DBG("cannot read len!\n");
        return false;
    }
    if(magic != ZMSG2_MAGIC) {
        DBG("invalid magic!\n");
        return false;
    }

    char buf[4096];
    int n;
    ZByteArray packet(false);
    packet.putInt(magic);
    packet.putInt(left);
    left += 2; // for crc32
    while(left > 0) {
        n = read(fd, buf, left > sizeof(buf) ? sizeof(buf) : left);
        if(n <= 0) {
            break;
        }
        left -= n;
        packet.append(buf, n);
    }

    if(left != 0) {
        DBG("incomplete read, left = %d\n", left);
        return false;
    }

    return msg.parse(packet);
}

bool ZApkLSocketClient::sendAndRecv(ZMsg2 &msg) {
    if(fd == -1) {
        fd = socket_connect("127.0.0.1", ZMASTER2_APK_PORT, 200);
        if(fd == -1) {
            return false;
        }
        socket_setblock(fd, 1);
    }

    return msg.writeTo(fd) && recv(msg);
}

bool ZApkLSocketClient::resetStatus() {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_RESET_STATUS;
    return sendAndRecv(msg);
}

bool ZApkLSocketClient::setConnType(u16 index, u16 type) {
    ZMsg2 msg;
    u16 t = type;
    t |= (index << 2);

    msg.cmd = ZMSG2_CMD_SET_CONN_TYPE;
    msg.data.putShort(t);
    return sendAndRecv(msg);
}

bool ZApkLSocketClient::addLog(char *str) {
    ZMsg2 msg;
    struct timeval tm;

    gettimeofday(&tm, NULL);
    u64 now = tm.tv_sec * 1000 + tm.tv_usec / 1000;

    msg.cmd = ZMSG2_CMD_ADD_LOG;
    msg.data.putInt64(now);
    msg.data.putUtf8(str);
    return sendAndRecv(msg);
}

bool ZApkLSocketClient::setHint(char *str) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_SET_HINT;
    msg.data.putUtf8(str);
    return sendAndRecv(msg);
}

bool ZApkLSocketClient::setProgress(u16 value, u16 subValue, u16 total) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_SET_PROGRESS;
    msg.data.putShort(value);
    msg.data.putShort(subValue);
    msg.data.putShort(total);
    return sendAndRecv(msg);
}

bool ZApkLSocketClient::setAlert(u16 type) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_SET_ALERT;
    msg.data.putShort(type);
    return sendAndRecv(msg);
}
#endif
