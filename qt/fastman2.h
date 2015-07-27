#ifndef FASTMAN2_H
#define FASTMAN2_H

#include <QString>
#ifndef NO_GUI
#include <QImage>
#endif
#define ZM_REMOTE_PORT 19001
#define JDWP_REMOTE_PORT 18201

// .... ..xx last 2 bits for conntype
// xxxx xx device_index
#define ZMSG2_CONNTYPE_LOST      0
#define ZMSG2_CONNTYPE_USB       1
#define ZMSG2_CONNTYPE_WIFI      2

// flags for alert
#define ZMSG2_ALERT_NONE         0
#define ZMSG2_ALERT_ASYNC_DONE   1
#define ZMSG2_ALERT_INSTALL_DONE 2
#define ZMSG2_ALERT_INSTALL_FAIL 4

#define ZMSG2_ALERT_SOUND        16
#define ZMSG2_ALERT_VIBRATE      32

class ZMINFO {
public:
    int euid;
    int sdk_int;

    enum {
        CPU_ABI_ARM = 0,
        CPU_ABI_X86 = 1,
        CPU_ABI_MIPS = 2
    };
    int cpu_abi;
    quint64 sys_free;
    quint64 sys_total;
    quint64 tmp_free;
    quint64 tmp_total;
    quint64 store_free;
    quint64 store_total;
    qint64 mem_freeKB;
    qint64 mem_totalKB;
    QString tmp_dir;
    QString store_dir;
};

class ZM_FILE {
public:
    QString path;
    QString link_path;
    uint st_size;
    uint st_mode;
    uint st_mtime;

    // client side only
    bool isLink();
    bool isDir();
    bool isFile();

    QString SDCardPath;
    uint file_type;
    enum {
        TYPE_UNKNOWN = 0,
        TYPE_PICTURE,
        TYPE_MOVIE_MUSIC
    };
    ZM_FILE():file_type(TYPE_UNKNOWN){}

};

class ZM_SDCARD {
public:
    QString sd_path;
    quint64 sd_free;
};

class APK_SAMPLE_INFO {
public:
    QString path1;
    QString md5_1;
    QString path2;
    QString md5_2;
};

class AGENT_BASIC_INFO {
public:
    QString brand;
    QString model;
    QString version;
    int sdk_int;
    QString imei;
    QString fingerprint;
};

class AGENT_APP_INFO {
public:
    enum {
        TYPE_UNKNOWN = 0,
        TYPE_SYSTEM_APP,
        TYPE_UPDATED_SYSTEM_APP,
        TYPE_USER_APP
    };

    QString name;
    QString packageName;
    QString versionName;
    unsigned int versionCode;
    QString sourceDir;
    quint64 size;
    quint64 mtime;
    unsigned int flags;
    bool enabled;
#ifndef NO_GUI
    QImage icon;
#endif
    QByteArray iconData;

    int getType();
    QString getTypeName();
    bool isExternal();
};

class AGENT_CALL_INFO {
public:
    qint64  call_id;
    QString name;
    QString phone_num;
    qint64  date_time;
    qint32  call_type;
    qint64  duration_sec;
};

class AGENT_SMS_INFO {
public:
    qint64  msg_id;
//    int     threadId;
    int     type;
    QString address;
    qint64  date_time;
    int read;
    int status;
    QString subject;
    QString body;
    int person;
    int protocol;
    int replyPathPresent;
    QString serviceCenter;
    qint64  date_sent;
    int seen;
    int locked;
    int errorCode;
};

class AGENT_CONTACTS_INFO {
public:
    qint64  contact_id;
    QString name;
    QString phone_num;
    QString num_type;
};

class FastManSocket;

class FastManAgentClient {
    FastManSocket *_socket;
public:
    FastManAgentClient(const QString& adb_serial = QString(),
                       int zm_port = ZM_REMOTE_PORT);
    ~FastManAgentClient();

    FastManSocket *getSocket();

    bool resetStatus();
    bool setConnType(unsigned short index, unsigned short type);
    bool addLog(const QString& log);
    bool setHint(const QString& hint);
    bool setProgress(short value,
                     short subValue,
                     short total);
    bool setAlert(unsigned short type);
    bool addInstLog(const QString& name, const QString& id, const QString& md5, const QString& pkg);
    bool getTimeGap(qint64 &gap);
    bool syncTime();
    bool getBasicInfo(AGENT_BASIC_INFO& info);

    int  getInfoCount(quint16 cmd);
    bool getCallInfo(QList<AGENT_CALL_INFO*> &info);
    bool getSMSInfo(QList<AGENT_SMS_INFO*> &info);
    bool getContactsInfo(QList<AGENT_CONTACTS_INFO*> &info);

    bool getAppList(QList<AGENT_APP_INFO*>& list,
                    bool loadIcon = true,
                    int flag_include = 0,
                    int flag_exclude = 0,
                    const QString& pkgs = QString());
    bool getAppListHead(bool loadIcon = true,
                        int flag_include = 0,
                        int flag_exclude = 0,
                        const QString& pkgs = QString());
    bool getNextApp(AGENT_APP_INFO& info);

    AGENT_APP_INFO *getAppInfo(const QString& pkg, bool loadIcon = true);
};

class FastManClient {
    FastManSocket *_socket;
public:    
    enum {
        LOCATION_AUTO = 0,
        LOCATION_PHONE,
        LOCATION_STORAGE
    };

    FastManClient(const QString& adb_serial = QString(),
                  int zm_port = ZM_REMOTE_PORT);
    ~FastManClient();

    bool testValid(int timeout = 500);
    void disconnect();

    bool switchRootCli();
    bool switchQueueCli();
    bool execQueue();
    bool cancelQueue();

    bool getZMInfo(ZMINFO &info);
    bool killRemote();

    bool push(const QString& lpath, const QString& rpath, int mode = 0777, int uid = -1, int gid = -1, uint mtime = 0);
    bool pushData(const QByteArray &data, const QString &rpath, int mode = 0777, int uid = -1, int gid = -1, uint mtime = 0);
    bool pull(const QString& lpath, const QString& rpath);
    bool pullData(QByteArray& out, const QString& rpath);

    int exec(QByteArray &result, int count, ...);
    bool remove(const QString& path, bool delSelf = true);

    quint64 getFreeSpace(const QString& path);
    bool getProps(const QStringList& keys, QStringList& values);
    bool getFileSize(const QString& path, quint64& size);
    bool getFileList(const QString& path, int maxdepth, QList<ZM_FILE*> &list, const QStringList& blackList);
    bool getSDCardList(QList<ZM_SDCARD*>& list);

    bool getFileMd5(const QString& path, QString &md5);
    bool getApkSample(APK_SAMPLE_INFO &info, int minXmlSize);
    bool searchApkStr(const QString& rpath, const QStringList& keys);

    bool setAlertType(const unsigned short type);
    bool installApk(const QString& lpath,
                    const QString& rpath,
                    const QString& pkg,
                    const QString& name,
                    unsigned char location = LOCATION_AUTO,
                    unsigned char sys = false);
    bool installApk(const QString& rpath,
                    const QString& pkg,
                    const QString& name,
                    unsigned char location = LOCATION_AUTO,
                    unsigned char sys = false);

    bool installApkSys(const QString &lpath,
                       const QString &rpath);

    bool installApkSys(const QString &rpath);

    bool invokeProtect(bool enable);
    bool invokeSu(const ZMINFO &info, bool add);
};

class FastManRooter {
    FastManSocket *_socket;
    QString adb_serial;
    int zm_port;
    int jdwp_port;
public:
    enum {
        FLAG_FRAMA_ROOT = 1,
        FLAG_MASTERKEY_ROOT = 2,
        FLAG_VROOT = 4,
        FLAG_TOWEL_ROOT = 8
    };

    FastManRooter(const QString& adb_serial = QString(),
                  int zm_port = ZM_REMOTE_PORT,
                  int jdwp_port = JDWP_REMOTE_PORT);
    ~FastManRooter();

    static bool startZMaster(const QString& adb_serial);
    bool getRoot(QString& err_msg, int flag);
    bool getTowelRoot(QString& err_msg);
    bool checkSystemWriteable();
};

#endif // FASTMAN_H
