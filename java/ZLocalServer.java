package com.dx.service;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;

import android.annotation.SuppressLint;
import android.content.ContentResolver;
import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.net.Uri;
import android.os.Build;
import android.provider.CallLog.Calls;
import android.provider.ContactsContract;
import android.provider.ContactsContract.CommonDataKinds.Phone;
import android.provider.ContactsContract.CommonDataKinds.StructuredName;
import android.provider.ContactsContract.Contacts;
import android.provider.ContactsContract.Data;
import android.provider.ContactsContract.RawContacts;
import android.provider.MediaStore;
import android.provider.Telephony.Sms;
import android.support.v4.content.LocalBroadcastManager;
import android.text.TextUtils;

import com.dx.agent2.db.InstData;
import com.dx.agent2.db.InstDb;
import com.dx.utils.IPhoneSubInfoUtil;
import com.dx.utils.Log;
import com.dx.utils.PackageReporter;
import com.dx.utils.ThumbnailUtil;
import com.dx.utils.ZByteArray;
import com.dx.utils.ZThreadPool;
import com.dx.utils.ZThreadPool.ZThread;

@SuppressLint("InlinedApi")
class ZLocalServerHandler extends Thread {
    final static String TAG = "ZLocalServerHandler";

    private static final Uri URI_CALLS = Calls.CONTENT_URI;
    private static final Uri URI_SMS = Uri.parse("content://sms/");
    private static final Uri URI_CONTACTS = ContactsContract.Contacts.CONTENT_URI;
    private static final Uri URI_VIDEOS = MediaStore.Video.Media.EXTERNAL_CONTENT_URI;
    private static final Uri URI_IMAGES = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
    private String[] projection4Sms;

    ZLocalServer server;
    Socket client;
    PackageManager pm;
    ContentResolver mResolver;
    InstDb instDb;
    long time_gap = 0;

    @SuppressLint("InlinedApi")
    public ZLocalServerHandler(ZLocalServer server, Socket client) {
        this.server = server;
        this.client = client;
        pm = server.context.getPackageManager();
        instDb = new InstDb(server.context);
        this.mResolver = server.context.getContentResolver();
        if (android.os.Build.VERSION.SDK_INT < 19) {
            projection4Sms = new String[] { "_id", "type", "address", "date", "read", "status", "subject", "body",
                    "person", "protocol", "reply_path_present", "service_center", "date_sent", "seen", "locked",
                    "error_code" };
        } else {
            projection4Sms = new String[] { Sms._ID, Sms.TYPE, Sms.ADDRESS, Sms.DATE, Sms.READ, Sms.STATUS,
                    Sms.SUBJECT, Sms.BODY, Sms.PERSON, Sms.PROTOCOL, Sms.REPLY_PATH_PRESENT, Sms.SERVICE_CENTER,
                    Sms.DATE_SENT, Sms.SEEN, Sms.LOCKED, Sms.ERROR_CODE };
        }
    }

    private void handleMessage(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        if (msg.cmd >= ZMsg2.ZMSG2_CMD_RESET_STATUS && msg.cmd <= ZMsg2.ZMSG2_CMD_SET_ALERT) {
            Intent intent = new Intent(ZMsg2.ZMSG2_BROADCAST_ACTION);
            intent.putExtra("cmd", msg.cmd);
            switch (msg.cmd) {
            case ZMsg2.ZMSG2_CMD_SET_CONN_TYPE:
                intent.putExtra("connType", msg.data.getShort(0));
                break;
            case ZMsg2.ZMSG2_CMD_ADD_LOG:
                intent.putExtra("time", msg.data.getInt64(0));
                intent.putExtra("log", msg.data.getUtf8(8));
                break;
            case ZMsg2.ZMSG2_CMD_SET_HINT:
                intent.putExtra("hint", msg.data.getUtf8(0));
                break;
            case ZMsg2.ZMSG2_CMD_SET_PROGRESS:
                intent.putExtra("value", msg.data.getShort(0));
                intent.putExtra("subValue", msg.data.getShort(2));
                intent.putExtra("total", msg.data.getShort(4));
                break;
            case ZMsg2.ZMSG2_CMD_SET_ALERT:
                intent.putExtra("alertType", msg.data.getShort(0));
                break;
            }
            server.lbm.sendBroadcast(intent);

            msg.data.clear();
            msg.ver = ZMsg2.ZMSG2_VERSION;
            os.write(msg.getPacket().getBytes());
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_GET_BASICINFO) {
            handleGetBasicInfo(msg, is, os);
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_GET_APPINFO || msg.cmd == ZMsg2.ZMSG2_CMD_GET_APPINFO_NOICON) {
            handleGetAppInfo(msg, is, os);
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_GET_CALLLOG) {
            handleGetCallLog(msg, is, os);
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_SET_CALLLOG) {
            handleSetCallLog(msg, is, os);
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_GET_SMSLOG) {
            handleGetSmsLog(msg, is, os);
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_SET_SMSLOG) {
            handleSetSmsLog(msg, is, os);
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_GET_CONTACTS) {
            handleGetContacts(msg, is, os);
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_SET_CONTACTS) {
            handleSetContacts(msg, is, os);
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_GET_IMAGES) {
            handleGetImages(msg, is, os);
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_GET_VIDEOS) {
            handleGetVideos(msg, is, os);
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_GET_IMAGE_THUMBNAIL) {
            handleGetImageThumbnail(msg, is, os);
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_ADD_INSTLOG) {
            handleAddInstLog(msg, is, os);
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_GET_CURTIME) {
            long cur = System.currentTimeMillis();
            msg.data.clear();
            msg.data.putInt64(cur);
            os.write(msg.getPacket().getBytes());
        } else if (msg.cmd == ZMsg2.ZMSG2_CMD_SET_TIMEGAP) {
            time_gap = msg.data.getInt64(0);
            msg.data.clear();
            Log.i(TAG, "set timeGap " + time_gap);
            os.write(msg.getPacket().getBytes());
        }
    }

    // head [flg1][flg2][pkg1,pkg2,...pkgN]
    // -- (flags & flag1 != 0) || (flags & flag2 == 0)
    private void handleGetAppInfo(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        int flg1 = msg.data.getInt(0);
        int flg2 = msg.data.getInt(4);
        String pkgstr = msg.data.getUtf8(8);
        String[] pkgs = pkgstr.length() > 0 ? pkgstr.split(",") : null;
        PackageReporter r = new PackageReporter(server.context);
        List<PackageReporter.Package> list = r.loadPackageList();

        msg.data.clear();
        msg.data.putInt(0);
        msg.data.putUtf8("OK", true);
        msg.ver = ZMsg2.ZMSG2_VERSION;
        os.write(msg.getPacket().getBytes());

        for (PackageReporter.Package p : list) {
            boolean match = false;
            if ((p.flags & flg1) != 0 || (p.flags & flg2) == 0) {
                match = true;
            }

            if (pkgs != null && pkgs.length > 0) {
                match = false;
                for (String pkg : pkgs) {
                    if (pkg != null && pkg.equals(p.packageName)) {
                        match = true;
                        break;
                    }
                }
            }
            if (!match) {
                continue;
            }

            Log.i(TAG, "sending " + p.name);
            msg.data.clear();
            msg.data.putUtf8(p.name, true);
            msg.data.putUtf8(p.packageName, true);
            msg.data.putUtf8(p.versionName, true);
            msg.data.putInt(p.versionCode);
            msg.data.putUtf8(p.sourceDir, true);
            File f = new File(p.sourceDir);
            msg.data.putInt64(f.length());
            msg.data.putInt64(f.lastModified());
            msg.data.putInt(p.flags);
            msg.data.putByte(p.enabled ? (byte) 1 : (byte) 0);
            if (msg.cmd == ZMsg2.ZMSG2_CMD_GET_APPINFO) {
                try {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    BitmapDrawable bd = (BitmapDrawable) pm.getApplicationIcon(p.packageName);
                    Bitmap b = bd.getBitmap();
                    if (b.getWidth() > 64) {
                        b = Bitmap.createScaledBitmap(b, 64, 64, true);
                    }
                    if (b.compress(Bitmap.CompressFormat.PNG, 100, bos)) {
                        msg.data.putInt(bos.size());
                        msg.data.putBytes(bos.toByteArray());
                    } else {
                        msg.data.putInt(0);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    msg.data.putInt(0);
                }
            }
            os.write(msg.getPacket().getBytes());
        }

        msg.data.clear();
        os.write(msg.getPacket().getBytes());
    }

    private void handleGetCallLog(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        boolean isCount = "Count".equals(msg.data.getUtf8(0));// 如果是获取数量，第0位请写"Count"字符串
        Cursor cursor = mResolver.query(URI_CALLS, new String[] { Calls._ID, Calls.CACHED_NAME, Calls.NUMBER,
                Calls.DATE, Calls.TYPE, Calls.DURATION }, null, null, Calls.DEFAULT_SORT_ORDER + " limit 1000");
        if (isCount) {
            msg.data.clear();
            msg.data.putInt(0);
            msg.data.putInt(cursor != null ? cursor.getCount() : 0);
            msg.ver = ZMsg2.ZMSG2_VERSION;
            os.write(msg.getPacket().getBytes());
            addLog(server.lbm, "handleGetCallLog(Count)");
        } else {
            msg.data.clear();
            msg.data.putInt(0);
            msg.data.putUtf8("OK", true);
            msg.ver = ZMsg2.ZMSG2_VERSION;
            os.write(msg.getPacket().getBytes());
            addLog(server.lbm, "handleGetCallLog(OK)");
            if (cursor != null) {
                while (cursor.moveToNext()) {
                    long id = cursor.getLong(cursor.getColumnIndex(Calls._ID));
                    String name = cursor.getString(cursor.getColumnIndex(Calls.CACHED_NAME));
                    String number = cursor.getString(cursor.getColumnIndex(Calls.NUMBER));
                    long date = cursor.getLong(cursor.getColumnIndex(Calls.DATE));
                    int callType = cursor.getInt(cursor.getColumnIndex(Calls.TYPE));
                    long duration = cursor.getLong(cursor.getColumnIndex(Calls.DURATION));
                    msg.data.clear();
                    msg.data.putInt64(id);// 记录ID
                    msg.data.putUtf8(name, true);// 对方姓名(可能为空)
                    msg.data.putUtf8(number, true);// 对方号码
                    msg.data.putInt64(date);// 来电或者去电的时间
                    msg.data.putInt(callType);// 电话类型 1:来电2:呼出3:未接
                    msg.data.putInt64(duration);// 通话持续时间，秒数
                    os.write(msg.getPacket().getBytes());
                    addLog(server.lbm, "handleGetCallLog(" + id + ")" + name + "," + number + "," + date + ","
                            + callType + "," + duration);
                }
            }
        }
        if (cursor != null) {
            cursor.close();
        }
        msg.data.clear();
        os.write(msg.getPacket().getBytes());
    }

    private void handleSetCallLog(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        // 初始回应
        msg.data.clear();
        msg.data.putInt(0);
        msg.data.putUtf8("OK", true);
        msg.ver = ZMsg2.ZMSG2_VERSION;
        os.write(msg.getPacket().getBytes());
        addLog(server.lbm, "handleSetCallLog(OK)");

        boolean endrecieved = false;
        int n = -1;
        byte b[] = new byte[1024];
        ZByteArray data = new ZByteArray();
        while (!endrecieved && (n = is.read(b, 0, b.length)) > 0) {
            addLog(server.lbm, "handleSetCallLog(while)");
            // 用来循环接收多条数据
            data.putBytes(b, 0, n);
            while (msg.parse(data)) {// 用来解析数据
                addLog(server.lbm, "handleSetCallLog(empty)");
                if (msg.data.size() == 0) {// 收到空包
                    endrecieved = true;// 收到空包及时退出
                    break;
                }
                long id = msg.data.getInt64();
                String name = msg.data.getUtf8();
                String number = msg.data.getUtf8();
                long date = msg.data.getInt64();
                int type = msg.data.getInt();
                long duration = msg.data.getInt64();

                Cursor cursor = mResolver.query(URI_CALLS, new String[] { Calls._ID }, Calls._ID + "=?",
                        new String[] { id + "" }, null);
                String result = "";
                if (!cursor.moveToFirst()) {
                    ContentValues values = new ContentValues();
                    values.put(Calls._ID, id);
                    values.put(Calls.CACHED_NAME, name);
                    values.put(Calls.NUMBER, number);
                    values.put(Calls.DATE, date);
                    values.put(Calls.TYPE, type);
                    values.put(Calls.DURATION, duration);
                    mResolver.insert(URI_CALLS, values);
                    result = "OK";
                } else {
                    result = "Exist";
                }
                cursor.close();
                msg.data.clear();
                msg.data.putInt(0);
                msg.data.putUtf8(result, true);
                msg.ver = ZMsg2.ZMSG2_VERSION;
                os.write(msg.getPacket().getBytes());
                addLog(server.lbm, "handleSetCallLog(" + id + ")" + name + "," + number + "," + date + "," + type + ","
                        + duration);
            }
        }
    }

    private void handleGetSmsLog(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        boolean isCount = "Count".equals(msg.data.getUtf8(0));// 如果是获取数量，第0位请写"Count"字符串
        Cursor cursor = mResolver.query(URI_SMS, null, null, null, " date DESC limit 1000");
        if (isCount) {
            msg.data.clear();
            msg.data.putInt(0);
            msg.data.putInt(cursor != null ? cursor.getCount() : 0);
            msg.ver = ZMsg2.ZMSG2_VERSION;
            os.write(msg.getPacket().getBytes());
            addLog(server.lbm, "handleGetSmsLog(Count)");
        } else {
            msg.data.clear();
            msg.data.putInt(0);
            msg.data.putUtf8("OK", true);
            msg.ver = ZMsg2.ZMSG2_VERSION;
            os.write(msg.getPacket().getBytes());
            addLog(server.lbm, "handleGetSmsLog(OK)");

            if (cursor != null) {
                while (cursor.moveToNext()) {
                    Long id = cursor.getLong(cursor.getColumnIndex(projection4Sms[0]));
                    Integer type = cursor.getInt(cursor.getColumnIndex(projection4Sms[1]));
                    String address = cursor.getString(cursor.getColumnIndex(projection4Sms[2]));
                    Long date = cursor.getLong(cursor.getColumnIndex(projection4Sms[3]));
                    Integer read = cursor.getInt(cursor.getColumnIndex(projection4Sms[4]));// Boolean
                    Integer status = cursor.getInt(cursor.getColumnIndex(projection4Sms[5]));
                    String subject = cursor.getString(cursor.getColumnIndex(projection4Sms[6]));
                    String body = cursor.getString(cursor.getColumnIndex(projection4Sms[7]));
                    Integer person = cursor.getInt(cursor.getColumnIndex(projection4Sms[8]));
                    Integer protocol = cursor.getInt(cursor.getColumnIndex(projection4Sms[9]));
                    Integer replyPathPresent = cursor.getInt(cursor.getColumnIndex(projection4Sms[10]));// Boolean
                    String serviceCenter = cursor.getString(cursor.getColumnIndex(projection4Sms[11]));
                    Long dateSent = 0l;
                    if (android.os.Build.VERSION.SDK_INT >= 14) {
                        dateSent = cursor.getLong(cursor.getColumnIndex(projection4Sms[12]));
                    }
                    Integer seen = cursor.getInt(cursor.getColumnIndex(projection4Sms[13]));
                    Integer locked = cursor.getInt(cursor.getColumnIndex(projection4Sms[14]));
                    Integer errorCode = cursor.getInt(cursor.getColumnIndex(projection4Sms[15]));
                    msg.data.clear();
                    msg.data.putInt64(id);
                    msg.data.putInt(type);
                    msg.data.putUtf8(address, true);
                    msg.data.putInt64(date);
                    msg.data.putInt(read);
                    msg.data.putInt(status);
                    msg.data.putUtf8(subject, true);
                    msg.data.putUtf8(body, true);
                    msg.data.putInt(person);
                    msg.data.putInt(protocol);
                    msg.data.putInt(replyPathPresent);
                    msg.data.putUtf8(serviceCenter, true);
                    msg.data.putInt64(dateSent);
                    msg.data.putInt(seen);
                    msg.data.putInt(locked);
                    msg.data.putInt(errorCode);
                    os.write(msg.getPacket().getBytes());
                    addLog(server.lbm, "handleGetSmsLog(" + id + ")" + address + "," + body);
                }
            }
        }
        if (cursor != null) {
            cursor.close();
        }
        msg.data.clear();
        os.write(msg.getPacket().getBytes());
    }

    private void handleSetSmsLog(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        msg.data.clear();
        msg.data.putInt(0);
        msg.data.putUtf8("OK", true);
        msg.ver = ZMsg2.ZMSG2_VERSION;
        os.write(msg.getPacket().getBytes());
        addLog(server.lbm, "handleSetSmsLog(OK)");

        boolean endrecieved = false;
        int n = -1;
        byte b[] = new byte[1024];
        ZByteArray data = new ZByteArray();
        while (!endrecieved && (n = is.read(b, 0, b.length)) > 0) {
            addLog(server.lbm, "handleSetSmsLog(while)");
            // 用来循环接收多条数据
            data.putBytes(b, 0, n);
            while (msg.parse(data)) {// 用来解析数据
                if (msg.data.size() == 0) {// 收到空包
                    addLog(server.lbm, "handleSetSmsLog(empty)");
                    endrecieved = true;// 收到空包及时退出
                    break;
                }
                long id = msg.data.getInt64();
                int type = msg.data.getInt();
                String address = msg.data.getUtf8();
                long date = msg.data.getInt64();
                int read = msg.data.getInt();
                int status = msg.data.getInt();
                String subject = msg.data.getUtf8();
                String body = msg.data.getUtf8();
                int person = msg.data.getInt();
                int protocol = msg.data.getInt();
                int replyPathPresent = msg.data.getInt();
                String serviceCenter = msg.data.getUtf8();
                long dateSent = msg.data.getInt64();
                Integer seen = msg.data.getInt();
                Integer locked = msg.data.getInt();
                Integer errorCode = msg.data.getInt();

                String result = "";
                Cursor cursor = mResolver.query(URI_SMS, new String[] { projection4Sms[0] }, projection4Sms[0] + "=?",
                        new String[] { id + "" }, null);
                if (!cursor.moveToFirst()) {
                    ContentValues values = new ContentValues();
                    values.put(projection4Sms[0], id);
                    values.put(projection4Sms[1], type);
                    values.put(projection4Sms[2], address);
                    values.put(projection4Sms[3], date);
                    values.put(projection4Sms[4], read);
                    values.put(projection4Sms[5], status);
                    values.put(projection4Sms[6], subject);
                    values.put(projection4Sms[7], body);
                    values.put(projection4Sms[8], person);
                    values.put(projection4Sms[9], protocol);
                    values.put(projection4Sms[10], replyPathPresent);
                    values.put(projection4Sms[11], serviceCenter);
                    if (android.os.Build.VERSION.SDK_INT >= 14) {
                        values.put(projection4Sms[12], dateSent);
                    }
                    values.put(projection4Sms[13], seen);
                    values.put(projection4Sms[14], locked);
                    values.put(projection4Sms[15], errorCode);
                    mResolver.insert(URI_SMS, values);
                    result = "OK";
                } else {
                    result = "Exist";
                }
                cursor.close();
                msg.data.clear();
                msg.data.putInt(0);
                msg.data.putUtf8(result, true);
                msg.ver = ZMsg2.ZMSG2_VERSION;
                os.write(msg.getPacket().getBytes());
                addLog(server.lbm, "handleSetSmsLog(" + id + ")" + address + "," + body);
            }
        }
    }

    private static final String SPLIT_PHONE = ";";

    private void handleGetContacts(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        boolean isCount = "Count".equals(msg.data.getUtf8(0));// 如果是获取数量，第0位请写"Count"字符串
        Cursor cursor1 = mResolver.query(URI_CONTACTS, null, null, null, null);
        if (isCount) {
            msg.data.clear();
            msg.data.putInt(0);
            msg.data.putInt(cursor1 != null ? cursor1.getCount() : 0);
            msg.ver = ZMsg2.ZMSG2_VERSION;
            os.write(msg.getPacket().getBytes());
            addLog(server.lbm, "handleGetContacts(Count)");
        } else {
            msg.data.clear();
            msg.data.putInt(0);
            msg.data.putUtf8("OK", true);
            msg.ver = ZMsg2.ZMSG2_VERSION;
            os.write(msg.getPacket().getBytes());
            addLog(server.lbm, "handleGetContacts(OK)");
            if (cursor1 != null) {
                while (cursor1.moveToNext()) {
                    long id = cursor1.getLong(cursor1.getColumnIndex(Contacts._ID));
                    String displayName = cursor1.getString(cursor1.getColumnIndex(Contacts.DISPLAY_NAME));
                    int photoCount = cursor1.getInt(cursor1.getColumnIndex(Contacts.HAS_PHONE_NUMBER));
                    if (photoCount > 0) {
                        String numbers = "";
                        String types = "";
                        Cursor cursor2 = mResolver.query(Phone.CONTENT_URI, null, Phone.CONTACT_ID + "=" + id, null,
                                null);
                        if (cursor2 != null) {
                            while (cursor2.moveToNext()) {
                                String number = cursor2.getString(cursor2.getColumnIndex(Phone.NUMBER));
                                int type = cursor2.getInt(cursor2.getColumnIndex(Phone.TYPE));
                                numbers += number + SPLIT_PHONE;
                                types += type + SPLIT_PHONE;
                            }
                            cursor2.close();
                            msg.data.clear();
                            msg.data.putInt64(id);
                            msg.data.putUtf8(displayName, true);
                            msg.data.putUtf8(numbers, true);
                            msg.data.putUtf8(types, true);
                            os.write(msg.getPacket().getBytes());
                            addLog(server.lbm, "handleGetContacts()" + displayName + "," + numbers + "," + types);
                        }
                    }
                }
            }
        }
        if (cursor1 != null) {
            cursor1.close();
        }
        msg.data.clear();
        os.write(msg.getPacket().getBytes());
    }

    private void handleSetContacts(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        msg.data.clear();
        msg.data.putInt(0);
        msg.data.putUtf8("OK", true);
        msg.ver = ZMsg2.ZMSG2_VERSION;
        os.write(msg.getPacket().getBytes());
        addLog(server.lbm, "handleSetContacts(OK)");

        boolean endrecieved = false;
        int n = -1;
        byte b[] = new byte[1024];
        ZByteArray data = new ZByteArray();
        while (!endrecieved && (n = is.read(b, 0, b.length)) > 0) {
            addLog(server.lbm, "handleSetContacts(while)");
            // 用来循环接收多条数据
            data.putBytes(b, 0, n);
            while (msg.parse(data)) {// 用来解析数据
                addLog(server.lbm, "handleSetContacts(empty)");
                if (msg.data.size() == 0) {// 收到空包
                    endrecieved = true;// 收到空包及时退出
                    break;
                }
                long id = msg.data.getInt64();
                String name = msg.data.getUtf8();
                String strNumbers = msg.data.getUtf8();
                String strTypes = msg.data.getUtf8();
                Cursor cursor = mResolver.query(Data.CONTENT_URI, new String[] { Data.DATA15 }, Data.DATA15 + "=?",
                        new String[] { id + "" }, null);
                String result = "";
                if (!cursor.moveToFirst()) {
                    ContentValues values = new ContentValues();
                    // 首先向RawContacts.CONTENT_URI执行一个空值插入，目的是获取系统返回的rawContactId
                    Uri rawContactUri = mResolver.insert(RawContacts.CONTENT_URI, values);
                    long rawContactId = ContentUris.parseId(rawContactUri);
                    // 录入联系人姓名信息
                    values.clear();
                    values.put(Data.RAW_CONTACT_ID, rawContactId);
                    values.put(Data.MIMETYPE, StructuredName.CONTENT_ITEM_TYPE);
                    values.put(StructuredName.GIVEN_NAME, name);// 名
                    // values.put(StructuredName.FAMILY_NAME, "");//姓
                    values.put(Data.DATA15, id);
                    mResolver.insert(Data.CONTENT_URI, values);
                    // 录入联系人电话及类型信息
                    String[] numbers = strNumbers.split(SPLIT_PHONE);
                    String[] types = strTypes.split(SPLIT_PHONE);
                    for (int i = 0; i < numbers.length; i++) {
                        values.clear();
                        values.put(Data.RAW_CONTACT_ID, rawContactId);
                        values.put(Data.MIMETYPE, Phone.CONTENT_ITEM_TYPE);
                        values.put(Phone.NUMBER, numbers[i]);
                        values.put(Phone.TYPE, Integer.valueOf(types[i]));
                        mResolver.insert(Data.CONTENT_URI, values);
                    }
                    result = "OK";
                } else {
                    result = "Exist";
                }
                cursor.close();
                msg.data.clear();
                msg.data.putInt(0);
                msg.data.putUtf8(result, true);
                msg.ver = ZMsg2.ZMSG2_VERSION;
                os.write(msg.getPacket().getBytes());
                addLog(server.lbm, "handleSetContacts( " + result + " ) " + name + "," + strNumbers + "," + strTypes);
            }
        }
    }

    private void handleGetImageThumbnail(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        String path = msg.data.getUtf8();// 原文件路径
        int height = msg.data.getInt();// 缩略图高度
        int width = msg.data.getInt();// 缩略图宽度
        if (TextUtils.isEmpty(path) || !new File(path).exists()) {
            addLog(server.lbm, "handleGetImageThumbnail() " + path + " file not exist ");
        } else {
            addLog(server.lbm, "handleGetImageThumbnail() path:" + path + " , h:w=" + height + ":" + width);
        }

        msg.data.clear();
        msg.ver = ZMsg2.ZMSG2_VERSION;
        Bitmap bitmap = ThumbnailUtil.getLocalImageThumbnailScaleByHW(path, height, width);
        if (bitmap == null) {
            msg.data.putInt(0);
            addLog(server.lbm, "handleGetImageThumbnail(Fail)");
        } else {
            addLog(server.lbm, "handleGetImageThumbnail(OK) ");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, out);
            byte[] b = out.toByteArray();
            msg.data.putInt(b.length);
            msg.data.putBytes(b);
        }
        os.write(msg.getPacket().getBytes());
    }

    private void handleGetImages(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        msg.data.clear();
        msg.data.putInt(0);
        msg.data.putUtf8("OK", true);
        msg.ver = ZMsg2.ZMSG2_VERSION;
        os.write(msg.getPacket().getBytes());

        Cursor cursor = mResolver.query(URI_IMAGES, null, null, null, MediaStore.Images.Media.DEFAULT_SORT_ORDER);
        if (cursor != null) {
            while (cursor.moveToNext()) {
                String displayName = cursor.getString(cursor.getColumnIndex(MediaStore.Images.Media.DISPLAY_NAME));
                String path = cursor.getString(cursor.getColumnIndex(MediaStore.Images.Media.DATA));
                long size = cursor.getLong(cursor.getColumnIndex(MediaStore.Images.Media.SIZE));
                long time = cursor.getLong(cursor.getColumnIndex(MediaStore.Images.Media.DATE_MODIFIED));
                String parentName = cursor
                        .getString(cursor.getColumnIndex(MediaStore.Images.Media.BUCKET_DISPLAY_NAME));
                String parentId = cursor.getString(cursor.getColumnIndex(MediaStore.Images.Media.BUCKET_ID));
                msg.data.clear();
                msg.data.putUtf8(displayName, true);// 文件显示名称
                msg.data.putUtf8(path, true);// 文件路径
                msg.data.putInt64(size);// 文件大小
                msg.data.putInt64(time);// 文件最后变更时间
                msg.data.putUtf8(parentName, true);// 上级目录名称，可选
                msg.data.putUtf8(parentId, true);// 上级目录对应的ID，可选
                os.write(msg.getPacket().getBytes());
            }
        }
        if (cursor != null) {
            cursor.close();
        }
        msg.data.clear();
        os.write(msg.getPacket().getBytes());
    }

    private void handleGetVideos(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        msg.data.clear();
        msg.data.putInt(0);
        msg.data.putUtf8("OK", true);
        msg.ver = ZMsg2.ZMSG2_VERSION;
        os.write(msg.getPacket().getBytes());

        Cursor cursor = mResolver.query(URI_VIDEOS, null, null, null, MediaStore.Video.Media.DEFAULT_SORT_ORDER);
        if (cursor != null) {
            while (cursor.moveToNext()) {
                String displayName = cursor.getString(cursor.getColumnIndex(MediaStore.Video.Media.DISPLAY_NAME));
                String path = cursor.getString(cursor.getColumnIndex(MediaStore.Video.Media.DATA));
                long size = cursor.getLong(cursor.getColumnIndex(MediaStore.Video.Media.SIZE));
                long time = cursor.getLong(cursor.getColumnIndex(MediaStore.Video.Media.DATE_MODIFIED));
                msg.data.clear();
                msg.data.putUtf8(displayName, true);// 显示的文件名称
                msg.data.putUtf8(path, true);// 文件绝对路径
                msg.data.putInt64(size);// 文件大小
                msg.data.putInt64(time);// 文件最后变更时间
                os.write(msg.getPacket().getBytes());
            }
        }
        if (cursor != null) {
            cursor.close();
        }
        msg.data.clear();
        os.write(msg.getPacket().getBytes());
    }

    private void handleGetBasicInfo(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        msg.data.clear();
        msg.ver = ZMsg2.ZMSG2_VERSION;
        msg.data.putUtf8(Build.BRAND, true);
        msg.data.putUtf8(Build.MODEL, true);
        msg.data.putUtf8(Build.VERSION.RELEASE, true);
        msg.data.putInt(Build.VERSION.SDK_INT);
        msg.data.putUtf8(IPhoneSubInfoUtil.getAllImei(server.context), true);

        StringBuilder sb = new StringBuilder();
        sb.append(Build.BRAND);
        sb.append('_');
        sb.append(Build.MODEL);
        sb.append('_');
        sb.append(Build.DISPLAY);
        sb.append('_');
        sb.append(Build.FINGERPRINT);
        msg.data.putUtf8(sb.toString(), true);

        os.write(msg.getPacket().getBytes());
    }

    private void handleAddInstLog(ZMsg2 msg, InputStream is, OutputStream os) throws Throwable {
        int i = 0;
        int len = 0;

        InstData obj = new InstData();

        len = msg.data.getInt(i);
        i += 4;
        obj.name = msg.data.getUtf8(i, len);
        i += len;

        len = msg.data.getInt(i);
        i += 4;
        obj.id = msg.data.getUtf8(i, len);
        i += len;

        len = msg.data.getInt(i);
        i += 4;
        obj.md5 = msg.data.getUtf8(i, len);
        i += len;

        len = msg.data.getInt(i);
        i += 4;
        obj.pkg = msg.data.getUtf8(i, len);
        i += len;

        InstData ori = instDb.getData(InstDb.TABLENAME, obj.id);
        if (ori != null) {
            obj.count = ori.count;
            obj.flow = ori.flow;
        }
        Log.i(TAG, "handleAddInstLog:");
        Log.dumpObject(TAG, obj);
        instDb.setData(InstDb.TABLENAME, obj);

        msg.data.clear();
        os.write(msg.getPacket().getBytes());
    }

    private void addLog(LocalBroadcastManager lbm, String log) {
        Log.i("", "addLog=>" + log);
        Intent intent = new Intent(ZMsg2.ZMSG2_BROADCAST_ACTION);
        intent.putExtra("cmd", ZMsg2.ZMSG2_CMD_ADD_LOG);
        intent.putExtra("log", log);
        lbm.sendBroadcast(intent);
    }

    void core_run() throws Throwable {
        InputStream is = client.getInputStream();
        OutputStream os = client.getOutputStream();

        byte[] buf = new byte[4096];
        int n = -1;

        ZMsg2 msg = new ZMsg2();
        ZByteArray data = new ZByteArray();

        try {
            while ((n = is.read(buf, 0, buf.length)) > 0) {
                data.putBytes(buf, 0, n);

                while (msg.parse(data) == true) {
                    handleMessage(msg, is, os);
                }
            }
        } catch (Exception e) {
        }

        is.close();
        os.close();
        Log.i(TAG, "close client " + client);
        client.close();
    }

    public void run() {
        try {
            core_run();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
}

public class ZLocalServer extends ZThread {
    final static String TAG = "ZLocalServer";

    Context context;
    LocalBroadcastManager lbm;

    boolean needsQuit = false;

    public ZLocalServer(Context context, ZThreadPool parent) {
        super(parent, TAG);
        this.context = context;
        lbm = LocalBroadcastManager.getInstance(context);
        Log.i(TAG, "LocalBroadcastManager getInstance " + lbm);
    }

    @Override
    public void core_run() throws Exception {
        ServerSocket server = new ServerSocket(ZMsg2.ZMSG2_SOCKET_PORT);
        while (!needsQuit) {
            Socket client = server.accept();
            // client.setSoTimeout(2000);
            Log.i(TAG, "got client " + client);
            new ZLocalServerHandler(this, client).start();
        }
        server.close();
    }

}
