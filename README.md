# ZMaster

[mmqt2 (qt)] <--ADB, tcp socket--> [zmaster2 (ndk)] <--localsocket--> [zagent2 (java)]

- ZByteArray & ZMsg2 : simplified message packet for easier communication

## qt
PC application codes

- fastman2 : zmaster service client, Android root impactor
- fastmansocket : socket wrapper for zmsg communication
- ioapi, zip, unzip : zip source code from zlib, modified to adopt Android master-key bugs
- ZipHacker : zip/unzip wrapper with functions for master-key bugs

## java
Android app codes

- ZLocalServer : zmaster service provider, Android SDK level (uid app_id)

## ndk
Android native codes

- zmasterserver : zmaster service provider, Android NDK level (uid root/shell)
- zapklsocketclient : zmaster service client, for invoking inside the zmasterserver
- msocket : tcp and local socket wrapper
- apkhelper : Android binary xml parser and master-key sample APK looking up
