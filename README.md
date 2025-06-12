# libOnvif
windows下编译onvif

## gsoap下载地址
https://sourceforge.net/projects/gsoap2/

```bash
#编译生成wsdl2h.exe,soapcpp2.exe
1.sln工程路径
gsoap\VisualStudio2005\wsdl2h\*.sln
gsoap\VisualStudio2005\soapcpp2\*.sln
2.引入openssl三方库支持https
  添加宏WITH_OPENSSL，WITH_DOM

3.将要下列文件复制并加入wsdl2h工程中，编译生成wsdl2h.exe
.\gsoap\plugin\httpda.c 
.\gsoap\plugin\httpda.h
.\gsoap\plugin\smdevp.c
.\gsoap\plugin\smdevp.h
.\gsoap\plugin\threads.c
.\gsoap\plugin\threads.h

#创建目录结构并复制文件
1.目录结构如该工程所示
- gsoap/*  源代码中复制的一些文件，只有typemap.data 做了修改
- gsoap/import
- gsoap/extras
- gsoap/custom
- gsoap/plugin
- gsoap/stdsoap2.cpp
- gsoap/dom.cpp
- gsoap/stdsoap2.h
- gsoap/typemap.dat
- onvif 生成的文件，工程需要
- onvif_head 生成的一个中间头文件，可以删除
- soap 从gsoap中复制的一些文件，后续需要编译进来

2.修改gsoap/typemap.dat
xsd__duration = #import “custom/duration.h” | xsd__duration
xsd__dateTime = #import "custom/struct_tm.h" | xsd__dateTime
```

## 执行bat生成onvif编译所需文件
```bash

1.生成step1_gen.bat并执行
set SOAPCPP_BIN=soapcpp2.exe
@echo off

set WSDL2H_BIN=wsdl2h.exe

set DST=onvif_head\onvif.h

%WSDL2H_BIN% -c++11 -x -t gsoap\typemap.dat -o %DST%  https://www.onvif.org/ver10/device/wsdl/devicemgmt.wsdl   https://www.onvif.org/onvif/ver10/network/wsdl/remotediscovery.wsdl https://www.onvif.org/onvif/ver20/ptz/wsdl/ptz.wsdl  https://www.onvif.org/onvif/ver20/imaging/wsdl/imaging.wsdl  https://www.onvif.org/onvif/ver10/deviceio.wsdl  https://www.onvif.org/onvif/ver10/media/wsdl/media.wsdl  https://www.onvif.org/onvif/ver20/media/wsdl/media.wsdl
:: # https://www.onvif.org/ver10/events/wsdl/event.wsdl \
:: # http://www.onvif.org/onvif/ver10/display.wsdl \
:: # http://www.onvif.org/onvif/ver10/deviceio.wsdl \
:: # http://www.onvif.org/onvif/ver20/imaging/wsdl/imaging.wsdl \
:: # http://www.onvif.org/onvif/ver10/receiver.wsdl \
:: # http://www.onvif.org/onvif/ver10/recording.wsdl \
:: # http://www.onvif.org/onvif/ver10/search.wsdl \
:: # http://www.onvif.org/onvif/ver10/replay.wsdl \
:: # http://www.onvif.org/onvif/ver20/analytics/wsdl/analytics.wsdl \
:: # http://www.onvif.org/onvif/ver10/analyticsdevice.wsdl \
:: # http://www.onvif.org/onvif/ver10/schema/onvif.xsd \
:: # http://www.onvif.org/ver10/actionengine.wsdl \
:: # http://www.onvif.org/ver10/pacs/accesscontrol.wsdl \
:: # http://www.onvif.org/ver10/pacs/doorcontrol.wsdl \
:: # http://www.onvif.org/ver10/advancedsecurity/wsdl/advancedsecurity.wsdl \
:: # http://www.onvif.org/ver10/accessrules/wsdl/accessrules.wsdl \
:: # http://www.onvif.org/ver10/credential/wsdl/credential.wsdl \
:: # http://www.onvif.org/ver10/schedule/wsdl/schedule.wsdl \
:: # http://www.onvif.org/ver10/pacs/types.xsd

pause
```

## 命令解析
step1_gen.sh主要使用了wsdl2h命令来生成onvif.h文件。wsdl2h参数解析：
```
-c ： 生成c风格代码（注：后缀名还是.cpp ，但实际上是.c）
-c++：生成c++风格代码（注 : 默认是生成c++代码）
-x : 表示不生成xml 文件（注：生成的xml文件，有助于了解发送是SOAP是怎样的结构，建议不使用-x）
-l : 表示指定导入路径
-C : 表示生成客户端代码
-S : 表示生成服务端代码
-s : 不使用STL代码
-o: 生成.h文件叫什么名字
-t : 后面紧跟“typemap.dat”这个批处理文件
```
## 关于鉴权
如果onvif.h不加入#import "wsse.h"，使用soap_wsse_add_UsernameTokenDigest函数会导致编译出错，也就无法登录设备进行操作了。

## wsdl相关文件的功能范围
- https://www.onvif.org/ver10/device/wsdl/devicemgmt.wsdl 用于获取设备参数
- https://www.onvif.org/onvif/ver10/network/wsdl/remotediscovery.wsdl 用于发现设备
- https://www.onvif.org/onvif/ver20/ptz/wsdl/ptz.wsdl 云台控制
- https://www.onvif.org/onvif/ver10/media/wsdl/media.wsdl 获取264的视频流地址
- https://www.onvif.org/onvif/ver20/media/wsdl/media.wsdl 获取h265视频流地址
- http://www.onvif.org/onvif/ver20/imaging/wsdl/imaging.wsdl 光圈，对比度，饱和度


```bash
#编译生成cpp
1.源码修改：
  - onvif.h中加入#import "wsse.h"，后面onvif使用soap_wsse_add_UsernameTokenDigest函数进行鉴权
  - SOAP_ENV__Fault重复定义问题
    修改libonvif\gsoap\import\wsa5.h文件，将int SOAP_ENV__Fault修改为不冲突的任何名字，例如int_SOAP_ENV__Fault_xxx，再次使用soapcpp2工具编译就成功了

2.执行step2_cpp.bat,生成可以用于工程实践的相关源代码文件

3.添加工程时，要在vs工程命令行添加 /bigobj 
cmakelists中添加如下：target_compile_options(${PROJECT_NAME} PRIVATE "/bigobj")

```
linxu下编译参考：
https://github.com/NoevilMe/onvif_demo
