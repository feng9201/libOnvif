rem @echo off

rem set SOAPCPP_BIN=soapcpp2.exe

soapcpp2.exe -2 -c++11 -C -L -x -I gsoap;gsoap/import;gosap/custom -d onvif onvif_head/onvif.h

copy gsoap\stdsoap2.cpp soap 
copy gsoap\stdsoap2.h soap
copy gsoap\plugin\wsaapi.h soap  
copy gsoap\plugin\wsaapi.c soap\wsaapi.cpp  
copy gsoap\custom\duration.c soap\duration.cpp 
copy gsoap\custom\duration.h soap 

copy gsoap\custom\struct_timeval.h soap  
copy gsoap\custom\struct_timeval.c soap\struct_timeval.cpp 
 
rem ::  用于授权验证的一些文件
copy gsoap\dom.cpp soap 
copy gsoap\plugin\mecevp.h soap  
copy gsoap\plugin\mecevp.c soap\mecevp.cpp 
copy gsoap\plugin\smdevp.h soap
copy gsoap\plugin\smdevp.c soap\smdevp.cpp  
copy gsoap\plugin\threads.h soap  
copy gsoap\plugin\threads.c soap\threads.cpp 
copy gsoap\plugin\wsseapi.h soap 
copy gsoap\plugin\wsseapi.c soap\wsseapi.cpp 



pause