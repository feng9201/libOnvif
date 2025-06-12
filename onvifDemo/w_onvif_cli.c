/****************************************************************************
 *文 件 名 称 : w_onvif_cli.c
 *功 能 描 述 : ONVIF协议客户端功能处理
 *版       本 : V1.0
 *日       期 : 2022-07-06
 *作       者 : lixianbo
 *修 改 历 史 : 新建
*****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include "w_onvif_cli.h"
#include "onvif/wsseapi.h"
#include "onvif/threads.h"

#ifdef __linux__
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#else
//#include <thread>
#include <WinSock.h>
#include <IPHlpApi.h>
#include <Mstcpip.h>
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif


static int g_eventSocketFlag = 0;
int g_eventSocket = 0;
static int g_chnSubFlag[32] = {0};

static int ParseStringValue(char *pSrcStr, char *pLeft, char *pRight, char *pOut)
{
    char *pStart = NULL;
    char *pEnd = NULL;
    
    pStart = strstr(pSrcStr, pLeft);
    if (NULL == pStart)
    {
        return -1;
    }
    
    pEnd = strstr(pStart, pRight);
    if (NULL == pEnd)
    {
        strcpy(pOut, pStart + strlen(pLeft));
        return -1;
    }
    else
    {
        memcpy(pOut, pStart + strlen(pLeft), pEnd - pStart - strlen(pLeft));
    }
    
    return 0;
}

void StrConverToSmall(char *pStr)
{
    char* p = pStr;

    while ((*p) != '\0')
    {
        if ((*p) >= 'A' && (*p) <= 'Z')
        {
            (*p) += 32;
        }
        p++;
    }
    
    return;
}


struct soap *W_OnvifSoapNew(int timeOut)
{
    struct soap *pSoap = NULL;
    
	pSoap = soap_new();
	if (NULL == pSoap)
	{
		printf("sopa new error\n");
		return NULL;
	}
    //unuse-space
	//soap_set_namespaces(pSoap, namespaces);
    pSoap->send_timeout    = timeOut;
	pSoap->recv_timeout    = timeOut;
    pSoap->connect_timeout = timeOut;

    /* set charset UTF-8 */
    soap_set_mode(pSoap, SOAP_C_UTFSTRING);

    return pSoap;
}

void W_OnvifSoapDelete(struct soap *pSoap)
{
    soap_destroy(pSoap);
    soap_end(pSoap);
    soap_done(pSoap);
    soap_free(pSoap);
}

// 搜索设备
int W_CliDetectDevice(W_DETECT_DEVICE_ST *pstDetectDevice)
{
    int result = 0;
    int detectCount = 0;
    char *pTmp = NULL;
    char acTmpBuf[32] = {0};
    struct soap *pSoap = NULL;          //entirment variable
    struct SOAP_ENV__Header header;    //soap header;
    struct wsdd__ProbeType  req;       //client send probe
    struct wsdd__ScopesType sScope;    //Probel 里面的范围
    struct __wsdd__ProbeMatches resp;  //server response prober

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    soap_default_SOAP_ENV__Header(pSoap, &header);
	header.wsa__MessageID = (char *)soap_wsa_rand_uuid(pSoap);
	header.wsa__To =     "urn:schemas-xmlsoap-org:ws:2005:04:discovery";
	header.wsa__Action = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";
	pSoap->header = &header;
    
	soap_default_wsdd__ScopesType(pSoap, &sScope);
	sScope.__item = "";
    
    soap_default_wsdd__ProbeType(pSoap, &req);
    req.Scopes = &sScope;
    req.Types  = "dn:NetworkVideoTransmitter";
    
	result = soap_send___wsdd__Probe(pSoap, "soap.udp://239.255.255.250:3702", NULL, &req);
	while (SOAP_OK == result)
	{
		result = soap_recv___wsdd__ProbeMatches(pSoap, &resp);
		if (result == SOAP_OK)
		{
			if (pSoap->error)
			{
                printf("ProbeMatches error %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
                continue;
			}
			else
			{
                if (detectCount >= W_MAX_DETECT_DEV_NUM)
                {
                    break;
                }
                
                //printf("Target EP Address: %s\r\n", resp.wsdd__ProbeMatches->ProbeMatch->wsa__EndpointReference.Address);
                pTmp = strrchr(resp.wsdd__ProbeMatches->ProbeMatch->wsa__EndpointReference.Address, '-');
                if (0 == strcmp(pstDetectDevice->stIpcInfo[detectCount-1].acDevMac, pTmp+1))
                {
                    continue;
                }
                printf("***************************************************************************\n");
                printf("detectId: %d\n", detectCount);
                sprintf(pstDetectDevice->stIpcInfo[detectCount].acDevMac, "%s", pTmp+1);
                StrConverToSmall(pstDetectDevice->stIpcInfo[detectCount].acDevMac);
                printf("devMac: %s\n", pstDetectDevice->stIpcInfo[detectCount].acDevMac);
                //printf("Target Service Address: %s\r\n", resp.wsdd__ProbeMatches->ProbeMatch->XAddrs);
                
                sscanf(resp.wsdd__ProbeMatches->ProbeMatch->XAddrs, "%*[^//]//%[^/]", acTmpBuf);
                if (NULL != strstr(acTmpBuf, ":"))
                {
                    sscanf(acTmpBuf, "%[^:]", pstDetectDevice->stIpcInfo[detectCount].acDevIp);
                }
                else
                {
                    sprintf(pstDetectDevice->stIpcInfo[detectCount].acDevIp, "%s", acTmpBuf);
                }
                printf("devIp: %s\n", pstDetectDevice->stIpcInfo[detectCount].acDevIp);
                
                if (resp.wsdd__ProbeMatches->ProbeMatch->Scopes)
                {
                    //printf("Target Scopes Address: %s\r\n", resp.wsdd__ProbeMatches->ProbeMatch->Scopes->__item);
                    ParseStringValue(resp.wsdd__ProbeMatches->ProbeMatch->Scopes->__item, "hardware/", " ", 
                        pstDetectDevice->stIpcInfo[detectCount].acTypeName);
                    if (strlen(pstDetectDevice->stIpcInfo[detectCount].acTypeName) <= 0)
                    {
                        ParseStringValue(resp.wsdd__ProbeMatches->ProbeMatch->Scopes->__item, "Hardware/", " ", 
                            pstDetectDevice->stIpcInfo[detectCount].acTypeName);
                    }
                    printf("typeName: %s\n", pstDetectDevice->stIpcInfo[detectCount].acTypeName);
                    ParseStringValue(resp.wsdd__ProbeMatches->ProbeMatch->Scopes->__item, "name/", " ", 
                        pstDetectDevice->stIpcInfo[detectCount].acAliasName);
                    printf("aliasName: %s\n", pstDetectDevice->stIpcInfo[detectCount].acAliasName);
                }
                detectCount++;
			}
		}
		else if (pSoap->error)
		{
            printf("ProbeMatches error %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            char sbuf[256] = { 0 };
            sprintf(sbuf, "ProbeMatches error %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            fflush(stdout);
            break;
		}
	}
    pstDetectDevice->deviceNum = detectCount;
    printf("totalDetectNum: %d\n", pstDetectDevice->deviceNum);
    printf("***************************************************************************\n");
    
    W_OnvifSoapDelete(pSoap);
    
    return SOAP_OK;
}


int W_SubDeviceReboot(W_ONVIF_REQ_ST *pReq)
{
    char acXAddr[128] = {0};
    struct soap *pSoap = NULL; 
    struct _tds__SystemReboot stRebootReq;
    struct _tds__SystemRebootResponse stRebootResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stRebootReq, 0, sizeof(stRebootReq));
	printf("\n------------------Device reboot-----------------\n");
    sprintf(acXAddr, "http://%s/onvif/device_service", pReq->acDevIp);
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tds__SystemReboot(pSoap, acXAddr, NULL, &stRebootReq, &stRebootResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
	else
    {
        printf("Message: %s\n", stRebootResp.Message);
	}
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_SubFactoryDefault(W_ONVIF_REQ_ST *pReq)
{
    char acXAddr[128] = {0};
    struct soap *pSoap = NULL; 
    struct _tds__SetSystemFactoryDefault stFactoryReq;
    struct _tds__SetSystemFactoryDefaultResponse stFactoryResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stFactoryReq, 0, sizeof(stFactoryReq));
    stFactoryReq.FactoryDefault = tt__FactoryDefaultType__Soft;
    
	printf("\n------------------Device Factory Default-----------------\n");
    sprintf(acXAddr, "http://%s/onvif/device_service", pReq->acDevIp);
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tds__SetSystemFactoryDefault(pSoap, acXAddr, NULL, &stFactoryReq, &stFactoryResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    printf("------------------Set Factory Default success-----------------\n");
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetDeviceInfo(W_ONVIF_REQ_ST *pReq, W_ONVIF_DEV_INFO_ST *pDeviceInfo)
{
    char acXAddr[128] = {0};
    struct soap *pSoap = NULL;
    struct _tds__GetDeviceInformation stDevInfoReq;
    struct _tds__GetDeviceInformationResponse stDevInfoResp;
    
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}

    memset(&stDevInfoReq, 0, sizeof(stDevInfoReq));
	printf("\n------------------Get device information-----------------\n");
    sprintf(acXAddr, "http://%s/onvif/device_service", pReq->acDevIp);
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tds__GetDeviceInformation(pSoap, acXAddr, NULL, &stDevInfoReq, &stDevInfoResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
	else
    {
        printf("Manufacturer   : %s\n", stDevInfoResp.Manufacturer);
        printf("Model          : %s\n", stDevInfoResp.Model);
        printf("FirmwareVersion: %s\n", stDevInfoResp.FirmwareVersion);
        printf("SerialNumber   : %s\n", stDevInfoResp.SerialNumber);
        printf("HardwareId     : %s\n", stDevInfoResp.HardwareId);
        strcpy(pDeviceInfo->acDevModel,  stDevInfoResp.Model);
        strcpy(pDeviceInfo->acSerialNum, stDevInfoResp.SerialNumber);
        strcpy(pDeviceInfo->acFwVersion, stDevInfoResp.FirmwareVersion);
        strcpy(pDeviceInfo->acHardwareId, stDevInfoResp.HardwareId);
	}

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}

#ifdef WIN32
//#include <ctime>
// // 计算格里高利安日期的天数（从1970-01-01开始）
// int days_from_civil(int year, int month, int day) {
//     // 逐年累加
//     int days = year * 365 + (year / 4) - (year / 100) + (year / 400);
//     // 按月累加
//     static int month_days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
//     for (int i = 0; i < month - 1; ++i) {
//         days += month_days[i];
//     }
//     // 考虑闰年
//     if (month > 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))) {
//         days += 1;
//     }
//     days += day;
//     return days;
// }

// time_t timegm_win(struct tm *tm) {
//     int year = tm->tm_year + 1900;
//     int month = tm->tm_mon + 1;
//     int day = tm->tm_mday;
//     int hour = tm->tm_hour;
//     int min = tm->tm_min;
//     int sec = tm->tm_sec;

//     // 计算从1970年1月1日到指定日期的天数
//     int days_since_epoch = days_from_civil(year, month, day);
//     // 计算总秒数
//     time_t seconds = (days_since_epoch - 719528) * 86400 + 3600 * hour + 60 * min + sec;
//     return seconds;
// }
#endif

int W_GetDateAndTime(W_ONVIF_REQ_ST *pReq, W_ONVIF_TIME_ST *pTime)
{
    char acXAddr[128] = {0};
    struct soap *pSoap = NULL;
    struct _tds__GetSystemDateAndTime stDateTimeReq;
    struct _tds__GetSystemDateAndTimeResponse stDateAndTimeResp;
    struct tm getTime = {0};

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stDateTimeReq, 0, sizeof(stDateTimeReq));
	printf("\n------------------Get System Date And Time-----------------\n");
    sprintf(acXAddr, "http://%s/onvif/device_service", pReq->acDevIp);
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tds__GetSystemDateAndTime(pSoap, acXAddr, NULL, &stDateTimeReq, &stDateAndTimeResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

	if (NULL != stDateAndTimeResp.SystemDateAndTime)
	{
        printf("TmieZone:%s\n", stDateAndTimeResp.SystemDateAndTime->TimeZone->TZ);
        printf("%04d-%02d-%02d %02d:%02d:%02d\n", stDateAndTimeResp.SystemDateAndTime->UTCDateTime->Date->Year,
            stDateAndTimeResp.SystemDateAndTime->UTCDateTime->Date->Month, stDateAndTimeResp.SystemDateAndTime->UTCDateTime->Date->Day,
            stDateAndTimeResp.SystemDateAndTime->UTCDateTime->Time->Hour, stDateAndTimeResp.SystemDateAndTime->UTCDateTime->Time->Minute,
            stDateAndTimeResp.SystemDateAndTime->UTCDateTime->Time->Second);
        
        sprintf(pTime->acTimeZone, stDateAndTimeResp.SystemDateAndTime->TimeZone->TZ);
        pTime->dateFormat = 0;
        pTime->hourFormat = 1;
        pTime->timeSyncMode = stDateAndTimeResp.SystemDateAndTime->DateTimeType;

        /* 将struct tm表示的UTC时间转换为time_t类型表示的UTC时间 */
        getTime.tm_year  = stDateAndTimeResp.SystemDateAndTime->UTCDateTime->Date->Year - 1900;
        getTime.tm_mon   = stDateAndTimeResp.SystemDateAndTime->UTCDateTime->Date->Month - 1;
        getTime.tm_mday  = stDateAndTimeResp.SystemDateAndTime->UTCDateTime->Date->Day;
        getTime.tm_hour  = stDateAndTimeResp.SystemDateAndTime->UTCDateTime->Time->Hour;
        getTime.tm_min   = stDateAndTimeResp.SystemDateAndTime->UTCDateTime->Time->Minute;
        getTime.tm_sec   = stDateAndTimeResp.SystemDateAndTime->UTCDateTime->Time->Second;
        getTime.tm_isdst = 0;
#ifdef __linux__
        pTime->devTime = timegm(&getTime);
#else
        //pTime->devTime = timegm_win(&getTime);
#endif
	}

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_SetDateAndTime(W_ONVIF_REQ_ST *pReq, W_ONVIF_TIME_ST *pTime)
{
    char acXAddr[128] = {0};
    char as8TzBuf[16]  = {0};
    struct soap *pSoap = NULL;
    struct _tds__GetSystemDateAndTime stGetTimeReq;
    struct _tds__GetSystemDateAndTimeResponse stGetTimeResp;
    struct _tds__SetSystemDateAndTime stDateAndTimeReq;
    struct _tds__SetSystemDateAndTimeResponse stDateTimeResp;
    struct tm *pSetTime = NULL;
    
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}

    printf("\n------------------Set System Date And Time-----------------\n");
    if (pTime->timeSyncMode)
    {
        stDateAndTimeReq.DateTimeType = tt__SetDateTimeType__NTP;
    }
    else
    {
        memset(&stGetTimeReq, 0, sizeof(stGetTimeReq));
        sprintf(acXAddr, "http://%s/onvif/device_service", pReq->acDevIp);
        soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
        soap_call___tds__GetSystemDateAndTime(pSoap, acXAddr, NULL, &stGetTimeReq, &stGetTimeResp);
        if (pSoap->error)
        {
            printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            W_OnvifSoapDelete(pSoap);
            return SOAP_ERR;
        }
        
        stDateAndTimeReq.DateTimeType    = tt__SetDateTimeType__Manual;
        stDateAndTimeReq.DaylightSavings = xsd__boolean__false_;
        
        stDateAndTimeReq.TimeZone = (struct tt__TimeZone *)soap_malloc(pSoap, sizeof(struct tt__TimeZone));
        stDateAndTimeReq.TimeZone->TZ = (char *)soap_malloc(pSoap, 64);
        memset(stDateAndTimeReq.TimeZone->TZ, 0, 64);
        
        char *ps8Tmp = NULL;
        int s32Hour = 0, s32Minute = 0;
        int s32Positive = 1;

        ps8Tmp = strstr(pTime->acTimeZone, "+");
        if (!ps8Tmp)
        {
            s32Positive = 0;
            ps8Tmp = strstr(pTime->acTimeZone, "-");
        }

        if (ps8Tmp)
        {
            sscanf(ps8Tmp + 1, "%d:%d", &s32Hour, &s32Minute);

            if (s32Positive)
            {
                snprintf(as8TzBuf, sizeof(as8TzBuf), "CST-%02d:%02d", s32Hour, s32Minute);
            }
            else
            {
                snprintf(as8TzBuf, sizeof(as8TzBuf), "CST+%02d:%02d", s32Hour, s32Minute);
            }

            snprintf(stDateAndTimeReq.TimeZone->TZ, 64, "%s", as8TzBuf);
        }
        else
        {
            snprintf(stDateAndTimeReq.TimeZone->TZ, 64, "%s", stGetTimeResp.SystemDateAndTime->TimeZone->TZ);
        }

        printf("timeZone: %s\n", stDateAndTimeReq.TimeZone->TZ);
        
        stDateAndTimeReq.UTCDateTime = (struct tt__DateTime *)soap_malloc(pSoap, sizeof(struct tt__DateTime));
        stDateAndTimeReq.UTCDateTime->Date = (struct tt__Date *)soap_malloc(pSoap, sizeof(struct tt__Date));
        stDateAndTimeReq.UTCDateTime->Time = (struct tt__Time *)soap_malloc(pSoap, sizeof(struct tt__Time));
        
        pSetTime = gmtime(&pTime->devTime);
        stDateAndTimeReq.UTCDateTime->Date->Year   = pSetTime->tm_year + 1900;
        stDateAndTimeReq.UTCDateTime->Date->Month  = pSetTime->tm_mon + 1;
        stDateAndTimeReq.UTCDateTime->Date->Day    = pSetTime->tm_mday;
        stDateAndTimeReq.UTCDateTime->Time->Hour   = pSetTime->tm_hour;
        stDateAndTimeReq.UTCDateTime->Time->Minute = pSetTime->tm_min;
        stDateAndTimeReq.UTCDateTime->Time->Second = pSetTime->tm_sec;
    }
    
    sprintf(acXAddr, "http://%s/onvif/device_service", pReq->acDevIp);
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tds__SetSystemDateAndTime(pSoap, acXAddr, NULL, &stDateAndTimeReq, &stDateTimeResp);
    if (pSoap->error)
    {
    	printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
    	return SOAP_ERR;
    }
    printf("-----------------Set Date And Time success----------------\n");
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetNTPInfo(W_ONVIF_REQ_ST *pReq, W_ONVIF_NTP_ST *pNTP)
{
    char acXAddr[128] = {0};
    struct soap *pSoap = NULL;
    struct _tds__GetNTP stNTPReq;
    struct _tds__GetNTPResponse stNTPResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stNTPReq, 0, sizeof(stNTPReq));
	printf("\n------------------Get NTP information-----------------\n");
    sprintf(acXAddr, "http://%s/onvif/device_service", pReq->acDevIp);
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tds__GetNTP(pSoap, acXAddr, NULL, &stNTPReq, &stNTPResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

    if (NULL != stNTPResp.NTPInformation)
    {
        pNTP->enabled      = 1;
        pNTP->port         = 0;
        pNTP->syncInterval = 0;
        printf("FromDHCP: %d\n", stNTPResp.NTPInformation->FromDHCP);
        if (stNTPResp.NTPInformation->FromDHCP)
        {
            printf("sizeNTPFromDHCP: %d\n", stNTPResp.NTPInformation->__sizeNTPFromDHCP);
            pNTP->addrType = stNTPResp.NTPInformation->NTPFromDHCP->Type;
            if (tt__NetworkHostType__IPv4 == stNTPResp.NTPInformation->NTPFromDHCP->Type)
            {
                printf("ipv4Addr: %s\n", stNTPResp.NTPInformation->NTPFromDHCP->IPv4Address);
                strcpy(pNTP->acIPAddr, stNTPResp.NTPInformation->NTPFromDHCP->IPv4Address);
            }
            else if (tt__NetworkHostType__IPv6 == stNTPResp.NTPInformation->NTPFromDHCP->Type)
            {
                strcpy(pNTP->acIPAddr, stNTPResp.NTPInformation->NTPFromDHCP->IPv6Address);
            }
            else
            {
                printf("DNSName: %s\n", stNTPResp.NTPInformation->NTPFromDHCP->DNSname);
                strcpy(pNTP->acDomain, stNTPResp.NTPInformation->NTPFromDHCP->DNSname);
            }
        }
        else
        {
            printf("sizeNTPManual: %d\n", stNTPResp.NTPInformation->__sizeNTPManual);
            pNTP->addrType = stNTPResp.NTPInformation->NTPManual->Type;
            if (tt__NetworkHostType__IPv4 == stNTPResp.NTPInformation->NTPManual->Type)
            {
                printf("ipv4Addr: %s\n", stNTPResp.NTPInformation->NTPManual->IPv4Address);
                strcpy(pNTP->acIPAddr, stNTPResp.NTPInformation->NTPManual->IPv4Address);
            }
            else if (tt__NetworkHostType__IPv6 == stNTPResp.NTPInformation->NTPManual->Type)
            {
                strcpy(pNTP->acIPAddr, stNTPResp.NTPInformation->NTPManual->IPv6Address);
            }
            else
            {
                printf("DNSName: %s\n", stNTPResp.NTPInformation->NTPManual->DNSname);
                strcpy(pNTP->acDomain, stNTPResp.NTPInformation->NTPManual->DNSname);
            }
        }
    }
    else
    {
        pNTP->enabled = 0;
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_SetNTPInfo(W_ONVIF_REQ_ST *pReq, W_ONVIF_NTP_ST *pNTP)
{
    char acXAddr[128] = {0};
    struct soap *pSoap = NULL;
    struct _tds__SetNTP stNTPReq;
    struct _tds__SetNTPResponse stNTPResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stNTPReq, 0, sizeof(stNTPReq));
	printf("\n------------------Set NTP information-----------------\n");

    if (strlen(pNTP->acIPAddr) < 0 && strlen(pNTP->acDomain) < 0)
    {
        stNTPReq.FromDHCP = xsd__boolean__true_;
    }
    else
    {
        stNTPReq.FromDHCP = xsd__boolean__false_;
        stNTPReq.__sizeNTPManual = 1;
        stNTPReq.NTPManual = (struct tt__NetworkHost *)soap_malloc(pSoap, sizeof(struct tt__NetworkHost));
        memset(stNTPReq.NTPManual, 0, sizeof(struct tt__NetworkHost));
        if (strlen(pNTP->acIPAddr) > 0)
        {
            if (strlen(pNTP->acIPAddr) < 16)
            {
                stNTPReq.NTPManual->Type = tt__NetworkHostType__IPv4;
                stNTPReq.NTPManual->IPv4Address = (char *)soap_malloc(pSoap, 16); 
                strcpy(stNTPReq.NTPManual->IPv4Address, pNTP->acIPAddr);
                printf("NTPServerAddr: %s\n", stNTPReq.NTPManual->IPv4Address);
            }
            else
            {
                stNTPReq.NTPManual->Type = tt__NetworkHostType__IPv6;
                stNTPReq.NTPManual->IPv6Address = (char *)soap_malloc(pSoap, 32);
                strcpy(stNTPReq.NTPManual->IPv6Address, pNTP->acIPAddr);
            }
        }
        else
        {
            stNTPReq.NTPManual->Type = tt__NetworkHostType__DNS;    
            stNTPReq.NTPManual->DNSname = (char *)soap_malloc(pSoap, 64);
            strcpy(stNTPReq.NTPManual->DNSname, pNTP->acDomain);
        }
    }
    sprintf(acXAddr, "http://%s/onvif/device_service", pReq->acDevIp);
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tds__SetNTP(pSoap, acXAddr, NULL, &stNTPReq, &stNTPResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    printf("------------------Set NTP information success---------------\n");
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetNetInterfaces(W_ONVIF_REQ_ST *pReq, W_ONVIF_NET_INFO_ST *pNetInfo)
{
    int i = 0, j = 0;
    char acXAddr[128] = {0};
    struct soap *pSoap = NULL;
    struct _tds__GetNetworkInterfaces stNetIntReq;
    struct _tds__GetNetworkInterfacesResponse stNetIntResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stNetIntReq, 0, sizeof(stNetIntReq));
	printf("\n------------------Get Net Interfaces-----------------\n");
    sprintf(acXAddr, "http://%s/onvif/device_service", pReq->acDevIp);
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tds__GetNetworkInterfaces(pSoap, acXAddr, NULL, &stNetIntReq, &stNetIntResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

    printf("sizeNetworkInterfaces: %d\n", stNetIntResp.__sizeNetworkInterfaces);
    pNetInfo->intfaceNum = stNetIntResp.__sizeNetworkInterfaces;
    for (i = 0; i < stNetIntResp.__sizeNetworkInterfaces; i++)
    {
        pNetInfo->stInterFace[i].intfaceId = i + 1;
        if (NULL != stNetIntResp.NetworkInterfaces[i].Info);
        {
            printf("Name:   %s\n", stNetIntResp.NetworkInterfaces[i].Info->Name);
            printf("HwAddr: %s\n", stNetIntResp.NetworkInterfaces[i].Info->HwAddress);
            printf("MTU:    %d\n", *(stNetIntResp.NetworkInterfaces[i].Info->MTU));
            strcpy(pNetInfo->stInterFace[i].acName, stNetIntResp.NetworkInterfaces[i].Info->Name);
            strcpy(pNetInfo->stInterFace[i].acHwAddress, stNetIntResp.NetworkInterfaces[i].Info->HwAddress);
            pNetInfo->stInterFace[i].MTU = *(stNetIntResp.NetworkInterfaces[i].Info->MTU);
        }
        if (NULL != stNetIntResp.NetworkInterfaces[i].IPv4)
        {
            printf("DHCP: %d\n", stNetIntResp.NetworkInterfaces[i].IPv4->Config->DHCP);
            if (0 == stNetIntResp.NetworkInterfaces[i].IPv4->Config->DHCP)
            {
                
                printf("ManuAddr: %s\n", stNetIntResp.NetworkInterfaces[i].IPv4->Config->Manual->Address);
                pNetInfo->stInterFace[i].ipType = 0;
                pNetInfo->stInterFace[i].addrNum = stNetIntResp.NetworkInterfaces[i].IPv4->Config->__sizeManual;
                for (j = 0; j < pNetInfo->stInterFace[i].addrNum; j++)
                {
                    strcpy(pNetInfo->stInterFace[i].stIpv4Info[j].acIPv4Addr, stNetIntResp.NetworkInterfaces[i].IPv4->Config->Manual[j].Address);
                    pNetInfo->stInterFace[i].stIpv4Info[j].prefixLength = stNetIntResp.NetworkInterfaces[i].IPv4->Config->Manual[j].PrefixLength;
                }
            }
            else
            {
                printf("DHCPAddr: %s\n", stNetIntResp.NetworkInterfaces[i].IPv4->Config->FromDHCP->Address);
                pNetInfo->stInterFace[i].ipType  = 2;
                pNetInfo->stInterFace[i].addrNum = 1;
                strcpy(pNetInfo->stInterFace[i].stIpv4Info[0].acIPv4Addr, stNetIntResp.NetworkInterfaces[i].IPv4->Config->FromDHCP->Address);
                pNetInfo->stInterFace[i].stIpv4Info[0].prefixLength = stNetIntResp.NetworkInterfaces[i].IPv4->Config->FromDHCP->PrefixLength;
            }
        }
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_SetNetInterfaces(W_ONVIF_REQ_ST *pReq, W_ONVIF_NET_INFO_ST *pNetInfo)
{
    int i = 0, j = 0;
    char acXAddr[128] = {0};
    struct soap *pSoap = NULL;
    struct _tds__SetNetworkInterfaces stNetIntReq;
    struct _tds__SetNetworkInterfacesResponse stNetIntResp;
    
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
	printf("\n------------------Set Net Interfaces-----------------\n");
    for (i = 0; i < pNetInfo->intfaceNum; i++)
    {
        memset(&stNetIntReq, 0, sizeof(stNetIntReq));
        /* tds:ReferenceToken */
        stNetIntReq.InterfaceToken = pNetInfo->stInterFace[i].acName;
        printf("InterfaceToken: %s\n", stNetIntReq.InterfaceToken);

        /* tds:NetworkInterface */
        stNetIntReq.NetworkInterface = (struct tt__NetworkInterfaceSetConfiguration *)soap_malloc(pSoap, sizeof(struct tt__NetworkInterfaceSetConfiguration));
        memset(stNetIntReq.NetworkInterface, 0, sizeof(struct tt__NetworkInterfaceSetConfiguration));

        /* tt:Enabled */
        stNetIntReq.NetworkInterface->Enabled = (enum xsd__boolean *)soap_malloc(pSoap, sizeof(enum xsd__boolean));
        *(stNetIntReq.NetworkInterface->Enabled) = xsd__boolean__true_;
        
        /* tt:MTU */
        stNetIntReq.NetworkInterface->MTU = &(pNetInfo->stInterFace[i].MTU);
        
        stNetIntReq.NetworkInterface->IPv4 = (struct tt__IPv4NetworkInterfaceSetConfiguration *)soap_malloc(pSoap, sizeof(struct tt__IPv4NetworkInterfaceSetConfiguration));
        memset(stNetIntReq.NetworkInterface->IPv4, 0, sizeof(struct tt__IPv4NetworkInterfaceSetConfiguration));
        stNetIntReq.NetworkInterface->IPv4->Enabled = (enum xsd__boolean *)soap_malloc(pSoap, sizeof(enum xsd__boolean));
        *(stNetIntReq.NetworkInterface->IPv4->Enabled) = xsd__boolean__true_;

        stNetIntReq.NetworkInterface->IPv4->DHCP = (enum xsd__boolean *)soap_malloc(pSoap, sizeof(enum xsd__boolean));
        if (0 == pNetInfo->stInterFace[i].ipType)
        {
            *(stNetIntReq.NetworkInterface->IPv4->DHCP) = xsd__boolean__false_;
            stNetIntReq.NetworkInterface->IPv4->__sizeManual = pNetInfo->stInterFace[i].addrNum;
            stNetIntReq.NetworkInterface->IPv4->Manual = (struct tt__PrefixedIPv4Address *)
                soap_malloc(pSoap, sizeof(struct tt__PrefixedIPv4Address) * stNetIntReq.NetworkInterface->IPv4->__sizeManual);
            for (j = 0; j < stNetIntReq.NetworkInterface->IPv4->__sizeManual; j++)
            {
                printf("newIp: %s\n", pNetInfo->stInterFace[i].stIpv4Info[j].acIPv4Addr);
                stNetIntReq.NetworkInterface->IPv4->Manual[j].Address      = pNetInfo->stInterFace[i].stIpv4Info[j].acIPv4Addr;
                stNetIntReq.NetworkInterface->IPv4->Manual[j].PrefixLength = pNetInfo->stInterFace[i].stIpv4Info[j].prefixLength;
            }
        }
        else if (2 == pNetInfo->stInterFace[i].ipType)
        {
            *(stNetIntReq.NetworkInterface->IPv4->DHCP) = xsd__boolean__true_;
        }
        
        sprintf(acXAddr, "http://%s/onvif/device_service", pReq->acDevIp);
    	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
        memset(&stNetIntResp, 0, sizeof(stNetIntResp));
    	soap_call___tds__SetNetworkInterfaces(pSoap, acXAddr, NULL, &stNetIntReq, &stNetIntResp);
    	if (pSoap->error)
    	{
    		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            W_OnvifSoapDelete(pSoap);
    		return SOAP_ERR;
    	}
        W_OnvifSoapDelete(pSoap);
        printf("------------------Set Net Interfaces success-----------------\n");
    }
    
    return SOAP_OK;
}


int W_GetDNSInfo(W_ONVIF_REQ_ST *pReq, W_ONVIF_DNS_ST *pDNS)
{
    int i = 0;
    char acXAddr[128] = {0};
    struct soap *pSoap = NULL;
    struct _tds__GetDNS stDNSReq;
    struct _tds__GetDNSResponse stDNSResp;
    
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stDNSReq, 0, sizeof(stDNSReq));
	printf("------------------Get DNS information-----------------\n");
    sprintf(acXAddr, "http://%s/onvif/device_service", pReq->acDevIp);
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tds__GetDNS(pSoap, acXAddr, NULL, &stDNSReq, &stDNSResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

    if (NULL != stDNSResp.DNSInformation)
    {
        printf("FromDHCP: %d\n", stDNSResp.DNSInformation->FromDHCP);
        if (stDNSResp.DNSInformation->FromDHCP)
        {
            printf("sizeDNSFromDHCP: %d\n", stDNSResp.DNSInformation->__sizeDNSFromDHCP);
            pDNS->DNSNum = stDNSResp.DNSInformation->__sizeDNSFromDHCP;
            for (i = 0; i < pDNS->DNSNum; i++)
            {
                if (tt__IPType__IPv4 == stDNSResp.DNSInformation->DNSFromDHCP[i].Type)
                {
                    printf("ipv4Addr: %s\n", stDNSResp.DNSInformation->DNSFromDHCP[i].IPv4Address);
                    strcpy(pDNS->stDNS[i].acIPv4Addr, stDNSResp.DNSInformation->DNSFromDHCP[i].IPv4Address);
                }
                else
                {
                    printf("ipv6Addr: %s\n", stDNSResp.DNSInformation->DNSFromDHCP[i].IPv6Address);
                    strcpy(pDNS->stDNS[i].acIPv6Addr, stDNSResp.DNSInformation->DNSFromDHCP[i].IPv6Address);
                }
                
            }
        }
        else
        {
            printf("sizeDNSManual: %d\n", stDNSResp.DNSInformation->__sizeDNSManual);
            pDNS->DNSNum = stDNSResp.DNSInformation->__sizeDNSManual;
            for (i = 0; i < pDNS->DNSNum; i++)
            {
                if (tt__IPType__IPv4 == stDNSResp.DNSInformation->DNSManual[i].Type)
                {
                    printf("ipv4Addr: %s\n", stDNSResp.DNSInformation->DNSManual[i].IPv4Address);
                    strcpy(pDNS->stDNS[i].acIPv4Addr, stDNSResp.DNSInformation->DNSManual[i].IPv4Address);
                }
                else
                {
                    printf("ipv6Addr: %s\n", stDNSResp.DNSInformation->DNSManual[i].IPv6Address);
                    strcpy(pDNS->stDNS[i].acIPv4Addr, stDNSResp.DNSInformation->DNSManual[i].IPv4Address);
                }
            }
        }
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_SetDNSInfo(W_ONVIF_REQ_ST *pReq, W_ONVIF_DNS_ST *pDNS)
{
    int i = 0;
    char acXAddr[128] = {0};
    struct soap *pSoap = NULL;
    struct _tds__SetDNS stDNSReq;
    struct _tds__SetDNSResponse stDNSResp;
    
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stDNSReq, 0, sizeof(stDNSReq));
	printf("----------------------Set DNS information---------------------\n");

    if (0 == pDNS->DNSNum)
    {
        stDNSReq.FromDHCP = xsd__boolean__true_ ;
    }
    else
    {
        stDNSReq.FromDHCP = xsd__boolean__false_ ;
        stDNSReq.__sizeDNSManual = pDNS->DNSNum;
        for (i = 0; i < stDNSReq.__sizeDNSManual; i++)
        {
            stDNSReq.DNSManual = (struct tt__IPAddress *)soap_malloc(pSoap, sizeof(struct tt__IPAddress) * stDNSReq.__sizeDNSManual);
            memset(stDNSReq.DNSManual, 0, sizeof(stDNSReq.DNSManual));
            stDNSReq.DNSManual[i].Type = pDNS->stDNS[i].addrType;
            printf("DNS IPv4Addr: %s\n", pDNS->stDNS[i].acIPv4Addr);
            stDNSReq.DNSManual[i].IPv4Address = pDNS->stDNS[i].acIPv4Addr;
            stDNSReq.DNSManual[i].IPv6Address = pDNS->stDNS[i].acIPv6Addr;
        }
    }
    
    sprintf(acXAddr, "http://%s/onvif/device_service", pReq->acDevIp);
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tds__SetDNS(pSoap, acXAddr, NULL, &stDNSReq, &stDNSResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    printf("-------------------Set DNS information success----------------\n");

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetScopes(W_ONVIF_REQ_ST *pReq)
{
    int i = 0;
    char acXAddrs[128] = {0};
    struct soap *pSoap = NULL;
    struct _tds__GetScopes stScopesReq;
    struct _tds__GetScopesResponse stScopesResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stScopesReq, 0, sizeof(stScopesReq));
    printf("\n--------------------Get Scopes--------------------\n");
    sprintf(acXAddrs, "http://%s/onvif/device_service", pReq->acDevIp);
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tds__GetScopes(pSoap, acXAddrs, NULL, &stScopesReq, &stScopesResp);
	if (pSoap->error)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    printf("sizeScopes: %d\n", stScopesResp.__sizeScopes);
    for (i = 0; i < stScopesResp.__sizeScopes; i++)
    {
        printf("ScopeDef:  %d\n", stScopesResp.Scopes[i].ScopeDef);
        printf("ScopeItem: %s\n", stScopesResp.Scopes[i].ScopeItem);
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetServices(W_ONVIF_REQ_ST *pReq)
{
    int i = 0;
    char acXAddrs[128] = {0};
    struct soap *pSoap = NULL;
    struct _tds__GetServices stServersReq;
    struct _tds__GetServicesResponse stServersResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stServersReq, 0, sizeof(stServersReq));
    stServersReq.IncludeCapability = xsd__boolean__true_;
    
    printf("\n--------------------Get Services--------------------\n");
    sprintf(acXAddrs, "http://%s/onvif/device_service", pReq->acDevIp);
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tds__GetServices(pSoap, acXAddrs, NULL, &stServersReq, &stServersResp);
	if (pSoap->error)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }
    
    for (i = 0; i < stServersResp.__sizeService; i++)
    {
        if (0 == strcmp(stServersResp.Service[i].Namespace, "http://www.onvif.org/ver10/media/wsdl"))
        {
            printf("XAddr: %s\n", stServersResp.Service[i].XAddr);
            strcpy(pReq->acXaddr, stServersResp.Service[i].XAddr);
        }
        if (0 == strcmp(stServersResp.Service[i].Namespace, "http://www.onvif.org/ver20/ptz/wsdl"))
        {
            printf("ptzXAddr: %s\n", stServersResp.Service[i].XAddr);
            strcpy(pReq->acPtzXaddr, stServersResp.Service[i].XAddr);
        }
        if (0 == strcmp(stServersResp.Service[i].Namespace, "http://www.onvif.org/ver20/media/wsdl"))
        {
            printf("Media2Addr: %s\n", stServersResp.Service[i].XAddr);
            strcpy(pReq->acMedia2Addr, stServersResp.Service[i].XAddr);
        }
        if (0 == strcmp(stServersResp.Service[i].Namespace, "http://www.onvif.org/ver20/analytics/wsdl"))
        {
            printf("Analytics: %s\n", stServersResp.Service[i].XAddr);
            strcpy(pReq->acAnalytics, stServersResp.Service[i].XAddr);
        }
        if (0 == strcmp(stServersResp.Service[i].Namespace, "http://www.onvif.org/ver10/events/wsdl"))
        {
            printf("EventAddr: %s\n", stServersResp.Service[i].XAddr);
            strcpy(pReq->acEventAddr, stServersResp.Service[i].XAddr);
        }
        if (0 == strcmp(stServersResp.Service[i].Namespace, "http://www.onvif.org/ver20/imaging/wsdl"))
        {
            printf("ImageAddr: %s\n", stServersResp.Service[i].XAddr);
            strcpy(pReq->acImageAddr, stServersResp.Service[i].XAddr);
        }
        if(0 == strcmp(stServersResp.Service[i].Namespace, "http://www.onvif.org/ver10/deviceIO/wsdl"))
        {
            printf("DeviceIO: %s\n", stServersResp.Service[i].XAddr);
            strcpy(pReq->acDeviceIO, stServersResp.Service[i].XAddr);
        }
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetCapabilities(W_ONVIF_REQ_ST *pReq, enum tt__CapabilityCategory capaType)
{
    char acXAddrs[128] = {0};
    struct soap *pSoap = NULL;
    struct _tds__GetCapabilities stCapaReq;
    struct _tds__GetCapabilitiesResponse stCapaResp;

	pSoap = W_OnvifSoapNew(10);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stCapaReq, 0, sizeof(stCapaReq));
    stCapaReq.__sizeCategory = 1;
    stCapaReq.Category    = (enum tt__CapabilityCategory *)soap_malloc(pSoap, sizeof(int));
    *(stCapaReq.Category) = (enum tt__CapabilityCategory)capaType;
    
    printf("\n--------------------Get Capabilities--------------------\n");
    sprintf(acXAddrs, "http://%s/onvif/device_service", pReq->acDevIp);
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tds__GetCapabilities(pSoap, acXAddrs, NULL, &stCapaReq, &stCapaResp);
	if (pSoap->error)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    if (NULL != stCapaResp.Capabilities)
    {
        printf("Media->XAddr: %s\n", stCapaResp.Capabilities->Media->XAddr);
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}

int W_GetProfiles(W_ONVIF_REQ_ST *pReq)
{
	int sRet = 0 ;
    int i = 0;
    struct soap *pSoap = NULL;
    struct _trt__GetProfiles stProfilesReq;
    struct _trt__GetProfilesResponse stProfilesResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stProfilesReq, 0, sizeof(stProfilesReq));
	printf("\n------------------Get Devices Profiles-----------------\n");
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	sRet = soap_call___trt__GetProfiles(pSoap, pReq->acXaddr, NULL, &stProfilesReq, &stProfilesResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        soap_print_fault(pSoap, stderr);
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    
    printf("sizeProfile: %d\n", stProfilesResp.__sizeProfiles);
    pReq->prifTokenNum = (stProfilesResp.__sizeProfiles <= 3) ? stProfilesResp.__sizeProfiles : 3;
    for (i = 0; i < stProfilesResp.__sizeProfiles; i++)
    {
        printf("Profiles Name:%s\n",  stProfilesResp.Profiles[i].Name);
        printf("Profiles Token:%s\n", stProfilesResp.Profiles[i].token);
        strcpy(pReq->aaPrifToken[i], stProfilesResp.Profiles[i].token);

        if (stProfilesResp.Profiles[i].PTZConfiguration)
        {
            if (stProfilesResp.Profiles[i].PTZConfiguration->NodeToken)
            {
                pReq->s32IsSupportPTZ = 1;
            }
        }

        if (stProfilesResp.Profiles[i].VideoAnalyticsConfiguration && stProfilesResp.Profiles[i].VideoAnalyticsConfiguration->token)
        {
            if (pReq->analyticsTokenNum < 3)
            {
                strcpy(pReq->aaAnalyticsToken[pReq->analyticsTokenNum], stProfilesResp.Profiles[i].VideoAnalyticsConfiguration->token);
                pReq->analyticsTokenNum++;
            }

            struct tt__AnalyticsEngineConfiguration *AnalyticsEngineConfiguration = stProfilesResp.Profiles[i].VideoAnalyticsConfiguration->AnalyticsEngineConfiguration;
            if (0 == i && AnalyticsEngineConfiguration)
            {
                for(int s32Idx = 0; s32Idx < AnalyticsEngineConfiguration->__sizeAnalyticsModule; s32Idx++)
                {
                    struct tt__Config *AnalyticsModule = &AnalyticsEngineConfiguration->AnalyticsModule[s32Idx];
                    if(0 == strcmp(AnalyticsModule->Name, "MyCellMotionModule"))
                    {
                        struct _tt__ItemList_ElementItem *ElementItem = AnalyticsModule->Parameters->ElementItem;
                        if (ElementItem)
                        {
                            if (0 == strcmp(ElementItem->Name, "Layout") && ElementItem->__any)
                            {
                                char as8CellLayout[32] = {0};
                                int s32Columns = 0, s32Rows = 0;
                                if (0 == ParseStringValue(ElementItem->__any, "<tt:CellLayout ", "><tt:Transformation>", as8CellLayout))
                                {
                                    printf("%s\n", as8CellLayout);
                                    sscanf(as8CellLayout, "Columns=\"%d\" Rows=\"%d\"", &s32Columns, &s32Rows);
                                    printf("s32Columns:%d s32Rows:%d\n", s32Columns, s32Rows);
                                    pReq->s32MDCellColumns = s32Columns;
                                    pReq->s32MDCellRows = s32Rows;
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
	}

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetVideoSources(W_ONVIF_REQ_ST *pReq)
{
	int i = 0 ;
    struct soap *pSoap = NULL;
    struct _trt__GetVideoSources stVideoReq;
    struct _trt__GetVideoSourcesResponse stVideoResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stVideoReq, 0, sizeof(stVideoReq));
	printf("\n------------------Get Video Sources-----------------\n");
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___trt__GetVideoSources(pSoap, pReq->acXaddr, NULL, &stVideoReq, &stVideoResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    
    printf("VideoSourcesNum: %d\n", stVideoResp.__sizeVideoSources);
    for (i = 0; i < stVideoResp.__sizeVideoSources; i++)
    {
        printf("token:     %s\n", stVideoResp.VideoSources[i].token);
        printf("framerate: %f\n", stVideoResp.VideoSources[i].Framerate);
        printf("width:     %d\n", stVideoResp.VideoSources[i].Resolution->Width);
        printf("height:    %d\n", stVideoResp.VideoSources[i].Resolution->Height);
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetVideoSourceConfigs(W_ONVIF_REQ_ST *pReq)
{
	int i = 0 ;
    struct soap *pSoap = NULL;
    struct _trt__GetVideoSourceConfigurations stVideoCnfReq;
    struct _trt__GetVideoSourceConfigurationsResponse stVideoCnfResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stVideoCnfReq, 0, sizeof(stVideoCnfReq));
	printf("\n------------------Get Video Source configs-----------------\n");
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___trt__GetVideoSourceConfigurations(pSoap, pReq->acXaddr, NULL, &stVideoCnfReq, &stVideoCnfResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    
    printf("SizeConfigurations: %d\n", stVideoCnfResp.__sizeConfigurations);
    pReq->cnfTokenNum = (stVideoCnfResp.__sizeConfigurations <= 3) ? stVideoCnfResp.__sizeConfigurations : 3;
    for (i = 0; i < stVideoCnfResp.__sizeConfigurations; i++)
    {
        printf("Name:        %s\n", stVideoCnfResp.Configurations[i].Name);
        printf("token:       %s\n", stVideoCnfResp.Configurations[i].token);
        printf("SourceToken: %s\n", stVideoCnfResp.Configurations[i].SourceToken);
        strcpy(pReq->aaCnfToken[i], stVideoCnfResp.Configurations[i].token);
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetVideoSourceModes(W_ONVIF_REQ_ST *pReq, W_VIDEO_MODE_ST *pVideoModes)
{
    struct soap *pSoap = NULL;
    struct _trt__GetVideoSourceModes stVideoModesReq;
    struct _trt__GetVideoSourceModesResponse stVideoModesResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stVideoModesReq, 0, sizeof(stVideoModesReq));
	printf("\n------------------Get Video Source Modes-----------------\n");
    stVideoModesReq.VideoSourceToken = pReq->aaCnfToken[0];
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___trt__GetVideoSourceModes(pSoap, pReq->acXaddr, NULL, &stVideoModesReq, &stVideoModesResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    
    printf("sizeVideoSourceModes: %d\n", stVideoModesResp.__sizeVideoSourceModes);
    pVideoModes->width     = stVideoModesResp.VideoSourceModes[0].MaxResolution->Width;
    pVideoModes->height    = stVideoModesResp.VideoSourceModes[0].MaxResolution->Height;
    pVideoModes->frameRate = (int)stVideoModesResp.VideoSourceModes[0].MaxFramerate;
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK; 
}


int W_SetVideoSourceModes(W_ONVIF_REQ_ST *pReq, W_VIDEO_MODE_ST *pVideoModes)
{
    struct soap *pSoap = NULL;
    struct _trt__SetVideoSourceMode stVideoModeReq;
    struct _trt__SetVideoSourceModeResponse stVideoModeResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stVideoModeReq, 0, sizeof(stVideoModeReq));
	printf("\n------------------Set Video Source Mode-----------------\n");
    stVideoModeReq.VideoSourceToken = pReq->aaCnfToken[0];
    stVideoModeReq.VideoSourceToken = "VideoSourceModeToken";
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___trt__SetVideoSourceMode(pSoap, pReq->acXaddr, NULL, &stVideoModeReq, &stVideoModeResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    printf("ifReboot: %d\n", stVideoModeResp.Reboot);

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetVideoEncodeConfigs(W_ONVIF_REQ_ST *pReq, W_ONVIF_VIDEO_PARAMS_ST *pVideoParams)
{
	int i = 0 ;
    struct soap *pSoap = NULL;
    struct _trt__GetVideoEncoderConfigurations stVideoEncCnfReq;
    struct _trt__GetVideoEncoderConfigurationsResponse stVideoEncCnfResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stVideoEncCnfReq, 0, sizeof(stVideoEncCnfReq));
	printf("\n------------------Get Video Encode configs-----------------\n");
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___trt__GetVideoEncoderConfigurations(pSoap, pReq->acXaddr, NULL, &stVideoEncCnfReq, &stVideoEncCnfResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    
    printf("SizeConfigurations: %d\n", stVideoEncCnfResp.__sizeConfigurations);
    pReq->cnfTokenNum = stVideoEncCnfResp.__sizeConfigurations;
    pVideoParams->streamNum = stVideoEncCnfResp.__sizeConfigurations;
    
    for (i = 0; i < stVideoEncCnfResp.__sizeConfigurations; i++)
    {
        printf("Name:   %s\n", stVideoEncCnfResp.Configurations[i].Name);
        printf("token:  %s\n", stVideoEncCnfResp.Configurations[i].token);
        strcpy(pReq->aaCnfToken[i], stVideoEncCnfResp.Configurations[i].token);

        pVideoParams->stStreamInfo[i].streamId       = i;
        pVideoParams->stStreamInfo[i].mainStramType  = 0;
        pVideoParams->stStreamInfo[i].encEnable      = 1;
        if (tt__VideoEncoding__JPEG  == stVideoEncCnfResp.Configurations[i].Encoding ||
            tt__VideoEncoding__MPEG4 == stVideoEncCnfResp.Configurations[i].Encoding)
        {
            pVideoParams->stStreamInfo[i].encFormat = 0;
        }
        else if (tt__VideoEncoding__H264  == stVideoEncCnfResp.Configurations[i].Encoding)
        {
            pVideoParams->stStreamInfo[i].encFormat = 1;
        }
        else
        {
            pVideoParams->stStreamInfo[i].encFormat = 2;
        }
        
        if (NULL != stVideoEncCnfResp.Configurations[i].Resolution)
        {
            pVideoParams->stStreamInfo[i].width   = stVideoEncCnfResp.Configurations[i].Resolution->Width;
            pVideoParams->stStreamInfo[i].height  = stVideoEncCnfResp.Configurations[i].Resolution->Height;
        }

        pVideoParams->stStreamInfo[i].bitRateType    = 0;
        if (NULL != stVideoEncCnfResp.Configurations[i].RateControl)
        {
            pVideoParams->stStreamInfo[i].bitRate        = stVideoEncCnfResp.Configurations[i].RateControl->BitrateLimit;
            pVideoParams->stStreamInfo[i].frameRate      = stVideoEncCnfResp.Configurations[i].RateControl->FrameRateLimit;
        }

        if (NULL != stVideoEncCnfResp.Configurations[i].H264)
        {
            pVideoParams->stStreamInfo[i].IFrameInterval = stVideoEncCnfResp.Configurations[i].H264->GovLength;
            pVideoParams->stStreamInfo[i].profileLine    = stVideoEncCnfResp.Configurations[i].H264->H264Profile;
        }
        else if (NULL != stVideoEncCnfResp.Configurations[i].MPEG4)
        {
            pVideoParams->stStreamInfo[i].IFrameInterval = stVideoEncCnfResp.Configurations[i].MPEG4->GovLength;
            pVideoParams->stStreamInfo[i].profileLine    = stVideoEncCnfResp.Configurations[i].MPEG4->Mpeg4Profile;
        }
        pVideoParams->stStreamInfo[i].imageQuality   = (int)stVideoEncCnfResp.Configurations[i].Quality;
        pVideoParams->stStreamInfo[i].smoothLevel    = 5;
        pVideoParams->stStreamInfo[i].smartEncMode   = 0;
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_SetVideoEncodeConfigs(W_ONVIF_REQ_ST *pReq, W_ONVIF_VIDEO_PARAMS_ST *pVideoParams)
{
	int i = 0 ;
    int streamId = 0;
    struct soap *pSoap = NULL;
    struct _trt__GetVideoEncoderConfigurations stGetVideoEncCnfReq;
    struct _trt__GetVideoEncoderConfigurationsResponse stGetVideoEncCnfResp;
    struct _trt__SetVideoEncoderConfiguration stVideoEncCnfReq;
    struct _trt__SetVideoEncoderConfigurationResponse stVideoEncCnfResp;
    
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    /* first get video encode configs */
    memset(&stGetVideoEncCnfReq, 0, sizeof(stGetVideoEncCnfReq));
	printf("\n------------------Set Video Encode configs-----------------\n");
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___trt__GetVideoEncoderConfigurations(pSoap, pReq->acXaddr, NULL, &stGetVideoEncCnfReq, &stGetVideoEncCnfResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

    for (i = 0; i < pVideoParams->streamNum; i++)
    {
        memset(&stVideoEncCnfReq, 0, sizeof(stVideoEncCnfReq));
        stVideoEncCnfReq.ForcePersistence = xsd__boolean__true_;
        
        streamId = pVideoParams->stStreamInfo[i].streamId;
        stVideoEncCnfReq.Configuration = &(stGetVideoEncCnfResp.Configurations[streamId]);
        if (NULL != stVideoEncCnfReq.Configuration->H264)
        {
            stVideoEncCnfReq.Configuration->H264->GovLength   = pVideoParams->stStreamInfo[i].IFrameInterval;
            stVideoEncCnfReq.Configuration->H264->H264Profile = pVideoParams->stStreamInfo[i].profileLine;
        }
        else if (NULL != stVideoEncCnfReq.Configuration->MPEG4)
        {
            stVideoEncCnfReq.Configuration->MPEG4->GovLength    = pVideoParams->stStreamInfo[i].IFrameInterval;
            stVideoEncCnfReq.Configuration->MPEG4->Mpeg4Profile = pVideoParams->stStreamInfo[i].profileLine;
        }
        else
        {
            printf("This encode format:%d does not support\n", pVideoParams->stStreamInfo[i].encFormat);
            W_OnvifSoapDelete(pSoap);
            return SOAP_ERR;
        }
        
        stVideoEncCnfReq.Configuration->Resolution->Width  = pVideoParams->stStreamInfo[i].width;
        stVideoEncCnfReq.Configuration->Resolution->Height = pVideoParams->stStreamInfo[i].height;
        stVideoEncCnfReq.Configuration->RateControl->BitrateLimit   = pVideoParams->stStreamInfo[i].bitRate;
        stVideoEncCnfReq.Configuration->RateControl->FrameRateLimit = pVideoParams->stStreamInfo[i].frameRate;
        stVideoEncCnfReq.Configuration->Quality = pVideoParams->stStreamInfo[i].imageQuality;
        
    	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    	soap_call___trt__SetVideoEncoderConfiguration(pSoap, pReq->acXaddr, NULL, &stVideoEncCnfReq, &stVideoEncCnfResp);
    	if (pSoap->error)
    	{
    		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            W_OnvifSoapDelete(pSoap);
    		return SOAP_ERR;
    	}
    }
    printf("---------------Set Video Encode configs success--------------\n");
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_VideoSourceConfigsOptions(W_ONVIF_REQ_ST *pReq)
{
	int i = 0 ;
    struct soap *pSoap = NULL;
    struct _trt__GetVideoSourceConfigurationOptions stVideoSourceCnfOptReq;
    struct _trt__GetVideoSourceConfigurationOptionsResponse stVideoSourceCnfOptResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stVideoSourceCnfOptReq, 0, sizeof(stVideoSourceCnfOptReq));
	printf("\n------------------Get Video Source configs Options-----------------\n");
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___trt__GetVideoSourceConfigurationOptions(pSoap, pReq->acXaddr, NULL, &stVideoSourceCnfOptReq, &stVideoSourceCnfOptResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    
    if (NULL != stVideoSourceCnfOptResp.Options->BoundsRange)
    {
        printf("WidMin:   %d\n", stVideoSourceCnfOptResp.Options->BoundsRange->WidthRange->Min);
        printf("WidMax:   %d\n", stVideoSourceCnfOptResp.Options->BoundsRange->WidthRange->Max);
        printf("HigMin:   %d\n", stVideoSourceCnfOptResp.Options->BoundsRange->HeightRange->Min);
        printf("HigMax:   %d\n", stVideoSourceCnfOptResp.Options->BoundsRange->HeightRange->Max);
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_VideoEncodeConfigsOptions(W_ONVIF_REQ_ST *pReq, W_ONVIF_VIDEO_CAPABILITY_ST *pVideoCapality)
{
	int i = 0, j = 0;
    int minBit = 0, maxBit = 0;
    struct soap *pSoap = NULL;
    struct _trt__GetVideoEncoderConfigurationOptions stVideoEncCnfOptReq;
    struct _trt__GetVideoEncoderConfigurationOptionsResponse stVideoEncCnfOptResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stVideoEncCnfOptReq, 0, sizeof(stVideoEncCnfOptReq));
	printf("\n------------------Get Video Encode configs Options-----------------\n");
	
    for (i = 0; i < pReq->cnfTokenNum; i++)
    {
        stVideoEncCnfOptReq.ProfileToken = pReq->aaPrifToken[i];
        stVideoEncCnfOptReq.ConfigurationToken = pReq->aaCnfToken[i];
        printf("prifToken: %s, cnfToken: %s\n", stVideoEncCnfOptReq.ProfileToken, stVideoEncCnfOptReq.ConfigurationToken);
        soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    	soap_call___trt__GetVideoEncoderConfigurationOptions(pSoap, pReq->acXaddr, NULL, &stVideoEncCnfOptReq, &stVideoEncCnfOptResp);
        if (pSoap->error)
    	{
    		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            W_OnvifSoapDelete(pSoap);
    		return SOAP_ERR;
    	}
        
        pVideoCapality->isSupCfg = 1;
        pVideoCapality->isSupSmoothLevel = 1;
        pVideoCapality->isSupImageFormat = 1;
        pVideoCapality->encodeFormatNum  = 0;
        if (NULL != stVideoEncCnfOptResp.Options->H264)
        {
            pVideoCapality->encodeFormatNum += 2;
            pVideoCapality->encodeFormatList[0] = 1;
            pVideoCapality->encodeFormatList[1] = 2;
        }
        if (NULL != stVideoEncCnfOptResp.Options->JPEG)
        {
            pVideoCapality->encodeFormatNum++;
            pVideoCapality->encodeFormatList[2] = 3;
        }
        if (NULL != stVideoEncCnfOptResp.Options->QualityRange)
        {
            pVideoCapality->minQuality = stVideoEncCnfOptResp.Options->QualityRange->Min;
            pVideoCapality->maxQuality = stVideoEncCnfOptResp.Options->QualityRange->Max;
        }
        pVideoCapality->minIFrameInterval = stVideoEncCnfOptResp.Options->H264->GovLengthRange->Min;
        pVideoCapality->maxIFrameInterval = stVideoEncCnfOptResp.Options->H264->GovLengthRange->Max;

        pVideoCapality->streamCapaNum = pReq->prifTokenNum;
        if (NULL == pVideoCapality->pStreamCapaList)
        {
            pVideoCapality->pStreamCapaList = (W_STREAM_CAPALITY_ST *)calloc(1, pVideoCapality->streamCapaNum * sizeof(W_STREAM_CAPALITY_ST));
        }
        pVideoCapality->pStreamCapaList[i].streamId = i;
        pVideoCapality->pStreamCapaList[i].resolutionNum = stVideoEncCnfOptResp.Options->H264->__sizeResolutionsAvailable;
        if (NULL == pVideoCapality->pStreamCapaList[i].pResoluCapaList)
        {
            pVideoCapality->pStreamCapaList[i].pResoluCapaList = 
                (W_RESOLU_CAPALITY_ST *)malloc(pVideoCapality->pStreamCapaList[i].resolutionNum * sizeof(W_RESOLU_CAPALITY_ST));
        }

        if (NULL != stVideoEncCnfOptResp.Options->Extension)
        {
            if (NULL != stVideoEncCnfOptResp.Options->Extension->H264)
            {
                minBit = stVideoEncCnfOptResp.Options->Extension->H264->BitrateRange->Min;
                maxBit = stVideoEncCnfOptResp.Options->Extension->H264->BitrateRange->Max;
            }
        }
        for (j = 0; j < pVideoCapality->pStreamCapaList[i].resolutionNum; j++)
        {
            pVideoCapality->pStreamCapaList[i].pResoluCapaList[j].width  = 
                stVideoEncCnfOptResp.Options->H264->ResolutionsAvailable[j].Width;
            pVideoCapality->pStreamCapaList[i].pResoluCapaList[j].height = 
                stVideoEncCnfOptResp.Options->H264->ResolutionsAvailable[j].Height;
            pVideoCapality->pStreamCapaList[i].pResoluCapaList[j].minBitRate = minBit;
            pVideoCapality->pStreamCapaList[i].pResoluCapaList[j].maxBitRate = maxBit;
        }
        
        pVideoCapality->pStreamCapaList[i].maxFrameRate = stVideoEncCnfOptResp.Options->H264->FrameRateRange->Max;

        pVideoCapality->pStreamCapaList[i].stSmartEncode.H264SmartEncModeNum = 
            stVideoEncCnfOptResp.Options->H264->__sizeH264ProfilesSupported;
        for (j = 0; j < pVideoCapality->pStreamCapaList[i].stSmartEncode.H264SmartEncModeNum; j++)
        {
            pVideoCapality->pStreamCapaList[i].stSmartEncode.H264SmartEncModeList[j] = 
                stVideoEncCnfOptResp.Options->H264->H264ProfilesSupported[j];
        }
	}
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetAudioSources(W_ONVIF_REQ_ST *pReq)
{
	int i = 0 ;
    struct soap *pSoap = NULL;
    struct _trt__GetAudioSources stAudioReq;
    struct _trt__GetAudioSourcesResponse stAudioResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stAudioReq, 0, sizeof(stAudioReq));
	printf("\n------------------Get Audio Sources-----------------\n");
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___trt__GetAudioSources(pSoap, pReq->acXaddr, NULL, &stAudioReq, &stAudioResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    
    printf("AudioSourcesNum: %d\n", stAudioResp.__sizeAudioSources);
    for (i = 0; i < stAudioResp.__sizeAudioSources; i++)
    {
        printf("Token:    %s\n", stAudioResp.AudioSources[i].token);
        printf("Channels: %d\n", stAudioResp.AudioSources[i].Channels);
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetAudioSourceConfigs(W_ONVIF_REQ_ST *pReq)
{
	int i = 0 ;
    struct soap *pSoap = NULL;
    struct _trt__GetAudioSourceConfigurations stAudioCnfReq;
    struct _trt__GetAudioSourceConfigurationsResponse stAudioCnfResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stAudioCnfReq, 0, sizeof(stAudioCnfReq));
	printf("\n------------------Get Audio Source config-----------------\n");
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___trt__GetAudioSourceConfigurations(pSoap, pReq->acXaddr, NULL, &stAudioCnfReq, &stAudioCnfResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    
    printf("sizeConfigurations: %d\n", stAudioCnfResp.__sizeConfigurations);
    pReq->cnfTokenNum = stAudioCnfResp.__sizeConfigurations;
    for (i = 0; i < stAudioCnfResp.__sizeConfigurations; i++)
    {
        printf("Name:        %s\n", stAudioCnfResp.Configurations[i].Name);
        printf("token:       %s\n", stAudioCnfResp.Configurations[i].token);
        printf("SourceToken: %s\n", stAudioCnfResp.Configurations[i].SourceToken);
        strcpy(pReq->aaCnfToken[i], stAudioCnfResp.Configurations[i].token);
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetAudioEncodeConfigs(W_ONVIF_REQ_ST *pReq, W_ONVIF_AUDIO_PARAMS_ST *pAudioParams)
{
	int i = 0 ;
    struct soap *pSoap = NULL;
    struct _trt__GetAudioEncoderConfigurations stAudioEncCnfReq;
    struct _trt__GetAudioEncoderConfigurationsResponse stAudioEncCnfResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stAudioEncCnfReq, 0, sizeof(stAudioEncCnfReq));
	printf("\n------------------Get Audio Encode config-----------------\n");
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___trt__GetAudioEncoderConfigurations(pSoap, pReq->acXaddr, NULL, &stAudioEncCnfReq, &stAudioEncCnfResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    
    printf("sizeConfigurations: %d\n", stAudioEncCnfResp.__sizeConfigurations);
    pReq->cnfTokenNum = stAudioEncCnfResp.__sizeConfigurations;
    for (i = 0; i < stAudioEncCnfResp.__sizeConfigurations; i++)
    {
        printf("Name:     %s\n", stAudioEncCnfResp.Configurations[i].Name);
        printf("token:    %s\n", stAudioEncCnfResp.Configurations[i].token);
        printf("Encoding: %d\n", stAudioEncCnfResp.Configurations[i].Encoding);
        strcpy(pReq->aaCnfToken[i], stAudioEncCnfResp.Configurations[i].token);
    }

    if (stAudioEncCnfResp.__sizeConfigurations > 0)
    {
        pAudioParams->isMute       = 0;
        pAudioParams->type         = 0;
        if (tt__AudioEncoding__G711 == stAudioEncCnfResp.Configurations->Encoding)
        {
            pAudioParams->encodeFormat = 1;
        }
        else if (tt__AudioEncoding__G726 == stAudioEncCnfResp.Configurations->Encoding)
        {
            pAudioParams->encodeFormat = 3;
        }
        else if (tt__AudioEncoding__AAC == stAudioEncCnfResp.Configurations->Encoding)
        {
            pAudioParams->encodeFormat = 6;
        }
        pAudioParams->sampleRate    = stAudioEncCnfResp.Configurations->SampleRate;
        pAudioParams->biteRate      = stAudioEncCnfResp.Configurations->Bitrate;
        pAudioParams->inputGain     = 0;
        pAudioParams->enableDenoise = 0;
        pAudioParams->audioInputNum = stAudioEncCnfResp.__sizeConfigurations;
        for (i = 0; i < pAudioParams->audioInputNum; i++)
        {
            pAudioParams->stAudioInput[i].chnId   = i + 1;
            pAudioParams->stAudioInput[i].enabled = 1;
            pAudioParams->stAudioInput[i].mode    = 2;
        }
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_SetAudioEncodeConfigs(W_ONVIF_REQ_ST *pReq, W_ONVIF_AUDIO_PARAMS_ST *pAudioParams)
{
	int i = 0 ;
    struct soap *pSoap = NULL;
    struct _trt__GetAudioEncoderConfigurations stGetAudioEncCnfReq;
    struct _trt__GetAudioEncoderConfigurationsResponse stGetAudioEncCnfResp;
    struct _trt__SetAudioEncoderConfiguration stAudioEncCnfReq;
    struct _trt__SetAudioEncoderConfigurationResponse stAudioEncCnfResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}

    /* first get audio encode configs */
    memset(&stGetAudioEncCnfReq, 0, sizeof(stGetAudioEncCnfReq));
	printf("\n------------------Set Audio Encode config-----------------\n");
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___trt__GetAudioEncoderConfigurations(pSoap, pReq->acXaddr, NULL, &stGetAudioEncCnfReq, &stGetAudioEncCnfResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

    memset(&stAudioEncCnfReq, 0, sizeof(stAudioEncCnfReq));
    stAudioEncCnfReq.Configuration = stGetAudioEncCnfResp.Configurations;
    printf("oldFormat:%d, newFormat: %d\n", stGetAudioEncCnfResp.Configurations->Encoding, pAudioParams->encodeFormat);
    if (1 == pAudioParams->encodeFormat)
    {
        stAudioEncCnfReq.Configuration->Encoding = tt__AudioEncoding__G711;
    }
    else if (3 == pAudioParams->encodeFormat)
    {
        stAudioEncCnfReq.Configuration->Encoding = tt__AudioEncoding__G726;
    }
    else if (6 == pAudioParams->encodeFormat)
    {
        stAudioEncCnfReq.Configuration->Encoding = tt__AudioEncoding__AAC;
    }
    stAudioEncCnfReq.Configuration->SampleRate = pAudioParams->sampleRate;
    
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___trt__SetAudioEncoderConfiguration(pSoap, pReq->acXaddr, NULL, &stAudioEncCnfReq, &stAudioEncCnfResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    printf("---------------Set Audio Encode config success--------------\n");

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_AudioSourceConfigsOptions(W_ONVIF_REQ_ST *pReq, W_ONVIF_AUDIO_CAPABILITY_ST *pAudioCapality)
{
	int i = 0;
    struct soap *pSoap = NULL;
    struct _trt__GetAudioSourceConfigurationOptions stAudioSourceCnfOptReq;
    struct _trt__GetAudioSourceConfigurationOptionsResponse stAudioSourceCnfOptResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stAudioSourceCnfOptReq, 0, sizeof(stAudioSourceCnfOptReq));
	printf("\n------------------Get Audio Source configs Options-----------------\n");

    for (i = 0; i < pReq->cnfTokenNum; i++)
    {
        stAudioSourceCnfOptReq.ProfileToken = pReq->aaPrifToken[i];
        stAudioSourceCnfOptReq.ConfigurationToken = pReq->aaCnfToken[i];
    	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    	soap_call___trt__GetAudioSourceConfigurationOptions(pSoap, pReq->acXaddr, NULL, &stAudioSourceCnfOptReq, &stAudioSourceCnfOptResp);
    	if (pSoap->error)
    	{
    		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            W_OnvifSoapDelete(pSoap);
    		return SOAP_ERR;
    	}
        
        if (NULL != stAudioSourceCnfOptResp.Options)
        {
            printf("sizeAvailable: %d\n", stAudioSourceCnfOptResp.Options->__sizeInputTokensAvailable);
            pAudioCapality->audioInNum = stAudioSourceCnfOptResp.Options->__sizeInputTokensAvailable;
            for (i = 0; i < stAudioSourceCnfOptResp.Options->__sizeInputTokensAvailable; i++)
            {
                printf("tokenAvailable: %s\n", stAudioSourceCnfOptResp.Options->InputTokensAvailable[i]);
            }
        }
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_AudioEncodeConfigsOptions(W_ONVIF_REQ_ST *pReq, W_ONVIF_AUDIO_CAPABILITY_ST *pAudioCapality)
{
	int i = 0, j = 0;
    struct soap *pSoap = NULL;
    struct _trt__GetAudioEncoderConfigurationOptions stAudioEncCnfOptReq;
    struct _trt__GetAudioEncoderConfigurationOptionsResponse stAudioEncCnfOptResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stAudioEncCnfOptReq, 0, sizeof(stAudioEncCnfOptReq));
	printf("\n------------------Get Audio Encode configs Options-----------------\n");
    
    for (i = 0; i < pReq->cnfTokenNum; i++)
    {
        stAudioEncCnfOptReq.ProfileToken = pReq->aaPrifToken[i];
        stAudioEncCnfOptReq.ConfigurationToken = pReq->aaCnfToken[i];
        printf("prifToken: %s, cnfToken: %s\n", stAudioEncCnfOptReq.ProfileToken, stAudioEncCnfOptReq.ConfigurationToken);
    	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    	soap_call___trt__GetAudioEncoderConfigurationOptions(pSoap, pReq->acXaddr, NULL, &stAudioEncCnfOptReq, &stAudioEncCnfOptResp);
    	if (pSoap->error)
    	{
    		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            W_OnvifSoapDelete(pSoap);
    		return SOAP_ERR;
    	}
        
        if (NULL != stAudioEncCnfOptResp.Options)
        {
            printf("sizeOptions: %d\n", stAudioEncCnfOptResp.Options->__sizeOptions);
            pAudioCapality->audioInEncNum = stAudioEncCnfOptResp.Options->__sizeOptions;
            for (i = 0; i < pAudioCapality->audioInEncNum; i++)
            {
                if (tt__AudioEncoding__G711 == stAudioEncCnfOptResp.Options->Options[i].Encoding)
                {
                    pAudioCapality->stAudioInEncList[i].type = 1;
                }
                else if (tt__AudioEncoding__G726 == stAudioEncCnfOptResp.Options->Options[i].Encoding)
                {
                    pAudioCapality->stAudioInEncList[i].type = 3;
                }
                else if (tt__AudioEncoding__AAC == stAudioEncCnfOptResp.Options->Options[i].Encoding)
                {
                    pAudioCapality->stAudioInEncList[i].type = 6;
                }
                
                if (NULL != stAudioEncCnfOptResp.Options->Options[i].SampleRateList)
                {
                    pAudioCapality->stAudioInEncList[i].num = stAudioEncCnfOptResp.Options->Options[i].SampleRateList->__sizeItems;
                    printf("sizeItem:%d\n", pAudioCapality->stAudioInEncList[i].num);
                    for (j = 0; j < pAudioCapality->stAudioInEncList[i].num; j++)
                    {
                        printf("%d \n", stAudioEncCnfOptResp.Options->Options[i].SampleRateList->Items[j]);
                        if (8 == stAudioEncCnfOptResp.Options->Options[i].SampleRateList->Items[j])
                        {
                            pAudioCapality->stAudioInEncList[i].sampleList[j] = 0;
                        }
                        else if (16 == stAudioEncCnfOptResp.Options->Options[i].SampleRateList->Items[j])
                        {
                            pAudioCapality->stAudioInEncList[i].sampleList[j] = 1;
                        }
                        else
                        {
                            printf("Does not support sampeValue: %d\n", stAudioEncCnfOptResp.Options->Options[i].SampleRateList->Items[j]);
                        }
                    }
                }
            }
        }
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetImageSettings(W_ONVIF_REQ_ST *pReq, W_ONVIF_IMAGE_PARAM_ST *pImageParam)
{
	int i = 0 ;
    struct soap *pSoap = NULL;
    struct _trt__GetVideoSources stVideoReq;
    struct _trt__GetVideoSourcesResponse stVideoResp;
    struct _timg__GetOptions stGetOptionsReq;
    struct _timg__GetOptionsResponse stGetOptionsResp;
    struct _timg__GetImagingSettings stImageSetReq;
    struct _timg__GetImagingSettingsResponse stImageSetResp;
    float coefBrightness = 0, coefColorSaturation = 0, coefContrast = 0, coefSharpness = 0;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stVideoReq, 0, sizeof(stVideoReq));
    printf("\n------------------Get Video Sources-----------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___trt__GetVideoSources(pSoap, pReq->acXaddr, NULL, &stVideoReq, &stVideoResp);
    if (pSoap->error)
    {
    	printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
    	return SOAP_ERR;
    }
    for (i = 0; i < stVideoResp.__sizeVideoSources; i++)
    {
        printf("token:  %s\n", stVideoResp.VideoSources[i].token);
    }
    
    memset(&stImageSetReq, 0, sizeof(stImageSetReq));
	printf("\n------------------Get Image Settings-----------------\n");
    stImageSetReq.VideoSourceToken = stVideoResp.VideoSources[0].token;
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___timg__GetImagingSettings(pSoap, pReq->acImageAddr, NULL, &stImageSetReq, &stImageSetResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

    /* get image SettingOption*/
    memset(&stGetOptionsReq, 0, sizeof(stGetOptionsReq));
    stGetOptionsReq.VideoSourceToken = stVideoResp.VideoSources[0].token;
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___timg__GetOptions(pSoap, pReq->acImageAddr, NULL, &stGetOptionsReq, &stGetOptionsResp);
    if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    coefBrightness = W_IMAGEOPTION_RANGE / (stGetOptionsResp.ImagingOptions->Brightness->Max - stGetOptionsResp.ImagingOptions->Brightness->Min);
    coefColorSaturation = W_IMAGEOPTION_RANGE / (stGetOptionsResp.ImagingOptions->ColorSaturation->Max - stGetOptionsResp.ImagingOptions->ColorSaturation->Min);
    coefContrast = W_IMAGEOPTION_RANGE / (stGetOptionsResp.ImagingOptions->Contrast->Max - stGetOptionsResp.ImagingOptions->Contrast->Min);
    coefSharpness = W_IMAGEOPTION_RANGE / (stGetOptionsResp.ImagingOptions->Sharpness->Max - stGetOptionsResp.ImagingOptions->Sharpness->Min);
    
    if (NULL != stImageSetResp.ImagingSettings)
    {
        pImageParam->brightness = (int)(*(stImageSetResp.ImagingSettings->Brightness) * coefBrightness);
        pImageParam->contrast   = (int)(*(stImageSetResp.ImagingSettings->Contrast) * coefColorSaturation);
        pImageParam->saturation = (int)(*(stImageSetResp.ImagingSettings->ColorSaturation) * coefContrast);
        pImageParam->sharpness  = (int)(*(stImageSetResp.ImagingSettings->Sharpness) * coefSharpness);
    }
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_SetImageSettings(W_ONVIF_REQ_ST *pReq, W_ONVIF_IMAGE_PARAM_ST *pImageParam)
{
	int i = 0 ;
    struct soap *pSoap = NULL;
    struct _trt__GetVideoSources stVideoReq;
    struct _trt__GetVideoSourcesResponse stVideoResp;
    struct _timg__GetOptions stGetOptionsReq;
    struct _timg__GetOptionsResponse stGetOptionsResp;
    struct _timg__GetImagingSettings stGetImageReq;
    struct _timg__GetImagingSettingsResponse stGetImageResp;
    struct _timg__SetImagingSettings stSetImageReq;
    struct _timg__SetImagingSettingsResponse stSetImageResp;
    float brightness = 0, contrast = 0, saturation = 0, sharpness = 0;
    float coefBrightness = 0, coefColorSaturation = 0, coefContrast = 0, coefSharpness = 0;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stVideoReq, 0, sizeof(stVideoReq));
    printf("\n------------------Get Video Sources-----------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___trt__GetVideoSources(pSoap, pReq->acXaddr, NULL, &stVideoReq, &stVideoResp);
    if (pSoap->error)
    {
    	printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
    	return SOAP_ERR;
    }
    for (i = 0; i < stVideoResp.__sizeVideoSources; i++)
    {
        printf("token:  %s\n", stVideoResp.VideoSources[i].token);
    }
    
    /* get image SettingOption*/
    memset(&stGetOptionsReq, 0, sizeof(stGetOptionsReq));
    stGetOptionsReq.VideoSourceToken = stVideoResp.VideoSources[0].token;
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___timg__GetOptions(pSoap, pReq->acImageAddr, NULL, &stGetOptionsReq, &stGetOptionsResp);
    if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    coefBrightness = (stGetOptionsResp.ImagingOptions->Brightness->Max - stGetOptionsResp.ImagingOptions->Brightness->Min) / W_IMAGEOPTION_RANGE;
    coefColorSaturation = (stGetOptionsResp.ImagingOptions->ColorSaturation->Max - stGetOptionsResp.ImagingOptions->ColorSaturation->Min) / W_IMAGEOPTION_RANGE;
    coefContrast = (stGetOptionsResp.ImagingOptions->Contrast->Max - stGetOptionsResp.ImagingOptions->Contrast->Min) / W_IMAGEOPTION_RANGE;
    coefSharpness = (stGetOptionsResp.ImagingOptions->Sharpness->Max - stGetOptionsResp.ImagingOptions->Sharpness->Min) / W_IMAGEOPTION_RANGE;

    brightness = pImageParam->brightness * coefBrightness;
    contrast = pImageParam->contrast * coefColorSaturation;
    saturation = pImageParam->saturation * coefContrast;
    sharpness = pImageParam->sharpness * coefSharpness;

    /* get image settings */
    memset(&stGetImageReq, 0, sizeof(stGetImageReq));
    stGetImageReq.VideoSourceToken = stVideoResp.VideoSources[0].token;
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___timg__GetImagingSettings(pSoap, pReq->acImageAddr, NULL, &stGetImageReq, &stGetImageResp);
	if (pSoap->error)
	{
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
	}
    
    printf("\n------------------Set image settings-----------------\n");
    memset(&stSetImageReq, 0, sizeof(stSetImageReq));
    stSetImageReq.VideoSourceToken = stVideoResp.VideoSources[0].token;
    stSetImageReq.ImagingSettings  = stGetImageResp.ImagingSettings;
    *(stSetImageReq.ImagingSettings->Brightness)      = brightness;
    *(stSetImageReq.ImagingSettings->Contrast)        = contrast;
    *(stSetImageReq.ImagingSettings->ColorSaturation) = saturation;
    *(stSetImageReq.ImagingSettings->Sharpness)       = sharpness;
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___timg__SetImagingSettings(pSoap, pReq->acImageAddr, NULL, &stSetImageReq, &stSetImageResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    printf("---------------Set image settings success--------------\n");

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetLiveStreamUri(W_ONVIF_REQ_ST *pReq, int streamId, char *pLiveUrl)
{
    struct soap *pSoap = NULL;
    struct _trt__GetStreamUri stStreamUriReq;
    struct _trt__GetStreamUriResponse stStreamUriResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stStreamUriReq, 0, sizeof(stStreamUriReq));
    stStreamUriReq.StreamSetup = (struct tt__StreamSetup *)soap_malloc(pSoap, sizeof(struct tt__StreamSetup));
    memset(stStreamUriReq.StreamSetup, 0, sizeof(struct tt__StreamSetup));
    stStreamUriReq.StreamSetup->Stream = 0;
    stStreamUriReq.StreamSetup->Transport = (struct tt__Transport *)soap_malloc(pSoap, sizeof(struct tt__Transport));
    stStreamUriReq.StreamSetup->Transport->Protocol = 0;
    stStreamUriReq.StreamSetup->Transport->Tunnel = 0;
    stStreamUriReq.StreamSetup->__size = 1;
    stStreamUriReq.StreamSetup->__any = NULL;
    stStreamUriReq.StreamSetup->__anyAttribute = NULL;
    stStreamUriReq.ProfileToken = pReq->aaPrifToken[streamId];

    printf("\n------------------Get live stream Uri-------------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___trt__GetStreamUri(pSoap, pReq->acXaddr, NULL, &stStreamUriReq, &stStreamUriResp);
    if (pSoap->error)
    {
        printf("soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    printf("Get RTSP Addr Done is :%s \n", stStreamUriResp.MediaUri->Uri);
    strcpy(pLiveUrl, stStreamUriResp.MediaUri->Uri);
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetSnapshotUri(W_ONVIF_REQ_ST *pReq, int streamId, char *pSnapUrl)
{
    struct soap *pSoap = NULL;
    struct _trt__GetSnapshotUri stSnapshotReq;
    struct _trt__GetSnapshotUriResponse stSnapshotResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stSnapshotReq, 0, sizeof(stSnapshotReq));
    stSnapshotReq.ProfileToken = pReq->aaPrifToken[streamId];
    printf("\n------------------Get Snapshot Uri-------------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___trt__GetSnapshotUri(pSoap, pReq->acXaddr, NULL, &stSnapshotReq, &stSnapshotResp);
    if (pSoap->error)
    {
        printf("soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }
    
    printf("Get RTSP Addr Done is :%s \n", stSnapshotResp.MediaUri->Uri);
    strcpy(pSnapUrl, stSnapshotResp.MediaUri->Uri);

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetOSDOptions(W_ONVIF_REQ_ST *pReq, W_ONVIF_OSD_CAPABILITY_ST *pOSDCapality)
{
    int i = 0;
    struct soap *pSoap = NULL;
    struct _trt__GetOSDOptions stOSDOptionReq;
    struct _trt__GetOSDOptionsResponse stOSDOptionResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}

    memset(&stOSDOptionReq, 0, sizeof(stOSDOptionReq));
    stOSDOptionReq.ConfigurationToken = pReq->aaCnfToken[0];
    printf("\n------------------Get OSD Options-------------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___trt__GetOSDOptions(pSoap, pReq->acXaddr, NULL, &stOSDOptionReq, &stOSDOptionResp);
    if (pSoap->error)
    {
        printf("soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    if (NULL != stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs)
    {
        printf("Total:     %d\n", stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs->Total);
        printf("Image:     %d\n", *(stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs->Image));
        printf("PlainText: %d\n", *(stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs->PlainText));
        printf("Date:      %d\n", *(stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs->Date));
        printf("Time:      %d\n", *(stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs->Time));
        printf("DateTime:  %d\n", *(stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs->DateAndTime));
        pOSDCapality->totalNum     = stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs->Total;
        pOSDCapality->plainTextNum = *(stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs->PlainText);
        pOSDCapality->imageNum     = *(stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs->Image);
        pOSDCapality->dateNum      = *(stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs->Date);
        pOSDCapality->timeNum      = *(stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs->Time);
        pOSDCapality->dateTimeNum  = *(stOSDOptionResp.OSDOptions->MaximumNumberOfOSDs->DateAndTime);
    }

    printf("sizePositionOption: %d\n", stOSDOptionResp.OSDOptions->__sizePositionOption);
    pOSDCapality->positionOption = stOSDOptionResp.OSDOptions->__sizePositionOption;
    for (i = 0; i < stOSDOptionResp.OSDOptions->__sizePositionOption; i++)
    {
        printf("Position[%d]: %s\n", i, stOSDOptionResp.OSDOptions->PositionOption[i]);
        strcpy(pOSDCapality->aaPosOptionList[i], stOSDOptionResp.OSDOptions->PositionOption[i]);
    }

    if (NULL != stOSDOptionResp.OSDOptions->TextOption)
    {
        printf("sizeType: %d\n", stOSDOptionResp.OSDOptions->TextOption->__sizeType);
        pOSDCapality->typeNum = stOSDOptionResp.OSDOptions->TextOption->__sizeType;
        for (i = 0; i < stOSDOptionResp.OSDOptions->TextOption->__sizeType; i++)
        {
            printf("Type[%d]: %s\n", i, stOSDOptionResp.OSDOptions->TextOption->Type[i]);
            strcpy(pOSDCapality->aaType[i], stOSDOptionResp.OSDOptions->TextOption->Type[i]);
        }
        
        printf("sizeDate: %d\n", stOSDOptionResp.OSDOptions->TextOption->__sizeDateFormat);
        pOSDCapality->dateFormatNum = stOSDOptionResp.OSDOptions->TextOption->__sizeDateFormat;
        for (i = 0; i < stOSDOptionResp.OSDOptions->TextOption->__sizeDateFormat; i++)
        {
            printf("DateFormat[%d]: %s\n", i, stOSDOptionResp.OSDOptions->TextOption->DateFormat[i]);
            strcpy(pOSDCapality->aaDateFormat[i], stOSDOptionResp.OSDOptions->TextOption->DateFormat[i]);
        }

        printf("sizeTime: %d\n", stOSDOptionResp.OSDOptions->TextOption->__sizeTimeFormat);
        pOSDCapality->timeFormatNum = stOSDOptionResp.OSDOptions->TextOption->__sizeTimeFormat;
        for (i = 0; i < stOSDOptionResp.OSDOptions->TextOption->__sizeTimeFormat; i++)
        {
            printf("TimeFormat[%d]: %s\n", i, stOSDOptionResp.OSDOptions->TextOption->TimeFormat[i]);
            strcpy(pOSDCapality->aaTimeFormat[i], stOSDOptionResp.OSDOptions->TextOption->TimeFormat[i]);
        } 
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetOSDs(W_ONVIF_REQ_ST *pReq, const char* pcEndPoint, W_ONVIF_OSD_PARAMS_ST *pOSDParams)
{
    int i = 0;
    float tmpX = 0;
    float tmpY = 0;
    float widthTmp  = 0;
    float heigthTmp = 0;
    struct soap *pSoap = NULL;
    struct _trt__GetVideoSourceConfigurations stVideoCnfReq;
    struct _trt__GetVideoSourceConfigurationsResponse stVideoCnfResp;
    struct _trt__GetOSDs stOSDsReq;
    struct _trt__GetOSDsResponse stOSDsResp;
    memset(&stOSDsResp, 0, sizeof(stOSDsResp));

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}

    memset(&stVideoCnfReq, 0, sizeof(stVideoCnfReq));
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___trt__GetVideoSourceConfigurations(pSoap, pcEndPoint, NULL, &stVideoCnfReq, &stVideoCnfResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

    memset(&stOSDsReq, 0, sizeof(stOSDsReq));
    stOSDsReq.ConfigurationToken = stVideoCnfResp.Configurations->token;
    printf("stOSDsReq.ConfigurationToken = %s\n", stOSDsReq.ConfigurationToken);

    printf("\n----------------------Get OSDs-----------------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___trt__GetOSDs(pSoap, pcEndPoint, NULL, &stOSDsReq, &stOSDsResp);
    if (pSoap->error)
    {
        printf("soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    printf("sizeOSDs: %d\n", stOSDsResp.__sizeOSDs);
    pOSDParams->OSDNum = stOSDsResp.__sizeOSDs;
    for (i = 0; i < pOSDParams->OSDNum; i++)
    {
        printf("OSD Token: %s\n", stOSDsResp.OSDs[i].token);
        printf("type: %s\n", stOSDsResp.OSDs[i].Position->Type);
        printf("PosX: %f\n", *(stOSDsResp.OSDs[i].Position->Pos->x));
        printf("PosY: %f\n", *(stOSDsResp.OSDs[i].Position->Pos->y));
        pOSDParams->astOSDParam[i].ebable = 1;
        tmpX = *(stOSDsResp.OSDs[i].Position->Pos->x);
        tmpY = *(stOSDsResp.OSDs[i].Position->Pos->y);
        if (fabs(tmpY) > 1e-6)
        {
            tmpY = -tmpY;
        }

        widthTmp  = stVideoCnfResp.Configurations->Bounds->width / 2;
        heigthTmp = stVideoCnfResp.Configurations->Bounds->height / 2;
        pOSDParams->astOSDParam[i].ebable = 1;
        pOSDParams->astOSDParam[i].positionX = (int)(tmpX * widthTmp  + widthTmp);
        pOSDParams->astOSDParam[i].positionY = (int)(tmpY * heigthTmp + heigthTmp);
        printf("positionX:%d, positionY:%d\n", pOSDParams->astOSDParam[i].positionX, pOSDParams->astOSDParam[i].positionY);

        if (tt__OSDType__Text == stOSDsResp.OSDs[i].Type)
        {
            printf("type:       %s\n", stOSDsResp.OSDs[i].TextString->Type);
            printf("PlainText:  %s\n", stOSDsResp.OSDs[i].TextString->PlainText);
            strcpy(pOSDParams->astOSDParam[i].acType,    stOSDsResp.OSDs[i].TextString->Type);
            if (NULL != stOSDsResp.OSDs[i].TextString->PlainText)
            {
                strcpy(pOSDParams->astOSDParam[i].acContent, stOSDsResp.OSDs[i].TextString->PlainText);
            }
        }
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}

//X坐标转换(1920 -> 参考宽度)
static int XConv(int nX, int nRefWidth)
{
    int nNewX = 0;
    float fX = (float)((float)nRefWidth/(float)1920);
    nNewX = (int)(fX*nX);
    return nNewX;
}

//Y坐标转换(1080 -> 参考高度)
static int YConv(int nY, int nRefHeight)
{
    int nNewY = 0;
    float fY = (float)((float)nRefHeight/(float)1080);
    nNewY = (int)(fY*nY);
    return nNewY;
}
int W_SetOSDs(W_ONVIF_REQ_ST *pReq, const char* pcEndPoint, W_ONVIF_OSD_PARAMS_ST *pOSDParams)
{
    int i = 0, j = 0;
    int findFlag = 0;
    float widthTmp = 0;
    float heigthTmp = 0;
    float tmpX = 0;
    float tmpY = 0;
    int nX = 0;
    int nY = 0;
    struct soap *pSoap = NULL;
    struct _trt__GetVideoSourceConfigurations stVideoCnfReq;
    struct _trt__GetVideoSourceConfigurationsResponse stVideoCnfResp;
    struct _trt__GetOSDs stGetOSDsReq;
    struct _trt__GetOSDsResponse stGetOSDsResp;
    struct _trt__SetOSD stOSDReq;
    struct _trt__SetOSDResponse stOSDResp;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}

    memset(&stVideoCnfReq, 0, sizeof(stVideoCnfReq));
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___trt__GetVideoSourceConfigurations(pSoap, pcEndPoint, NULL, &stVideoCnfReq, &stVideoCnfResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

    memset(&stGetOSDsReq, 0, sizeof(stGetOSDsReq));
    stGetOSDsReq.ConfigurationToken = stVideoCnfResp.Configurations->token;
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___trt__GetOSDs(pSoap, pcEndPoint, NULL, &stGetOSDsReq, &stGetOSDsResp);
    if (pSoap->error)
    {
        printf("soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    printf("\n----------------------Set OSD-----------------------\n");
    for (i = 0; i < pOSDParams->OSDNum; i++)
    {
        findFlag = 0;
        for (j = 0; j < stGetOSDsResp.__sizeOSDs; j++)
        {
            if (1 == pOSDParams->astOSDParam[i].ebable
                && 0 == strcmp(pOSDParams->astOSDParam[i].acType, stGetOSDsResp.OSDs[j].TextString->Type))
            {
                findFlag = 1;
                break;
            }
        }

        if (0 == findFlag)
        {
            continue;
        }
        memset(&stOSDReq, 0, sizeof(stOSDReq));
        stOSDReq.OSD = &(stGetOSDsResp.OSDs[j]);

        widthTmp = stVideoCnfResp.Configurations->Bounds->width / 2;
        nX = XConv(pOSDParams->astOSDParam[i].positionX, stVideoCnfResp.Configurations->Bounds->width);
        tmpX = (float)(nX - (int)widthTmp) / (float)widthTmp;
        *(stOSDReq.OSD->Position->Pos->x) = tmpX;

        heigthTmp = stVideoCnfResp.Configurations->Bounds->height / 2;
        nY = YConv(pOSDParams->astOSDParam[i].positionY, stVideoCnfResp.Configurations->Bounds->height);
        tmpY = (float)(nY - (int)heigthTmp) / (float)heigthTmp;
        if (fabs(tmpY) > 1e-6)
        {
            *(stOSDReq.OSD->Position->Pos->y) = -tmpY;
        }
        stOSDReq.OSD->TextString->PlainText = pOSDParams->astOSDParam[i].acContent;
        soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
        soap_call___trt__SetOSD(pSoap, pcEndPoint, NULL, &stOSDReq, &stOSDResp);
        if (pSoap->error)
        {
            printf("soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            W_OnvifSoapDelete(pSoap);
            return SOAP_ERR;
        }
    }
    printf("---------------------Set OSD success------------------\n");
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetPTZCapality(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_CAPABILITY_ST *pPTZCapality)
{
    int i = 0;
    int sRet = 0;
    struct soap *pSoap = NULL;
    struct _trt__GetProfiles stProfilesReq;
    struct _trt__GetProfilesResponse stProfilesResp;
    struct _tptz__GetNode stNodeReq;
    struct _tptz__GetNodeResponse stNodeResp;

	pSoap = W_OnvifSoapNew(10);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    if (strlen(pReq->acPtzXaddr) <= 0)
    {
        pPTZCapality->isSupportPTZ    = 0;
        pPTZCapality->isSupportPreset = 0;
        pPTZCapality->isSupportPatrol = 0;
    }
    else
    {
        memset(&stProfilesReq, 0, sizeof(stProfilesReq));
        printf("\n------------------Get Devices Profiles-----------------\n");
        soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
        sRet = soap_call___trt__GetProfiles(pSoap, pReq->acXaddr, NULL, &stProfilesReq, &stProfilesResp);
        if (SOAP_OK != sRet)
        {
            printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            W_OnvifSoapDelete(pSoap);
            return SOAP_ERR;
        }

        printf("sizeProfile: %d\n", stProfilesResp.__sizeProfiles);
        if (stProfilesResp.__sizeProfiles <= 0)
        {
            W_OnvifSoapDelete(pSoap);
            return SOAP_ERR;
        }
        else if (pReq->prifTokenNum <= 0)
        {
            pReq->prifTokenNum = (stProfilesResp.__sizeProfiles <= 3) ? stProfilesResp.__sizeProfiles : 3;
            for (int i = 0; i < stProfilesResp.__sizeProfiles; i++)
            {
                strcpy(pReq->aaPrifToken[i], stProfilesResp.Profiles[i].token);
            }
        }

        if (stProfilesResp.Profiles[0].PTZConfiguration)
        {
            if (!stProfilesResp.Profiles[0].PTZConfiguration->NodeToken)
            {
                W_OnvifSoapDelete(pSoap);
                return SOAP_ERR;
            }
        }
        else
        {
            W_OnvifSoapDelete(pSoap);
            return SOAP_ERR;
        }

        pPTZCapality->isSupportPTZ    = 1;
        pPTZCapality->isSupportPreset = 1;
        
        printf("\n--------------------Get Node--------------------\n");
        memset(&stNodeReq, 0, sizeof(stNodeReq));
        stNodeReq.NodeToken = stProfilesResp.Profiles[0].PTZConfiguration->NodeToken;
        printf("PTZ XAddr: %s, nodeToken: %s\n", pReq->acPtzXaddr, stNodeReq.NodeToken);
        soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
        soap_call___tptz__GetNode(pSoap, pReq->acPtzXaddr, NULL, &stNodeReq, &stNodeResp);
        if (pSoap->error)
        {
            printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            W_OnvifSoapDelete(pSoap);
            return SOAP_ERR;
        }

        if (NULL != stNodeResp.PTZNode->Extension)
        {
            if (NULL != stNodeResp.PTZNode->Extension->SupportedPresetTour)
            {
                pPTZCapality->isSupportPatrol = 1;
            }
        }

        if (stNodeResp.PTZNode->SupportedPTZSpaces)
        {
            struct tt__PTZSpaces *ptPTZSpaces = stNodeResp.PTZNode->SupportedPTZSpaces;

            /* RelativePanTiltTranslationSpace */
            for (int s32Idx = 0; s32Idx < ptPTZSpaces->__sizeRelativePanTiltTranslationSpace; s32Idx++)
            {
                /* TranslationSpaceFov */
                if (ptPTZSpaces->RelativePanTiltTranslationSpace[s32Idx].URI
                    && strstr(ptPTZSpaces->RelativePanTiltTranslationSpace[s32Idx].URI, "TranslationSpaceFov"))
                {
                    snprintf(pPTZCapality->as8TranslationTSF, sizeof(pPTZCapality->as8TranslationTSF), "%s", ptPTZSpaces->RelativePanTiltTranslationSpace[s32Idx].URI);
                }

                /* TranslationGenericSpace */
                if (ptPTZSpaces->RelativePanTiltTranslationSpace[s32Idx].URI
                    && strstr(ptPTZSpaces->RelativePanTiltTranslationSpace[s32Idx].URI, "TranslationGenericSpace"))
                {
                    snprintf(pPTZCapality->as8TranslationTGS, sizeof(pPTZCapality->as8TranslationTGS), "%s", ptPTZSpaces->RelativePanTiltTranslationSpace[s32Idx].URI);
                }
            }

            /* RelativeZoomTranslationSpace */
            for (int s32Idx = 0; s32Idx < ptPTZSpaces->__sizeRelativeZoomTranslationSpace; s32Idx++)
            {
                /* TranslationGenericSpace */
                if (ptPTZSpaces->RelativeZoomTranslationSpace[s32Idx].URI
                    && strstr(ptPTZSpaces->RelativeZoomTranslationSpace[s32Idx].URI, "TranslationGenericSpace"))
                {
                    snprintf(pPTZCapality->as8ZoomTGS, sizeof(pPTZCapality->as8ZoomTGS), "%s", ptPTZSpaces->RelativeZoomTranslationSpace[s32Idx].URI);
                }
            }

            /* PanTiltSpeedSpace */
            for (int s32Idx = 0; s32Idx < ptPTZSpaces->__sizePanTiltSpeedSpace; s32Idx++)
            {
                /* GenericSpeedSpace */
                if (ptPTZSpaces->PanTiltSpeedSpace[s32Idx].URI)
                {
                    snprintf(pPTZCapality->as8SpeedGSS, sizeof(pPTZCapality->as8SpeedGSS), "%s", ptPTZSpaces->PanTiltSpeedSpace[s32Idx].URI);
                }
            }

            /* ZoomSpeedSpace */
            for (int s32Idx = 0; s32Idx < ptPTZSpaces->__sizeZoomSpeedSpace; s32Idx++)
            {
                /* ZoomGenericSpeedSpace */
                if (ptPTZSpaces->ZoomSpeedSpace[s32Idx].URI)
                {
                    snprintf(pPTZCapality->as8SpeedZSS, sizeof(pPTZCapality->as8SpeedZSS), "%s", ptPTZSpaces->ZoomSpeedSpace[s32Idx].URI);
                }
            }
        }
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_PTZControl(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_CTRL_ST *pPTZCtrl)
{
    int sRet = 0;
    enum xsd__boolean enumBool;
    struct soap *pSoap = NULL;
    struct _trt__GetProfiles stProfilesReq;
    struct _trt__GetProfilesResponse stProfilesResp;
    struct _tptz__ContinuousMove stMoveReq;
    struct _tptz__ContinuousMoveResponse stMoveResp;
    struct _tptz__Stop stStopReq;
    struct _tptz__StopResponse stStopResp;
    
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    memset(&stProfilesReq, 0, sizeof(stProfilesReq));
    printf("\n------------------Get Devices Profiles-----------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    sRet = soap_call___trt__GetProfiles(pSoap, pReq->acXaddr, NULL, &stProfilesReq, &stProfilesResp);
    if (SOAP_OK != sRet)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    printf("sizeProfile: %d\n", stProfilesResp.__sizeProfiles);
    if (stProfilesResp.__sizeProfiles <= 0)
    {
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }
    
    if (!stProfilesResp.Profiles[0].PTZConfiguration)
    {
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }
    
    memset(&stMoveReq, 0, sizeof(stMoveReq));
    memset(&stStopReq, 0, sizeof(stStopReq));
    stMoveReq.ProfileToken = stProfilesResp.Profiles[0].token;
    stMoveReq.Velocity = (struct tt__PTZSpeed *)soap_malloc(pSoap, sizeof(struct tt__PTZSpeed));
    if (pPTZCtrl->PTZCmd <= 8)
    {
        stMoveReq.Velocity->PanTilt = (struct tt__Vector2D *)soap_malloc(pSoap, sizeof(struct tt__Vector2D));
        memset(stMoveReq.Velocity->PanTilt, 0, sizeof(struct tt__Vector2D));
        stMoveReq.Velocity->PanTilt->space = stProfilesResp.Profiles[0].PTZConfiguration->DefaultContinuousPanTiltVelocitySpace;
        printf("priToken: %s, space: %s\n", stMoveReq.ProfileToken, stMoveReq.Velocity->PanTilt->space);
    }
    else
    {
        stMoveReq.Velocity->PanTilt = (struct tt__Vector2D *)soap_malloc(pSoap, sizeof(struct tt__Vector2D));
        memset(stMoveReq.Velocity->PanTilt, 0, sizeof(struct tt__Vector2D));
        stMoveReq.Velocity->Zoom = (struct tt__Vector1D *)soap_malloc(pSoap, sizeof(struct tt__Vector1D));
        memset(stMoveReq.Velocity->Zoom, 0, sizeof(struct tt__Vector1D));
        stMoveReq.Velocity->Zoom->space = stProfilesResp.Profiles[0].PTZConfiguration->DefaultContinuousZoomVelocitySpace;
        printf("priToken: %s, space: %s\n", stMoveReq.ProfileToken, stMoveReq.Velocity->Zoom->space);
    }
    
    switch (pPTZCtrl->PTZCmd)
    {
        // 向上
        case 0:
            stMoveReq.Velocity->PanTilt->x = 0;
            stMoveReq.Velocity->PanTilt->y = (float)pPTZCtrl->verticalSpeed / 9;
            goto MOVE;
        // 向下
        case 1:
            stMoveReq.Velocity->PanTilt->x = 0;
            stMoveReq.Velocity->PanTilt->y = -((float)pPTZCtrl->verticalSpeed / 9);
            goto MOVE;
        // 向左
        case 2:
            stMoveReq.Velocity->PanTilt->x = -((float)pPTZCtrl->horizontalSpeed / 9);
            stMoveReq.Velocity->PanTilt->y = 0;
            goto MOVE;
        // 向右
        case 3:
            stMoveReq.Velocity->PanTilt->x = (float)pPTZCtrl->horizontalSpeed / 9;
            stMoveReq.Velocity->PanTilt->y = 0;
            goto MOVE;
        // 左上
        case 4:
            stMoveReq.Velocity->PanTilt->x = -((float)pPTZCtrl->horizontalSpeed / 9);
            stMoveReq.Velocity->PanTilt->y = (float)pPTZCtrl->verticalSpeed / 9;
            goto MOVE;
        // 左下
        case 5:
            stMoveReq.Velocity->PanTilt->x = -((float)pPTZCtrl->horizontalSpeed / 9);
            stMoveReq.Velocity->PanTilt->y = -((float)pPTZCtrl->verticalSpeed / 9);
        // 右上
        case 6:
            stMoveReq.Velocity->PanTilt->x = (float)pPTZCtrl->horizontalSpeed / 9;
            stMoveReq.Velocity->PanTilt->y = (float)pPTZCtrl->verticalSpeed / 9;
            goto MOVE;
        // 右下
        case 7:
            stMoveReq.Velocity->PanTilt->x = (float)pPTZCtrl->horizontalSpeed / 9;
            stMoveReq.Velocity->PanTilt->y = -((float)pPTZCtrl->verticalSpeed / 9);
            goto MOVE;
        // 停
        case 8:
            enumBool = xsd__boolean__true_;
            stStopReq.PanTilt = &enumBool;
            goto STOP;
        // 近聚焦
        case 13:
        // 放大
        case 17:
            stMoveReq.Velocity->Zoom->x = -((float)pPTZCtrl->zoomSpeed / 9);
            goto MOVE;
        // 近聚焦停止
        case 14:
        // 放大停止
        case 18:
            enumBool = xsd__boolean__true_;
            stStopReq.Zoom = &enumBool;
            goto STOP;
        // 远聚焦
        case 15:
        // 缩小
        case 19:
            stMoveReq.Velocity->Zoom->x = (float)pPTZCtrl->zoomSpeed / 9;
            goto MOVE;
        // 远聚焦停止
        case 16:
        // 缩小停止
        case 20:
            enumBool = xsd__boolean__true_;
            stStopReq.Zoom = &enumBool;
            goto STOP;
        default:
            printf("Does not support this PTZ cmd: %d\n", pPTZCtrl->PTZCmd);
            W_OnvifSoapDelete(pSoap);
            return SOAP_ERR;
    }
    
MOVE:
    printf("\n----------------------PTZ Move-----------------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tptz__ContinuousMove(pSoap, pReq->acPtzXaddr, NULL, &stMoveReq, &stMoveResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;

STOP:
    stStopReq.ProfileToken = stProfilesResp.Profiles[0].token;
    printf("\n----------------------PTZ Stop-----------------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tptz__Stop(pSoap, pReq->acPtzXaddr, NULL, &stStopReq, &stStopResp);
    if (pSoap->error)
    {
        printf("soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetPresets(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_PRESETS_ST *pPresets)
{
    int i = 0;
    struct soap *pSoap = NULL;
    struct _tptz__GetPresets stPresetsReq;
    struct _tptz__GetPresetsResponse stPresetsResp;
    
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    printf("\n----------------------Get presets-----------------------\n");
    memset(&stPresetsReq, 0, sizeof(stPresetsReq));
    stPresetsReq.ProfileToken = pReq->aaPrifToken[0];
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tptz__GetPresets(pSoap, pReq->acPtzXaddr, NULL, &stPresetsReq, &stPresetsResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

    pPresets->presetNum = stPresetsResp.__sizePreset;
    printf("Get presetNum: %d\n", pPresets->presetNum); 
    pPresets->pstPtzPreset = (W_PTZ_PRESET_ST *)malloc(sizeof(W_PTZ_PRESET_ST) * pPresets->presetNum);
    for (i = 0; i < pPresets->presetNum; i++)
    {
        pPresets->pstPtzPreset[i].preId = atoi(stPresetsResp.Preset[i].token);
        strcpy(pPresets->pstPtzPreset[i].acPreName, stPresetsResp.Preset[i].Name);
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_SetPreset(W_ONVIF_REQ_ST *pReq, W_PTZ_PRESET_ST *pPreset)
{
    char acBuff[8] = {0};
    struct soap *pSoap = NULL;
    struct _tptz__SetPreset stSetPresetReq;
    struct _tptz__SetPresetResponse stSetPresetResp;
    W_ONVIF_PTZ_PRESETS_ST stPresets;
    int i = 0;
    int bPresetExist = 0;

    pSoap = W_OnvifSoapNew(5);
    if (NULL == pSoap)
    {
    	return SOAP_ERR;
    }

    printf("\n----------------------Set preset-----------------------\n");
    memset(&stSetPresetReq, 0, sizeof(stSetPresetReq));
    stSetPresetReq.ProfileToken = pReq->aaPrifToken[0];
    stSetPresetReq.PresetName   = pPreset->acPreName;
    sprintf(acBuff, "%d", pPreset->preId);
    stSetPresetReq.PresetToken  = acBuff;
    printf("preName:%s, token:%s\n", stSetPresetReq.PresetName, stSetPresetReq.PresetToken);
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tptz__SetPreset(pSoap, pReq->acPtzXaddr, NULL, &stSetPresetReq, &stSetPresetResp);
    if (pSoap->error) {
        /* 查询是否存在预置位 */
        memset(&stPresets, 0, sizeof(stPresets));
        if (SOAP_OK == W_GetPresets(pReq, &stPresets))
        {
            for (i = 0; i < stPresets.presetNum; i++) {
                if (stPresets.pstPtzPreset[i].preId == pPreset->preId) {
                    bPresetExist = 1;
                    break;
                }
            }
        }
        if (!bPresetExist) {
            stSetPresetReq.PresetToken = NULL;
            soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
            soap_call___tptz__SetPreset(pSoap, pReq->acPtzXaddr, NULL, &stSetPresetReq, &stSetPresetResp);
        }
    }
    if (pSoap->error)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_DelPreset(W_ONVIF_REQ_ST *pReq, W_PTZ_PRESET_ST *pPreset)
{
    char acBuff[8] = {0};
    struct soap *pSoap = NULL;
    struct _tptz__RemovePreset stRemPresetReq;
    struct _tptz__RemovePresetResponse stRemPresetResp;

    pSoap = W_OnvifSoapNew(5);
    if (NULL == pSoap)
    {
    	return SOAP_ERR;
    }

    printf("\n----------------------Delete preset-----------------------\n");
    memset(&stRemPresetReq, 0, sizeof(stRemPresetReq));
    stRemPresetReq.ProfileToken = pReq->aaPrifToken[0];
    sprintf(acBuff, "%d", pPreset->preId);
    stRemPresetReq.PresetToken  = acBuff;
    printf("preToken:%s\n", stRemPresetReq.PresetToken);
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tptz__RemovePreset(pSoap, pReq->acPtzXaddr, NULL, &stRemPresetReq, &stRemPresetResp);
    if (pSoap->error)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        /* keda preset does not exist del error ignore */
        //W_OnvifSoapDelete(pSoap);
        //return SOAP_ERR;
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GotoPreset(W_ONVIF_REQ_ST *pReq, W_PTZ_PRESET_ST *pPreset)
{
    char acBuff[8] = {0};
    struct soap *pSoap = NULL;
    struct _tptz__GotoPreset stGotoPresetReq;
    struct _tptz__GotoPresetResponse stGotoPresetResp;

    pSoap = W_OnvifSoapNew(5);
    if (NULL == pSoap)
    {
    	return SOAP_ERR;
    }

    printf("\n----------------------Goto preset-----------------------\n");
    memset(&stGotoPresetReq, 0, sizeof(stGotoPresetReq));
    stGotoPresetReq.ProfileToken = pReq->aaPrifToken[0];
    sprintf(acBuff, "%d", pPreset->preId);
    stGotoPresetReq.PresetToken  = acBuff;
    printf("preToken:%s\n", stGotoPresetReq.PresetToken);
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tptz__GotoPreset(pSoap, pReq->acPtzXaddr, NULL, &stGotoPresetReq, &stGotoPresetResp);
    if (pSoap->error)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetPatrols(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_PATROLS_ST *pPatrols)
{
    int i = 0, j = 0;
    int duration = 0;
    struct soap *pSoap = NULL;
    struct _tptz__GetPresetTours stToursReq;
    struct _tptz__GetPresetToursResponse stToursResp;
    
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    printf("\n----------------------Get patrols-----------------------\n");
    memset(&stToursReq, 0, sizeof(stToursReq));
    stToursReq.ProfileToken = pReq->aaPrifToken[0];
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tptz__GetPresetTours(pSoap, pReq->acPtzXaddr, NULL, &stToursReq, &stToursResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

    pPatrols->patrolNum = (stToursResp.__sizePresetTour <= W_MAX_PTZ_PATROL_NUM) ? stToursResp.__sizePresetTour : W_MAX_PTZ_PATROL_NUM;
    printf("Get patrolNum: %d\n", pPatrols->patrolNum);
    for (i = 0; i < pPatrols->patrolNum; i++)
    {
        pPatrols->astPtzPatrol[i].Id = i + 1;
        strcpy(pPatrols->astPtzPatrol[i].acName, stToursResp.PresetTour[i].token);
        pPatrols->astPtzPatrol[i].itemNum = stToursResp.PresetTour[i].__sizeTourSpot;
        pPatrols->astPtzPatrol[i].pstPatrolItem = 
            (W_PATROL_ITEM_ST *)malloc(sizeof(W_PATROL_ITEM_ST) * pPatrols->astPtzPatrol[i].itemNum);
        for (j = 0; j < pPatrols->astPtzPatrol[i].itemNum; j++)
        {
            pPatrols->astPtzPatrol[i].pstPatrolItem[j].presetId = 
                atoi(stToursResp.PresetTour[i].TourSpot[j].PresetDetail->union_PTZPresetTourPresetDetail.PresetToken);

            pPatrols->astPtzPatrol[i].pstPatrolItem[j].duration = 120;
            if (stToursResp.PresetTour[i].TourSpot[j].StayTime) {
                sscanf(stToursResp.PresetTour[i].TourSpot[j].StayTime, "PT%dS", &duration);
                pPatrols->astPtzPatrol[i].pstPatrolItem[j].duration = duration;
            }
        }
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


static int W_ModifyPatrol(W_ONVIF_REQ_ST *pReq, W_PTZ_PATROL_ST *pPatrol)
{
    int i = 0;
    struct soap *pSoap = NULL;
    struct _tptz__ModifyPresetTour stTourReq;
    struct _tptz__ModifyPresetTourResponse stTourResp;
    char *pcName = NULL;
    
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}

    /* 缺少name, 根据id找到name */
    pcName = pPatrol->acName;
    if (strlen(pPatrol->acName) == 0) {
        struct _tptz__GetPresetTours stToursReq;
        struct _tptz__GetPresetToursResponse stToursResp;
        memset(&stToursReq, 0, sizeof(stToursReq));
        stToursReq.ProfileToken = pReq->aaPrifToken[0];
        soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
        soap_call___tptz__GetPresetTours(pSoap, pReq->acPtzXaddr, NULL, &stToursReq, &stToursResp);
        if (pSoap->error)
        {
            printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            W_OnvifSoapDelete(pSoap);
            return SOAP_ERR;
        }

        for (i = 0; i < stToursResp.__sizePresetTour; i++)
        {
            if (pPatrol->Id == i + 1)
            {
                printf("tourId: %d, tourToken: %s\n", pPatrol->Id, stToursResp.PresetTour[i].token);
                pcName = stToursResp.PresetTour[i].token;
                break;
            }
        }
    }

    memset(&stTourReq, 0, sizeof(stTourReq));
    stTourReq.ProfileToken = pReq->aaPrifToken[0];
    
    stTourReq.PresetTour = (struct tt__PresetTour *)soap_malloc(pSoap, sizeof(struct tt__PresetTour));
    memset(stTourReq.PresetTour, 0, sizeof(struct tt__PresetTour));
    stTourReq.PresetTour->Name = pcName;
    stTourReq.PresetTour->AutoStart = xsd__boolean__false_;
    stTourReq.PresetTour->token = pcName;
    
    stTourReq.PresetTour->__sizeTourSpot = pPatrol->itemNum;
    stTourReq.PresetTour->TourSpot = (struct tt__PTZPresetTourSpot *)
        soap_malloc(pSoap, sizeof(struct tt__PTZPresetTourSpot) * stTourReq.PresetTour->__sizeTourSpot);
    memset(stTourReq.PresetTour->TourSpot, 0, sizeof(struct tt__PTZPresetTourSpot) * stTourReq.PresetTour->__sizeTourSpot);
    for (i = 0; i < stTourReq.PresetTour->__sizeTourSpot; i++)
    {
        stTourReq.PresetTour->TourSpot[i].PresetDetail = (struct tt__PTZPresetTourPresetDetail *)soap_malloc(pSoap, sizeof(struct tt__PTZPresetTourPresetDetail));
        memset(stTourReq.PresetTour->TourSpot[i].PresetDetail, 0, sizeof(struct tt__PTZPresetTourPresetDetail));
        stTourReq.PresetTour->TourSpot[i].PresetDetail->__union_PTZPresetTourPresetDetail = 1;
        stTourReq.PresetTour->TourSpot[i].PresetDetail->union_PTZPresetTourPresetDetail.PresetToken = (char *)soap_malloc(pSoap, 16);
        memset(stTourReq.PresetTour->TourSpot[i].PresetDetail->union_PTZPresetTourPresetDetail.PresetToken, 0, 16);
        sprintf(stTourReq.PresetTour->TourSpot[i].PresetDetail->union_PTZPresetTourPresetDetail.PresetToken, "%d", pPatrol->pstPatrolItem[i].presetId);
        stTourReq.PresetTour->TourSpot[i].StayTime = (char *)soap_malloc(pSoap, 16);
        memset(stTourReq.PresetTour->TourSpot[i].StayTime, 0, 16);
        sprintf(stTourReq.PresetTour->TourSpot[i].StayTime, "PT%dS", pPatrol->pstPatrolItem[i].duration);
    }
    
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tptz__ModifyPresetTour(pSoap, pReq->acPtzXaddr, NULL, &stTourReq, &stTourResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_ModifyPatrols(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_PATROLS_ST *pPatrols)
{
    int i = 0;
    
    printf("\n----------------------Set patrols-----------------------\n");
    for (i = 0; i < pPatrols->patrolNum; i++)
    {
        if (SOAP_OK != W_ModifyPatrol(pReq, &(pPatrols->astPtzPatrol[i])))
        {
            printf("Set patrol name: %s failed.\n", pPatrols->astPtzPatrol[i].acName);
            return SOAP_ERR;
        }
        printf("Set patrol name: %s success.\n", pPatrols->astPtzPatrol[i].acName);
    }
    
    return SOAP_OK;
}


static int W_CreatePatrol(W_ONVIF_REQ_ST *pReq, char *pNewToken)
{
    int i = 0;
    struct soap *pSoap = NULL;
    struct _tptz__CreatePresetTour stNewTourReq;
    struct _tptz__CreatePresetTourResponse stNewTourResp;

    pSoap = W_OnvifSoapNew(5);
    if (NULL == pSoap)
    {
    	return SOAP_ERR;
    }

    memset(&stNewTourReq, 0, sizeof(stNewTourReq));
    stNewTourReq.ProfileToken = pReq->aaPrifToken[0];

    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tptz__CreatePresetTour(pSoap, pReq->acPtzXaddr, NULL, &stNewTourReq, &stNewTourResp);
    if (pSoap->error)
    {
    	printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
    	return SOAP_ERR;
    }
    printf("Create presetTourToken: %s\n", stNewTourResp.PresetTourToken);
    strcpy(pNewToken, stNewTourResp.PresetTourToken);
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_CreatePatrols(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_PATROLS_ST *pPatrols)
{
    int i = 0;
    char acToken[64] = {0};
    
    printf("\n----------------------Create patrols-----------------------\n");
    for (i = 0; i < pPatrols->patrolNum; i++)
    {
        if (SOAP_OK != W_CreatePatrol(pReq, acToken))
        {
            printf("Create new patrol failed.\n");
            return SOAP_ERR;
        }
        printf("Create new patrol success.\n");
        
        memset(pPatrols->astPtzPatrol[i].acName, 0, sizeof(pPatrols->astPtzPatrol[i].acName));
        strcpy(pPatrols->astPtzPatrol[i].acName, acToken);
        if (SOAP_OK != W_ModifyPatrol(pReq, &(pPatrols->astPtzPatrol[i])))
        {
            printf("Add config to patrolName:%s failed.\n", pPatrols->astPtzPatrol[i].acName);
            return SOAP_ERR;
        }
        printf("Add config to patrolName:%s success.\n", pPatrols->astPtzPatrol[i].acName);
    }
    
    return SOAP_OK;
}


static int W_DeletePatrol(W_ONVIF_REQ_ST *pReq, W_PTZ_PATROL_ST *pPatrol)
{
    int i = 0;
    struct soap *pSoap = NULL;
    struct _tptz__RemovePresetTour stDelTourReq;
    struct _tptz__RemovePresetTourResponse stDelTourResp;

    pSoap = W_OnvifSoapNew(5);
    if (NULL == pSoap)
    {
    	return SOAP_ERR;
    }

    memset(&stDelTourReq, 0, sizeof(stDelTourReq));
    stDelTourReq.ProfileToken    = pReq->aaPrifToken[0];
    stDelTourReq.PresetTourToken = pPatrol->acName;
    printf("priToken:%s, tourToken:%s\n", stDelTourReq.ProfileToken, stDelTourReq.PresetTourToken);
    
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tptz__RemovePresetTour(pSoap, pReq->acPtzXaddr, NULL, &stDelTourReq, &stDelTourResp);
    if (pSoap->error)
    {
    	printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
    	return SOAP_ERR;
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_DeletePatrols(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_PATROLS_ST *pPatrols)
{
    int i = 0;
    
    printf("\n----------------------Delete patrols-----------------------\n");
    for (i = 0; i < pPatrols->patrolNum; i++)
    {
        if (SOAP_OK != W_DeletePatrol(pReq, &(pPatrols->astPtzPatrol[i])))
        {
            printf("Delete patrol name: %s failed.\n", pPatrols->astPtzPatrol[i].acName);
            return SOAP_ERR;
        }
        printf("Delete patrol name: %s success.\n", pPatrols->astPtzPatrol[i].acName);
    }
    
    return SOAP_OK;
}


int W_OperatePatrol(W_ONVIF_REQ_ST *pReq, int patrolId, int operateType)
{
    int i = 0;
    int findPatrolId = 0;
    struct soap *pSoap = NULL;
    struct _tptz__GetPresetTours stToursReq;
    struct _tptz__GetPresetToursResponse stToursResp;
    struct _tptz__OperatePresetTour stOperateReq;
    struct _tptz__OperatePresetTourResponse stOperateResp;
        
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    printf("\n----------------------Get patrols-----------------------\n");
    memset(&stToursReq, 0, sizeof(stToursReq));
    stToursReq.ProfileToken = pReq->aaPrifToken[0];
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tptz__GetPresetTours(pSoap, pReq->acPtzXaddr, NULL, &stToursReq, &stToursResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

    printf("stToursResp.__sizePresetTour = %d\n", stToursResp.__sizePresetTour);
#if 1
    for (i = 0; i < stToursResp.__sizePresetTour; i++)
    {
        if (patrolId == i + 1)
        {
            printf("tourId: %d, tourToken: %s\n", patrolId, stToursResp.PresetTour[i].token);
            findPatrolId = 1;
            break;
        }
    }
#else
    if (stToursResp.__sizePresetTour > patrolId) {
        i = patrolId;
        findPatrolId = 1;
    }
#endif
    if (0 == findPatrolId)
    {
        printf("Does not found the patrolId: %d\n", patrolId);
        W_OnvifSoapDelete(pSoap);
        return SOAP_OK;
    }
    
    printf("\n----------------------Operate patrol-----------------------\n");
    memset(&stOperateReq, 0, sizeof(stOperateReq));
    stOperateReq.ProfileToken    = pReq->aaPrifToken[0];
    stOperateReq.PresetTourToken = stToursResp.PresetTour[i].token;
    if (0 == operateType)
    {
        stOperateReq.Operation   = tt__PTZPresetTourOperation__Stop;
    }
    else if (1 == operateType)
    {
        stOperateReq.Operation   = tt__PTZPresetTourOperation__Start;
    }
    printf("Operate patrolId:%d, patrolToken:%s, operateType:%d\n", patrolId, stOperateReq.PresetTourToken, operateType);
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tptz__OperatePresetTour(pSoap, pReq->acPtzXaddr, NULL, &stOperateReq, &stOperateResp);
    if (pSoap->error)
    {
    	printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
    	return SOAP_ERR;
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}

int W_PTZRelativeMove(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZRelativeMove_ST *ptRelativeMoveParam, W_ONVIF_PTZ_CAPABILITY_ST *ptPTZCapality)
{
    struct soap *pSoap = NULL;
    struct _tptz__RelativeMove tRelativeMoveReq = {0};
    struct _tptz__RelativeMoveResponse tRelativeMoveResp = {0};

    pSoap = W_OnvifSoapNew(5);
    if (NULL == pSoap)
    {
    	return SOAP_ERR;
    }

    printf("\n----------------------PTZ RelativeMove-----------------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    tRelativeMoveReq.ProfileToken = pReq->aaPrifToken[0];

    tRelativeMoveReq.Translation = (struct tt__PTZVector *)soap_malloc(pSoap, sizeof(struct tt__PTZVector));
    memset(tRelativeMoveReq.Translation, 0, sizeof(struct tt__PTZVector));
    struct tt__PTZVector *ptTranslation = tRelativeMoveReq.Translation;

    if (1 == ptRelativeMoveParam->stTranslation.s32HasPT)
    {
        ptTranslation->PanTilt = (struct tt__Vector2D *)soap_malloc(pSoap, sizeof(struct tt__Vector2D));
        memset(ptTranslation->PanTilt, 0, sizeof(struct tt__Vector2D));
        ptTranslation->PanTilt->x = ptRelativeMoveParam->stTranslation.stPanTilt.x;
        ptTranslation->PanTilt->y = ptRelativeMoveParam->stTranslation.stPanTilt.y;

        if (strlen(ptPTZCapality->as8TranslationTSF) > 0)
        {
            ptTranslation->PanTilt->space = ptPTZCapality->as8TranslationTSF;
        }
    }

    if (1 == ptRelativeMoveParam->stTranslation.s32HasZoom)
    {
        ptTranslation->Zoom = (struct tt__Vector1D *)soap_malloc(pSoap, sizeof(struct tt__Vector1D));
        memset(ptTranslation->Zoom, 0, sizeof(struct tt__Vector1D));
        ptTranslation->Zoom->x = ptRelativeMoveParam->stTranslation.stZoom.x;

        if (strlen(ptPTZCapality->as8ZoomTGS) > 0)
        {
            ptTranslation->Zoom->space = ptPTZCapality->as8ZoomTGS;
        }
    }

    if (1 == ptRelativeMoveParam->s32HasSpeed)
    {
        tRelativeMoveReq.Speed = (struct tt__PTZSpeed *)soap_malloc(pSoap, sizeof(struct tt__PTZSpeed));
        memset(tRelativeMoveReq.Speed, 0, sizeof(struct tt__PTZSpeed));
        struct tt__PTZSpeed *ptSpeed = tRelativeMoveReq.Speed;

        if (1 == ptRelativeMoveParam->stSpeed.s32HasPT)
        {
            ptSpeed->PanTilt = (struct tt__Vector2D *)soap_malloc(pSoap, sizeof(struct tt__Vector2D));
            memset(ptSpeed->PanTilt, 0, sizeof(struct tt__Vector2D));
            ptSpeed->PanTilt->x = ptRelativeMoveParam->stSpeed.stPanTilt.x;
            ptSpeed->PanTilt->y = ptRelativeMoveParam->stSpeed.stPanTilt.y;

            if (strlen(ptPTZCapality->as8SpeedGSS) > 0)
            {
                ptSpeed->PanTilt->space = ptPTZCapality->as8SpeedGSS;
            }
        }

        if (1 == ptRelativeMoveParam->stSpeed.s32HasZoom)
        {
            ptSpeed->Zoom = (struct tt__Vector1D *)soap_malloc(pSoap, sizeof(struct tt__Vector1D));
            memset(ptSpeed->Zoom, 0, sizeof(struct tt__Vector1D));
            ptSpeed->Zoom->x = ptRelativeMoveParam->stSpeed.stZoom.x;

            if (strlen(ptPTZCapality->as8SpeedZSS) > 0)
            {
                ptSpeed->Zoom->space = ptPTZCapality->as8SpeedZSS;
            }
        }
    }

    if (SOAP_OK != soap_call___tptz__RelativeMove(pSoap, pReq->acPtzXaddr, NULL, &tRelativeMoveReq, &tRelativeMoveResp))
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        pSoap = NULL;
        return SOAP_ERR;
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetMotionDetect(W_ONVIF_REQ_ST *pReq, W_ONVIF_ALARM_MD_ST *pAlarmMD)
{
    int i = 0, j = 0;
    struct soap *pSoap = NULL;
    struct _tan__GetRules stRulesReq;
    struct _tan__GetRulesResponse stRulesResp;
    struct _tan__GetAnalyticsModules stModulesReq;
    struct _tan__GetAnalyticsModulesResponse stModulesResp;
    struct _trt__GetVideoAnalyticsConfigurations stVideoAnalyticsCnfReq;
    struct _trt__GetVideoAnalyticsConfigurationsResponse stVideoAnalyticsCnfResp;
    char *pcAnalyticsToken = NULL;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}

    if (pReq->analyticsTokenNum <= 0) {
        memset(&stVideoAnalyticsCnfReq, 0, sizeof(stVideoAnalyticsCnfReq));
        soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
        soap_call___trt__GetVideoAnalyticsConfigurations(pSoap, pReq->acAnalytics, NULL, &stVideoAnalyticsCnfReq, &stVideoAnalyticsCnfResp);
        if (pSoap->error)
        {
            printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            W_OnvifSoapDelete(pSoap);
            return SOAP_ERR;
        }
        pcAnalyticsToken = stVideoAnalyticsCnfResp.Configurations->token;
    } else {
        pcAnalyticsToken = pReq->aaAnalyticsToken[0];
    }

    memset(&stRulesReq, 0, sizeof(stRulesReq));
	printf("\n------------------Get Analytics Rules-----------------\n");
    stRulesReq.ConfigurationToken = pcAnalyticsToken;
    printf("stRulesReq.ConfigurationToken = %s\n", stRulesReq.ConfigurationToken);
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tan__GetRules(pSoap, pReq->acAnalytics, NULL, &stRulesReq, &stRulesResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

	for (i= 0; i < stRulesResp.__sizeRule; i++)
	{
        if (0 == strcmp(stRulesResp.Rule[i].Name, "MyMotionDetectorRule") ||
            0 == strcmp(stRulesResp.Rule[i].Name, "Region1"))
        {
            if (NULL != stRulesResp.Rule[i].Parameters)
            {
                for (j = 0; j < stRulesResp.Rule[i].Parameters->__sizeSimpleItem; j++)
                {
                    if (0 == strcmp(stRulesResp.Rule[i].Parameters->SimpleItem[j].Name, "ActiveCells"))
                    {
                        strcpy(pAlarmMD->acGrid, stRulesResp.Rule[i].Parameters->SimpleItem[j].Value);
                    }
                }
            }
            break;
        }
	}
    
    memset(&stModulesReq, 0, sizeof(stModulesReq));
	printf("\n------------------Get Analytics Modules-----------------\n");
    stModulesReq.ConfigurationToken = pcAnalyticsToken;
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tan__GetAnalyticsModules(pSoap, pReq->acAnalytics, NULL, &stModulesReq, &stModulesResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}

	for (i= 0; i < stModulesResp.__sizeAnalyticsModule; i++)
	{
        if (0 == strcmp(stModulesResp.AnalyticsModule[i].Name, "MyCellMotionModule") ||
            0 == strcmp(stModulesResp.AnalyticsModule[i].Name, "MyCellMotion") ||
            0 == strcmp(stModulesResp.AnalyticsModule[i].Name, "MyCellMotionEngine"))
        {
            if (NULL != stModulesResp.AnalyticsModule[i].Parameters)
            {
                for (j = 0; j < stModulesResp.AnalyticsModule[i].Parameters->__sizeSimpleItem; j++)
                {
                    if (0 == strcmp(stModulesResp.AnalyticsModule[i].Parameters->SimpleItem[j].Name, "Sensitivity"))
                    {
                        pAlarmMD->sensitivity = atoi(stModulesResp.AnalyticsModule[i].Parameters->SimpleItem[j].Value);
                        if (0 == pAlarmMD->sensitivity)
                        {
                            pAlarmMD->enable = 0;
                        }
                        else
                        {
                            pAlarmMD->enable = 1;
                        }
                    }
                }
            }
            break;
        }
	}
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_SetMotionDetect(W_ONVIF_REQ_ST *pReq, W_ONVIF_ALARM_MD_ST *pAlarmMD)
{
    int i = 0, j = 0;
    struct soap *pSoap = NULL;
    struct _tan__GetRules stRulesReq;
    struct _tan__GetRulesResponse stRulesResp;
    struct _tan__ModifyRules stModifyRulesReq;
    struct _tan__ModifyRulesResponse stModifyRulesResp;
    struct _tan__GetAnalyticsModules stModulesReq;
    struct _tan__GetAnalyticsModulesResponse stModulesResp;
    struct _tan__ModifyAnalyticsModules stModifyModulesReq;
    struct _tan__ModifyAnalyticsModulesResponse stModifyModulesResp;
    struct _trt__GetVideoAnalyticsConfigurations stVideoAnalyticsCnfReq;
    struct _trt__GetVideoAnalyticsConfigurationsResponse stVideoAnalyticsCnfResp;
    char *pcAnalyticsToken = NULL;

	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}

    if (pReq->analyticsTokenNum <= 0) {
        memset(&stVideoAnalyticsCnfReq, 0, sizeof(stVideoAnalyticsCnfReq));
        soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
        soap_call___trt__GetVideoAnalyticsConfigurations(pSoap, pReq->acAnalytics, NULL, &stVideoAnalyticsCnfReq, &stVideoAnalyticsCnfResp);
        if (pSoap->error)
        {
            printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            W_OnvifSoapDelete(pSoap);
            return SOAP_ERR;
        }
        pcAnalyticsToken = stVideoAnalyticsCnfResp.Configurations->token;
    } else {
        pcAnalyticsToken = pReq->aaAnalyticsToken[0];
    }
    
    memset(&stRulesReq, 0, sizeof(stRulesReq));
	printf("\n------------------Get Analytics Rules-----------------\n");
    stRulesReq.ConfigurationToken = pcAnalyticsToken;
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tan__GetRules(pSoap, pReq->acAnalytics, NULL, &stRulesReq, &stRulesResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    
    memset(&stModifyRulesReq, 0, sizeof(stModifyRulesReq));
    printf("\n------------------Modify Analytics Rules-----------------\n");
    stModifyRulesReq.ConfigurationToken = pcAnalyticsToken;
    stModifyRulesReq.__sizeRule = stRulesResp.__sizeRule;
    stModifyRulesReq.Rule = stRulesResp.Rule;
	for (i= 0; i < stModifyRulesReq.__sizeRule; i++)
	{
        if (0 == strcmp(stModifyRulesReq.Rule[i].Name, "MyMotionDetectorRule"))
        {
            if (NULL != stModifyRulesReq.Rule[i].Parameters)
            {
                for (j = 0; j < stModifyRulesReq.Rule[i].Parameters->__sizeSimpleItem; j++)
                {
                    if (0 == strcmp(stModifyRulesReq.Rule[i].Parameters->SimpleItem[j].Name, "ActiveCells"))
                    {
                        stModifyRulesReq.Rule[i].Parameters->SimpleItem[j].Value = soap_malloc(pSoap, strlen(pAlarmMD->acGrid) + 1);
                        memset(stModifyRulesReq.Rule[i].Parameters->SimpleItem[j].Value, 0, strlen(pAlarmMD->acGrid) + 1);
                        strcpy(stModifyRulesReq.Rule[i].Parameters->SimpleItem[j].Value, pAlarmMD->acGrid);
                    }
                }
            }
            break;
        }
	}
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tan__ModifyRules(pSoap, pReq->acAnalytics, NULL, &stModifyRulesReq, &stModifyRulesResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        //W_OnvifSoapDelete(pSoap);
        //return SOAP_ERR;
	}
    
    memset(&stModulesReq, 0, sizeof(stModulesReq));
	printf("\n------------------Get Analytics Modules-----------------\n");
    stModulesReq.ConfigurationToken = pcAnalyticsToken;
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tan__GetAnalyticsModules(pSoap, pReq->acAnalytics, NULL, &stModulesReq, &stModulesResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
		return SOAP_ERR;
	}
    
    memset(&stModifyModulesReq, 0, sizeof(stModifyModulesReq));
	printf("\n------------------Modify Analytics Modules-----------------\n");
    stModifyModulesReq.ConfigurationToken = pcAnalyticsToken;
    stModifyModulesReq.__sizeAnalyticsModule = stModulesResp.__sizeAnalyticsModule;
    stModifyModulesReq.AnalyticsModule = stModulesResp.AnalyticsModule;
    
	for (i= 0; i < stModifyModulesReq.__sizeAnalyticsModule; i++)
	{
        if (0 == strcmp(stModifyModulesReq.AnalyticsModule[i].Name, "MyCellMotionModule") ||
            0 == strcmp(stModifyModulesReq.AnalyticsModule[i].Name, "MyCellMotion"))
        {
            if (NULL != stModifyModulesReq.AnalyticsModule[i].Parameters)
            {
                for (j = 0; j < stModifyModulesReq.AnalyticsModule[i].Parameters->__sizeSimpleItem; j++)
                {
                    if (0 == strcmp(stModifyModulesReq.AnalyticsModule[i].Parameters->SimpleItem[j].Name, "Sensitivity"))
                    {
                        if (0 == pAlarmMD->enable)
                        {
                            sprintf(stModifyModulesReq.AnalyticsModule[i].Parameters->SimpleItem[j].Value, "%d", 0);
                        }
                        else
                        {
                            sprintf(stModifyModulesReq.AnalyticsModule[i].Parameters->SimpleItem[j].Value, "%d", pAlarmMD->sensitivity);
                        }
                    }
                }
            }
            break;
        }
	}
	soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
	soap_call___tan__ModifyAnalyticsModules(pSoap, pReq->acAnalytics, NULL, &stModifyModulesReq, &stModifyModulesResp);
	if (pSoap->error)
	{
		printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        //W_OnvifSoapDelete(pSoap);
        //return SOAP_ERR;
	}
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_GetRelayOutput(W_ONVIF_REQ_ST *pReq, W_ONVIF_ALARM_IO_ST *ptAlarmIO)
{
    int sRet = 0, s32Flag = 0;
    struct soap *pSoap = NULL;
    struct _tds__GetRelayOutputs tGetRelayOutputsReq;
    struct _tds__GetRelayOutputsResponse tGetRelayOutputsResp;

    pSoap = W_OnvifSoapNew(5);
    if(NULL == pSoap)
    {
        return SOAP_ERR;
    }

    memset(&tGetRelayOutputsReq, 0, sizeof(tGetRelayOutputsReq));
    
    printf("\n------------------Get GetRelayOutputs-----------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    sRet = soap_call___tmd__GetRelayOutputs(pSoap, pReq->acDeviceIO, NULL, &tGetRelayOutputsReq, &tGetRelayOutputsResp);
    if(SOAP_OK != sRet)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    printf("IOInputIndex: %d, sizeRelayOutputs: %d\n", ptAlarmIO->IOInputIndex, tGetRelayOutputsResp.__sizeRelayOutputs);
    if(ptAlarmIO->IOInputIndex < tGetRelayOutputsResp.__sizeRelayOutputs)
    {
        int s32Idx = ptAlarmIO->IOInputIndex;
        if(tGetRelayOutputsResp.RelayOutputs[s32Idx].Properties)
        {           
            printf("RelayMode:%d\n", tGetRelayOutputsResp.RelayOutputs[s32Idx].Properties->Mode);
            ptAlarmIO->relayMode = tGetRelayOutputsResp.RelayOutputs[s32Idx].Properties->Mode;
            
            printf("DelayTime:%s\n", tGetRelayOutputsResp.RelayOutputs[s32Idx].Properties->DelayTime);
            sscanf(tGetRelayOutputsResp.RelayOutputs[s32Idx].Properties->DelayTime, "PT%dS", &ptAlarmIO->delayTime);

            printf("IdleState:%d\n", tGetRelayOutputsResp.RelayOutputs[s32Idx].Properties->IdleState);
            ptAlarmIO->idleState = tGetRelayOutputsResp.RelayOutputs[s32Idx].Properties->IdleState;
            s32Flag = 1;
        }
    }

    if(0 == s32Flag)
    {
        printf("Get[%d] GetRelayOutputs Failed !!!\n", ptAlarmIO->IOInputIndex);
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}

int W_SetRelayOutput(W_ONVIF_REQ_ST *pReq, W_ONVIF_ALARM_IO_ST *ptAlarmIO)
{
    int sRet = 0;
    struct soap *pSoap = NULL;
    struct _tds__SetRelayOutputSettings tSetRelayOutputSettingsReq;
    struct _tds__SetRelayOutputSettingsResponse tSetRelayOutputSettingsResp;
    struct _tds__GetRelayOutputs tGetRelayOutputsReq;
    struct _tds__GetRelayOutputsResponse tGetRelayOutputsResp;
    struct tt__RelayOutputSettings *ptRelayOutputSettings = NULL;

    pSoap = W_OnvifSoapNew(5);
    if(NULL == pSoap)
    {
        return SOAP_ERR;
    }

    memset(&tGetRelayOutputsReq, 0, sizeof(tGetRelayOutputsReq));
    printf("\n------------------Get GetRelayOutputs-----------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    sRet = soap_call___tmd__GetRelayOutputs(pSoap, pReq->acDeviceIO, NULL, &tGetRelayOutputsReq, &tGetRelayOutputsResp);
    if(SOAP_OK != sRet)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }
    printf("IOInputIndex: %d, sizeRelayOutputs: %d\n", ptAlarmIO->IOInputIndex, tGetRelayOutputsResp.__sizeRelayOutputs);

    memset(&tSetRelayOutputSettingsReq, 0, sizeof(tSetRelayOutputSettingsReq));

    tSetRelayOutputSettingsReq.RelayOutputToken = soap_malloc(pSoap, 32);
    if(NULL == tSetRelayOutputSettingsReq.RelayOutputToken)
    {
        printf("tSetRelayOutputSettingsReq.RelayOutputToken is NULL !!!\n");
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }
    if(ptAlarmIO->IOInputIndex < tGetRelayOutputsResp.__sizeRelayOutputs)
    {
        int s32Idx = ptAlarmIO->IOInputIndex;
        strncpy(tSetRelayOutputSettingsReq.RelayOutputToken, tGetRelayOutputsResp.RelayOutputs[s32Idx].token, 32);
    }
    else{
        printf("ptRelayOutsize is less than IOInputIndex !!!\n");
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }
    
    ptRelayOutputSettings = soap_malloc(pSoap, sizeof(struct tt__RelayOutputSettings));
    if(NULL == ptRelayOutputSettings)
    {
        printf("ptRelayOutputSettings is NULL !!!\n");
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }
    tSetRelayOutputSettingsReq.Properties = ptRelayOutputSettings;
    
    ptRelayOutputSettings->DelayTime = soap_malloc(pSoap, 32);
    if(NULL == ptRelayOutputSettings->DelayTime)
    {
        printf("ptRelayOutputSettings->DelayTime is NULL !!!\n");
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }
    snprintf(ptRelayOutputSettings->DelayTime, 32, "PT%dS", ptAlarmIO->delayTime);

    ptRelayOutputSettings->Mode = ptAlarmIO->relayMode;
    ptRelayOutputSettings->IdleState = ptAlarmIO->idleState;
    
    printf("\n------------------Set RelayOutputSettings-----------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    sRet = soap_call___tds__SetRelayOutputSettings(pSoap, pReq->acDeviceIO, NULL, &tSetRelayOutputSettingsReq, &tSetRelayOutputSettingsResp);
    if(SOAP_OK != sRet)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}

int W_SetRelayOutputState(W_ONVIF_REQ_ST *pReq, W_ONVIF_ALARM_IO_STATE_ST *ptAlarmIOState)
{
    int sRet = 0;
    struct soap *pSoap = NULL;
    struct _tds__SetRelayOutputState tSetRelayOutputStateReq;
    struct _tds__SetRelayOutputStateResponse tSetRelayOutputStateResp;
    struct _tds__GetRelayOutputs tGetRelayOutputsReq;
    struct _tds__GetRelayOutputsResponse tGetRelayOutputsResp;

    pSoap = W_OnvifSoapNew(5);
    if(NULL == pSoap)
    {
        return SOAP_ERR;
    }

    memset(&tGetRelayOutputsReq, 0, sizeof(tGetRelayOutputsReq));
    printf("\n------------------Get GetRelayOutputs-----------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    sRet = soap_call___tmd__GetRelayOutputs(pSoap, pReq->acDeviceIO, NULL, &tGetRelayOutputsReq, &tGetRelayOutputsResp);
    if(SOAP_OK != sRet)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }
    printf("IOInputIndex: %d, sizeRelayOutputs: %d\n", ptAlarmIOState->IOInputIndex, tGetRelayOutputsResp.__sizeRelayOutputs);

    memset(&tSetRelayOutputStateReq, 0, sizeof(tSetRelayOutputStateReq));
    tSetRelayOutputStateReq.RelayOutputToken = soap_malloc(pSoap, 32);
    if(NULL == tSetRelayOutputStateReq.RelayOutputToken)
    {
        printf("tSetRelayOutputStateReq.RelayOutputToken is NULL !!!\n");
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    tSetRelayOutputStateReq.LogicalState = (enum tt__RelayLogicalState)ptAlarmIOState->alarmStatus;
    if(ptAlarmIOState->IOInputIndex < tGetRelayOutputsResp.__sizeRelayOutputs)
    {
        int s32Idx = ptAlarmIOState->IOInputIndex;
        strncpy(tSetRelayOutputStateReq.RelayOutputToken, tGetRelayOutputsResp.RelayOutputs[s32Idx].token, 32);
    }
    else{
        printf("ptRelayOutsize is less than IOInputIndex !!!\n");
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    printf("\n------------------Set RelayOutputState-----------------\n");
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    sRet = soap_call___tds__SetRelayOutputState(pSoap, pReq->acDeviceIO, NULL, &tSetRelayOutputStateReq, &tSetRelayOutputStateResp);
    if(SOAP_OK != sRet)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }

    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


/* parse XML key value */
static int ParseXMLValue(char *pXMLStr, char *pLeft, char *pRight, char *pOut)
{
    char *pStart = NULL;
    char *pEnd = NULL;

    pStart = strstr(pXMLStr, pLeft);
    pEnd = strstr(pXMLStr, pRight);

    if (NULL == pStart || NULL == pEnd)
    {
        printf("Parse \"%s\" failed.\n", pLeft);
        return -1;
    }

    memcpy(pOut, pStart + strlen(pLeft), pEnd - pStart - strlen(pLeft));
    return 0;
}


static void *W_CreateAlarmServerDemo(void *pThParam)
{
    // int listenFd = 0;
    // int connFd = 0;
    // int recvLen = 0;
    // char acRecvBuff[2048];
    // struct sockaddr_in listenAddr;
    // char reuseAddr = 1;
    
    // W_ONVIF_EVENT_SUB_ST stEventSub = {0};
    // memcpy(&stEventSub, (W_ONVIF_EVENT_SUB_ST *)pThParam, sizeof(W_ONVIF_EVENT_SUB_ST));

    // listenFd = socket(AF_INET, SOCK_STREAM, 0);
    // if (listenFd < 0)
    // {
    //     printf("Create socket error: %s(errno: %d)\n", strerror(errno), errno);
    //     pthread_exit(NULL);
    // }
    
    // memset(&listenAddr, 0, sizeof(listenAddr));
    // listenAddr.sin_family      = AF_INET;
    // listenAddr.sin_addr.s_addr = inet_addr(stEventSub.acSubAddr);
    // listenAddr.sin_port        = htons(stEventSub.subPort);

    // int flags = fcntl(listenFd, F_GETFD);
    // flags |= FD_CLOEXEC;
    // fcntl(listenFd, F_SETFD, flags);
    
    // setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR,(const char*)&reuseAddr, sizeof(char));
    // if (bind(listenFd, (struct sockaddr *)&listenAddr, sizeof(listenAddr)) < 0)
    // {
    //     printf("Bind socket error: %s(errno: %d)\n", strerror(errno), errno);
    //     pthread_exit(NULL);
    // }
    
    // if (listen(listenFd, 20) < 0)
    // {
    //     printf("Listen socket error: %s(errno: %d)\n", strerror(errno), errno);
    //     pthread_exit(NULL);
    // }
    // printf("======waiting for alarm event======\n");

    // connFd = accept(listenFd, (struct sockaddr*)NULL, NULL);
    // if (connFd < 0)
    // {
    //     printf("accept socket error: %s(errno: %d)\n", strerror(errno), errno);
    //     pthread_exit(NULL);
    // }
    
    // while (1)
    // {
    //     memset(acRecvBuff, 0, sizeof(acRecvBuff));
    //     recvLen = recv(connFd, acRecvBuff, sizeof(acRecvBuff), 0);
    //     acRecvBuff[recvLen + 1] = '\0';
    //     printf("Recv alarm msg from client: \n%s\n", acRecvBuff); 
    // }
    
    // close(connFd);
    // close(listenFd);
    // pthread_exit(NULL);
}


static void W_ConnectAlarmServer(W_ONVIF_EVENT_SUB_ST *pEventSub)
{
    int socketFd = 0;
    struct sockaddr_in svrAddr;
    struct timeval timeout={10, 0}; //10s

    memset(&svrAddr, 0, sizeof(svrAddr));
    svrAddr.sin_family = AF_INET;    
    svrAddr.sin_addr.s_addr = inet_addr(pEventSub->acSubAddr);
    svrAddr.sin_port  = htons(pEventSub->subPort); 
    bzero(&(svrAddr.sin_zero), 8);
                
    if ((socketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0)    
    {
        printf("Create Socket Fail!\n");
        return;
    }

    if (connect(socketFd, (struct sockaddr *)&svrAddr, sizeof(svrAddr)) < 0)
    {
        printf("Connect to alarm server %s: %d failed\n", pEventSub->acSubAddr, pEventSub->subPort);
        if (socketFd > 0)
        {
            close(socketFd);
            socketFd = -1;
        }
        return;
    }
    printf("Connect to alarm server %s: %d Success, socket:%d.\n", pEventSub->acSubAddr, pEventSub->subPort, socketFd);

    setsockopt(socketFd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
    
    g_eventSocket = socketFd;
    return;
}


static void W_SendAlarmMsgToServer(W_ONVIF_EVENT_SUB_ST *pEventSub, char *pAlamInfo)
{
    int sRet = 0;
    char acData[128] = {0};
    char acSendBuf[1024] = {0};
    char acUtcTime[1024] = {0};
    char as8RelayToken[32] = {0};
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    struct tm getTime;
    int timeStamp = 0;
    int sendFlag = 0;

    printf("AlamInfo:%s\n", pAlamInfo);
    
    ParseStringValue(pAlamInfo, "UtcTime=\"", "\" ", acUtcTime);
    sscanf(acUtcTime, "%04d-%02d-%02dT%02d:%02d:%02dZ\n", &year, &month, &day, &hour, &minute, &second);
    /* time string conver to int */
    getTime.tm_year  = year - 1900;
    getTime.tm_mon   = month - 1;
    getTime.tm_mday  = day;
    getTime.tm_hour  = hour;
    getTime.tm_min   = minute;
    getTime.tm_sec   = second;
    getTime.tm_isdst = 0;
    timeStamp = mktime(&getTime);
    
    sRet = ParseXMLValue(pAlamInfo, "<tt:Data>", "</tt:Data>", acData);
    if (0 != sRet || strlen(acData) <= 0)
    {
        printf("Pust alarm <tt:Data> failed\n");
        return;
    }
    
    if(NULL != strstr(acData, "LogicalState"))
    {
        int s32IOIndex = 0;

        if(0 == ParseStringValue(pAlamInfo, "InputToken\" Value=\"", "\"/", as8RelayToken))
        {
            sendFlag = 1;
            sscanf(as8RelayToken, "AlarmIn_%d", &s32IOIndex);
            if(pEventSub->relayOutputSize <= s32IOIndex)
            {
                s32IOIndex--;
            }
        }
        else if (0 == ParseStringValue(pAlamInfo, "Value=\"", "\" Name=\"InputToken\"", as8RelayToken))
        {
            sendFlag = 1;
            sscanf(as8RelayToken, "%d", &s32IOIndex);
            if(pEventSub->relayOutputSize <= s32IOIndex)
            {
                s32IOIndex--;
            }
        }
  
        if(NULL != strstr(acData, "false"))
        {
            sprintf(acSendBuf, "{\"channelID\":%d, \"AlarmType\":\"%s\", \"timeStamp\":%d, \"IOAlarmIndex\":%d}",
                pEventSub->chnId, "InputAlarmOff", timeStamp, s32IOIndex);
        }
        else
        {
            sprintf(acSendBuf, "{\"channelID\":%d, \"AlarmType\":\"%s\", \"timeStamp\":%d, \"IOAlarmIndex\":%d}",
                pEventSub->chnId, "InputAlarmOn", timeStamp, s32IOIndex);
        }
    }
    else
    {
        if(NULL != strstr(acData, "true"))
        {
            sprintf(acSendBuf, "{\"channelID\":%d, \"AlarmType\":\"%s\", \"timeStamp\":%d}",
                pEventSub->chnId, "MotionAlarmOn", timeStamp);
            sendFlag = 1;
        }
        else
        {
            sprintf(acSendBuf, "{\"channelID\":%d, \"AlarmType\":\"%s\", \"timeStamp\":%d}",
                pEventSub->chnId, "MotionAlarmOff", timeStamp);
            sendFlag = 1;
        }
    }
    if(1 == sendFlag)
    {
        printf("SendBuf:%s\n", acSendBuf);
        if (0 != W_PostMsgToServer(acSendBuf))
        {
            printf("W_PostMsgToServer failed\n");
            return;
        }
    }
    return;
}


static void *W_PullAlarmMsgProc(void *pParam)
{
    int i = 0;
    struct soap *pSoap = NULL;
    struct SOAP_ENV__Header header;    //soap header;
    struct wsa5__EndpointReferenceType wsa5__ReplyTo = {0};
    struct _tev__PullMessages stPullMsgReq;
    struct _tev__PullMessagesResponse stPullMsgResp;
    W_ONVIF_EVENT_SUB_ST *ptEventSub = (W_ONVIF_EVENT_SUB_ST *)pParam;
    int s32SleepCnt = 0;

    if (!ptEventSub)
    {
        printf("ptEventSub = NULL !!!\n");
        return NULL;
    }
    
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return NULL;
	}

    soap_default_SOAP_ENV__Header(pSoap, &header);
    header.wsa5__MessageID = (char *)soap_wsa_rand_uuid(pSoap);
    header.wsa5__To =     ptEventSub->acSubId;
    header.wsa5__Action = "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesRequest";
    wsa5__ReplyTo.Address = "http://www.w3.org/2005/08/addressing/anonymous";
    header.wsa5__ReplyTo = &wsa5__ReplyTo;
    pSoap->header = &header;
    
    memset(&stPullMsgReq, 0, sizeof(stPullMsgReq));
    stPullMsgReq.Timeout = (char *)soap_malloc(pSoap, 32);
    printf("chnId:%d start Pull Messages\n", ptEventSub->chnId);
    
    while (g_chnSubFlag[ptEventSub->chnId])
    {
        memset(stPullMsgReq.Timeout, 0, 32);
        sprintf(stPullMsgReq.Timeout, "PT%dS", 10);
        stPullMsgReq.MessageLimit = 2;

        pSoap->header = &header;
        soap_wsse_add_UsernameTokenDigest(pSoap, "User", ptEventSub->acUserName, ptEventSub->acPassword);
        soap_call___tev__PullMessages(pSoap, ptEventSub->acSubId, NULL, &stPullMsgReq, &stPullMsgResp);
        if (pSoap->error)
        {
            printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
            //sleep(2);
            s32SleepCnt = 0;
            while (s32SleepCnt < 20)
            {
                if (!g_chnSubFlag[ptEventSub->chnId])
                {
                    break;
                }
                s32SleepCnt++;
                usleep(100 * 1000);
            }
            continue;
        }
        else
        {
            printf("soap_call___tev__PullMessages success\n");
        }
        
        for (i = 0; i < stPullMsgResp.__sizeNotificationMessage; i++)
        {
            if (NULL != strstr(stPullMsgResp.wsnt__NotificationMessage[i].Message.__any, "IsMotion") 
                || NULL != strstr(stPullMsgResp.wsnt__NotificationMessage[i].Message.__any, "LogicalState"))
            {
                W_SendAlarmMsgToServer(ptEventSub, stPullMsgResp.wsnt__NotificationMessage[i].Message.__any);
            }
        }
        
        //sleep(2);
        s32SleepCnt = 0;
        while (s32SleepCnt < 20)
        {
            if (!g_chnSubFlag[ptEventSub->chnId])
            {
                break;
            }
            s32SleepCnt++;
            usleep(100 * 1000);
        }
    }

EXIT:
    printf("chnId:%d thread Exit\n", ptEventSub->chnId);
    free(ptEventSub);
    W_OnvifSoapDelete(pSoap);
    pthread_exit(NULL);
}


int W_Subscription(W_ONVIF_REQ_ST *pReq, W_ONVIF_EVENT_SUB_ST *pEventSub)
{
    int sRet = 0;
    struct soap *pSoap = NULL;
    struct _tds__GetRelayOutputs tGetRelayOutputsReq;
    struct _tds__GetRelayOutputsResponse tGetRelayOutputsResp;
    struct _tev__CreatePullPointSubscription stCreatPullReq;
    struct _tev__CreatePullPointSubscriptionResponse stSCreatPullResp;
#ifdef __linux__
    pthread_t detThreadId;
#else
    //std::thread detThreadId;
#endif
    struct _tev__PullMessages stPullMsgReq;
    struct _tev__PullMessagesResponse stPullMsgResp;
    W_ONVIF_EVENT_SUB_ST *ptEventSub = NULL;
    
	pSoap = W_OnvifSoapNew(5);
	if (NULL == pSoap)
	{
		return SOAP_ERR;
	}
    
    printf("\n------------------Get GetRelayOutputs-----------------\n");

    memset(&tGetRelayOutputsReq, 0, sizeof(tGetRelayOutputsReq));
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    sRet = soap_call___tmd__GetRelayOutputs(pSoap, pReq->acDeviceIO, NULL, &tGetRelayOutputsReq, &tGetRelayOutputsResp);
    if(SOAP_OK != sRet)
    {
        printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
        return SOAP_ERR;
    }
    pEventSub->relayOutputSize = tGetRelayOutputsResp.__sizeRelayOutputs;

    printf("\n------------------Create PullPoint Subscription-----------------\n");
    
    memset(&stCreatPullReq, 0, sizeof(stCreatPullReq));
    stCreatPullReq.InitialTerminationTime = (char *)soap_malloc(pSoap, 32);
    sprintf(stCreatPullReq.InitialTerminationTime, "PT%dS", pEventSub->sudDurationTime);
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tev__CreatePullPointSubscription(pSoap, pReq->acEventAddr, NULL, &stCreatPullReq, &stSCreatPullResp);
    if (pSoap->error)
    {
    	printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
    	return SOAP_ERR;
    }
    pEventSub->currentTime = stSCreatPullResp.wsnt__CurrentTime;
    pEventSub->terminaTime = stSCreatPullResp.wsnt__TerminationTime;
    strcpy(pEventSub->acSubId, stSCreatPullResp.SubscriptionReference.Address);
    printf("acSubId:%s\n", pEventSub->acSubId);

    strcpy(pEventSub->acUserName, pReq->acUserName);
    strcpy(pEventSub->acPassword, pReq->acPassword);
    
    if (0 == g_chnSubFlag[pEventSub->chnId])
    {
        ptEventSub = (W_ONVIF_EVENT_SUB_ST *)malloc(sizeof(W_ONVIF_EVENT_SUB_ST));
        if (!ptEventSub)
        {
            W_OnvifSoapDelete(pSoap);
            printf("malloc ptEventSub failed !!!\n");
    	    return SOAP_ERR;
        }
        memcpy(ptEventSub, pEventSub, sizeof(W_ONVIF_EVENT_SUB_ST));
        
#ifdef __linux__
        if (0 != pthread_create(&detThreadId, NULL, W_PullAlarmMsgProc, ptEventSub))
        {
            printf("Create chnId:%d pull alarm msg failed.\n", ptEventSub->chnId);
            free(ptEventSub);
            ptEventSub = NULL;
        }
        else
        {
            g_chnSubFlag[pEventSub->chnId] = 1;
        }
#else
        // detThreadId = thread(W_PullAlarmMsgProc, ptEventSub);
        // detThreadId.detach();
        //  g_chnSubFlag[pEventSub->chnId] = 1;
#endif
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}


int W_DeleteSubscription(W_ONVIF_REQ_ST *pReq, W_ONVIF_EVENT_SUB_ST *pEventSub)
{
    struct soap *pSoap = NULL;
    struct _wsnt__Unsubscribe stUnsubReq;
    struct _wsnt__UnsubscribeResponse stUnsubResp;

    g_chnSubFlag[pEventSub->chnId] = 0;
    
    pSoap = W_OnvifSoapNew(5);
    if (NULL == pSoap)
    {
    	return SOAP_ERR;
    }
    
    printf("\n------------------Delete Subscription-----------------\n");
    memset(&stUnsubReq, 0, sizeof(stUnsubReq));
    soap_wsse_add_UsernameTokenDigest(pSoap, "user", pReq->acUserName, pReq->acPassword);
    soap_call___tev__Unsubscribe(pSoap, pEventSub->acSubId, NULL, &stUnsubReq, &stUnsubResp);
    if (pSoap->error)
    {
    	printf("Soap error: %d, %s, %s\n", pSoap->error, *soap_faultcode(pSoap), *soap_faultstring(pSoap));
        W_OnvifSoapDelete(pSoap);
    	return SOAP_ERR;
    }
    
    W_OnvifSoapDelete(pSoap);
    return SOAP_OK;
}

