#ifndef _W_ONVIF_CLI_H_
#define _W_ONVIF_CLI_H_

#include "onvif/wsaapi.h"
#include "onvif/wsseapi.h"
#include "onvif/soapH.h"

#ifdef __cplusplus
    extern "C" {
#endif

#define W_MAX_DETECT_DEV_NUM    128
#define W_MAX_PTZ_PATROL_NUM    8
#define W_MAX_DEV_NUM           16
#define W_IMAGEOPTION_RANGE     255

typedef struct W_DetectInfo
{
    char acDevMac[16];
    char acDevIp[16];
    char acTypeName[64];
    char acAliasName[64];
}W_DETECT_INFO_ST;

typedef struct W_detectDevice
{
    int deviceNum;
    W_DETECT_INFO_ST stIpcInfo[W_MAX_DETECT_DEV_NUM];
}W_DETECT_DEVICE_ST;


typedef struct W_onvifReq
{
    char acDevType[32];
    char acDevIp[32];
    char acUserName[64];
    char acPassword[64];
    char acXaddr[128];
    char acMedia2Addr[128];
    char acPtzXaddr[128];
    char acAnalytics[128];
    char acEventAddr[128];
    char acImageAddr[128];
    char acDeviceIO[128];
    int  prifTokenNum;
    char aaPrifToken[3][64];
    int  cnfTokenNum;
    char aaCnfToken[3][64];
    int  analyticsTokenNum;
    char aaAnalyticsToken[3][64];
    int s32MDCellColumns;
    int s32MDCellRows;
    int s32IsOnLine;
    int s32IsOnvif;
    int s32IsSupportPTZ;
    int s32IsSupportAudio;
    int s32ID;
    int s32Fps;
    int s32Width;
    int s32Height;
}W_ONVIF_REQ_ST;


typedef struct W_onvifDevInfo
{
    char acDevName[64];
    char acDevModel[64];
    char acSerialNum[64];
    char acFwVersion[64];
    char acHardwareId[64];
}W_ONVIF_DEV_INFO_ST;


typedef struct W_onvifTime
{
    char acTimeZone[64];
    time_t  devTime;
    int  dateFormat;
    int  hourFormat;
    int  timeSyncMode;
}W_ONVIF_TIME_ST;


typedef struct W_onvifNTP
{
    int  enabled;
    int  addrType;
    int  port;
    int  syncInterval;
    char acIPAddr[46];
    char acDomain[64];
}W_ONVIF_NTP_ST;


typedef struct W_IPV4Info
{
    char acIPv4Addr[16];
    char as8Gateway[16];
    char as8Netmask[16];
    int  prefixLength;
}W_IPV4_INFO_ST;

typedef struct W_netInterFace
{
    int  intfaceId;
    char acName[16];
    char acHwAddress[32];
    int  MTU;
    int  ipType;
    int  addrNum;
    W_IPV4_INFO_ST stIpv4Info[2];
}W_NET_INTERFACE_ST;


typedef struct W_onvifNetInfo
{
    int intfaceNum;
    W_NET_INTERFACE_ST stInterFace[3];
}W_ONVIF_NET_INFO_ST;


typedef struct W_DNSInfo
{
    int  addrType;
    char acIPv4Addr[16];
    char acIPv6Addr[46];
}W_DNS_INFO_ST;

typedef struct W_onvifDNS
{
    int DNSNum;
    W_DNS_INFO_ST stDNS[4];
}W_ONVIF_DNS_ST;


typedef struct W_resoluCapality
{
    int width;
    int height;
    int minBitRate;
    int maxBitRate;
    int defaultBitRate;
}W_RESOLU_CAPALITY_ST;

typedef struct W_smartEncode
{
    int H264SmartEncModeNum;
    int H264SmartEncModeList[4];
    int H265SmartEncModeNum;
    int H265SmartEncModeList[4];
}W_SMART_ENCODe_ST;

typedef struct W_streamCapality
{
    int streamId;
    int resolutionNum;
    W_RESOLU_CAPALITY_ST *pResoluCapaList;
    int maxFrameRate;
    int maxMJPEGFrameRate;
    W_SMART_ENCODe_ST stSmartEncode;
}W_STREAM_CAPALITY_ST;

typedef struct W_videoMode
{
    int width;
    int height;
    int frameRate;
}W_VIDEO_MODE_ST;

typedef struct W_onvifVideoCapability
{
    int isSupCfg;
    int isSupSmoothLevel;
    int isSupImageFormat;
    int encodeFormatNum;
    int encodeFormatList[8];
    int minQuality;
    int maxQuality;
    int minIFrameInterval;
    int maxIFrameInterval;
    int streamCapaNum;
    W_STREAM_CAPALITY_ST *pStreamCapaList;
    int videoModeNum;
    W_VIDEO_MODE_ST *pVideoModeList;
    int GOPTypeNum;
    int GOPTypeList[4];
}W_ONVIF_VIDEO_CAPABILITY_ST;


typedef struct W_audioMode
{
    int channel;
    int modeNum;
    int modeList[4];
}W_AUDIO_MODE_ST;

typedef struct W_audioEncFormat
{
    int type;
    int num;
    int sampleList[8];
}W_AUDIO_ENC_FORMAT_ST;

typedef struct W_onvifAudioCapability
{
    int audioInNum;
    W_AUDIO_MODE_ST stAudioInModeList[2];
    int audioInEncNum;
    W_AUDIO_ENC_FORMAT_ST stAudioInEncList[8];
    int serialInNum;
    W_AUDIO_MODE_ST stSerialInModeList[2];
    int serialInEncNum;
    W_AUDIO_ENC_FORMAT_ST stSerialInEncList[8];
}W_ONVIF_AUDIO_CAPABILITY_ST;


typedef struct W_videoStreamInfo
{
    int streamId;
    int mainStramType;
    int encEnable;
    int encFormat;
    int width;
    int height;
    int bitRate;
    int bitRateType;
    int frameRate;
    int IFrameInterval;
    int profileLine;
    int imageQuality;
    int smoothLevel;
    int smartEncMode;
}W_VIDEO_STRAM_INFO_ST;


typedef struct W_onvifVideoParams
{
    int streamNum;
    W_VIDEO_STRAM_INFO_ST stStreamInfo[3];
}W_ONVIF_VIDEO_PARAMS_ST;


typedef struct W_audioInput
{
    int chnId;
    int enabled;
    int mode;
}W_AUDIO_INPUT_ST;

typedef struct W_onvifAudioParams
{
    int isMute;
    int type;
    int encodeFormat;
    int sampleRate;
    int biteRate;
    int inputGain;
    int enableDenoise;
    int audioInputNum;
    W_AUDIO_INPUT_ST stAudioInput[2];
    int serialInputNum;
    W_AUDIO_INPUT_ST stSerialInput[2];
}W_ONVIF_AUDIO_PARAMS_ST;


typedef struct W_onvifImageParam
{
    int  brightness;
    int  contrast;
    int  saturation;
    int  sharpness;
}W_ONVIF_IMAGE_PARAM_ST;


typedef struct W_onvifOSDCapability
{
    int  totalNum;
    int  plainTextNum;
    int  imageNum;
    int  dateNum;
    int  timeNum;
    int  dateTimeNum;
    int  positionOption;
    char aaPosOptionList[8][32];
    int  typeNum;
    char aaType[4][32];
    int  dateFormatNum;
    char aaDateFormat[4][32];
    int  timeFormatNum;
    char aaTimeFormat[4][32];
}W_ONVIF_OSD_CAPABILITY_ST;


typedef struct w_osdParam
{
    int  ebable;
    int  positionX;
    int  positionY;
    char acType[32];
    char acContent[128];
} W_OSD_PARAM_ST;

typedef struct W_onvifOSDParams_ST
{
    int OSDNum;
    W_OSD_PARAM_ST astOSDParam[8];
} W_ONVIF_OSD_PARAMS_ST;


typedef struct W_onvifPTZCapability
{
    int  isSupportPTZ;
    int  isSupportPreset;
    int  isSupportPatrol;
    char as8TranslationTSF[128];
    char as8TranslationTGS[128];
    char as8ZoomTGS[128];
    char as8SpeedGSS[128];
    char as8SpeedZSS[128];
}W_ONVIF_PTZ_CAPABILITY_ST;


typedef struct W_onvifPTZCtrl
{
    int  PTZCmd;
    int  horizontalSpeed;
    int  verticalSpeed;
    int  zoomSpeed;
}W_ONVIF_PTZ_CTRL_ST;


typedef struct W_ptzPreset
{
    int  preId;
    char acPreName[64];
}W_PTZ_PRESET_ST;

typedef struct W_onvifPTZPresets
{
    int  presetNum;
    W_PTZ_PRESET_ST *pstPtzPreset;
}W_ONVIF_PTZ_PRESETS_ST;


typedef struct W_patrolItem
{
    int presetId;
    int duration;
}W_PATROL_ITEM_ST;

typedef struct W_ptzPatrol
{
    int  Id;
    char acName[64];
    int  itemNum;
    W_PATROL_ITEM_ST *pstPatrolItem;
}W_PTZ_PATROL_ST;

typedef struct W_onvifPTZPatrols
{
    int  patrolNum;
    W_PTZ_PATROL_ST astPtzPatrol[W_MAX_PTZ_PATROL_NUM];
}W_ONVIF_PTZ_PATROLS_ST;

typedef struct W_onvifZoomAera
{
    int s32CenterPointX;
    int s32CenterPointY;
    int s32Width;
    int s32Height;
    int s32WinWidth;
    int s32WinHeight;
}W_ONVIF_ZOOM_AERA_ST;

typedef struct W_onvifVector1D
{
    float x;
}W_ONVIF_Vector1D_ST;

typedef struct W_onvifVector2D
{
    float x;
    float y;
}W_ONVIF_Vector2D_ST;

typedef struct W_onvifPTZVector
{
    int s32HasPT;
    W_ONVIF_Vector2D_ST stPanTilt;
    int s32HasZoom;
    W_ONVIF_Vector1D_ST stZoom;
}W_ONVIF_PTZVector_ST;

typedef struct W_onvifPTZSpeed
{
    int s32HasPT;
    W_ONVIF_Vector2D_ST stPanTilt;
    int s32HasZoom;
    W_ONVIF_Vector1D_ST stZoom;
}W_ONVIF_PTZSpeed_ST;

typedef struct W_onvifPTZRelativeMove
{
    W_ONVIF_PTZVector_ST stTranslation;
    int s32HasSpeed;
    W_ONVIF_PTZSpeed_ST stSpeed;
}W_ONVIF_PTZRelativeMove_ST;

typedef struct W_onvifMDCapability
{
    int s32IsSupCfg;
    int s32MDCellColumns;
    int s32MDCellRows;
}W_ONVIF_MD_CAPABILITY_ST;

typedef struct W_onvifVideoAnalyticsCapability
{
    W_ONVIF_MD_CAPABILITY_ST stMDCapability;
}W_ONVIF_VIDEO_ANALYTICS_CAPABILITY_ST;

typedef struct W_onvifAlarmMD
{
    int enable;
    int sensitivity;
    char acGrid[128];
}W_ONVIF_ALARM_MD_ST;


typedef struct W_onvifEventSub
{
    char acSubAddr[32];
    int  subPort;
    int  sudDurationTime;
    char acSubId[128];
    int  currentTime;
    int  terminaTime;
    int  chnId;
    char acUserName[64];
    char acPassword[64];
    int  eventSocket;
    int  relayOutputSize;
}W_ONVIF_EVENT_SUB_ST;


typedef struct W_onvifAlarmIO
{
    int IOInputIndex;
    int relayMode;
    int delayTime;
    int idleState;
}W_ONVIF_ALARM_IO_ST;


typedef struct W_onvifAlarmIOState
{
    int IOInputIndex;
    int alarmStatus;
}W_ONVIF_ALARM_IO_STATE_ST;

typedef struct W_onvifDevReqInfo
{
    int s32DevNum;
    W_ONVIF_REQ_ST atOnvifReq[W_MAX_DEV_NUM];
}W_ONVIF_DEV_REQ_INFO_ST;

typedef struct W_onvifRecordInfo
{
    long long s64Begin;
    long long s64End;
}W_ONVIF_RECORD_INFO_ST;

typedef struct W_onvifRecord
{
    long long s64BeginMin;
    long long s64EndMax;
    int s32RecordNum;
    W_ONVIF_RECORD_INFO_ST *ptRecordInfo;
}W_ONVIF_RECORD_ST;

int W_GetOnvifDevReqInfo(W_ONVIF_DEV_REQ_INFO_ST *ptDevReqInfo);

int W_CliDetectDevice(W_DETECT_DEVICE_ST *pstDetectDevice);
int W_SubDeviceReboot(W_ONVIF_REQ_ST *pReq);
int W_SubFactoryDefault(W_ONVIF_REQ_ST *pReq);
int W_GetDeviceInfo(W_ONVIF_REQ_ST *pReq, W_ONVIF_DEV_INFO_ST *pDeviceInfo);
int W_GetDateAndTime(W_ONVIF_REQ_ST *pReq, W_ONVIF_TIME_ST *pTime);
int W_SetDateAndTime(W_ONVIF_REQ_ST *pReq, W_ONVIF_TIME_ST *pTime);
int W_GetNTPInfo(W_ONVIF_REQ_ST *pReq, W_ONVIF_NTP_ST *pNTP);
int W_SetNTPInfo(W_ONVIF_REQ_ST *pReq, W_ONVIF_NTP_ST *pNTP);

int W_GetNetInterfaces(W_ONVIF_REQ_ST *pReq, W_ONVIF_NET_INFO_ST *pNetInfo);
int W_SetNetInterfaces(W_ONVIF_REQ_ST *pReq, W_ONVIF_NET_INFO_ST *pNetInfo);
int W_GetDNSInfo(W_ONVIF_REQ_ST *pReq, W_ONVIF_DNS_ST *pDNS);
int W_SetDNSInfo(W_ONVIF_REQ_ST *pReq, W_ONVIF_DNS_ST *pDNS);

int W_GetScopes(W_ONVIF_REQ_ST *pReq);
int W_GetServices(W_ONVIF_REQ_ST *pReq);
int W_GetCapabilities(W_ONVIF_REQ_ST *pReq, enum tt__CapabilityCategory capaType);
int W_GetProfiles(W_ONVIF_REQ_ST *pReq);

int W_GetVideoSources(W_ONVIF_REQ_ST *pReq);
int W_GetVideoSourceConfigs(W_ONVIF_REQ_ST *pReq);
int W_GetVideoSourceModes(W_ONVIF_REQ_ST *pReq, W_VIDEO_MODE_ST *pVideoModes);
int W_SetVideoSourceModes(W_ONVIF_REQ_ST *pReq, W_VIDEO_MODE_ST *pVideoModes);
int W_GetVideoEncodeConfigs(W_ONVIF_REQ_ST *pReq, W_ONVIF_VIDEO_PARAMS_ST *pVideoParams);
int W_SetVideoEncodeConfigs(W_ONVIF_REQ_ST *pReq, W_ONVIF_VIDEO_PARAMS_ST *pVideoParams);
int W_VideoSourceConfigsOptions(W_ONVIF_REQ_ST *pReq);
int W_VideoEncodeConfigsOptions(W_ONVIF_REQ_ST *pReq, W_ONVIF_VIDEO_CAPABILITY_ST *pVideoCapality);

int W_GetAudioSources(W_ONVIF_REQ_ST *pReq);
int W_GetAudioSourceConfigs(W_ONVIF_REQ_ST *pReq);
int W_GetAudioEncodeConfigs(W_ONVIF_REQ_ST *pReq, W_ONVIF_AUDIO_PARAMS_ST *pAudioParams);
int W_SetAudioEncodeConfigs(W_ONVIF_REQ_ST *pReq, W_ONVIF_AUDIO_PARAMS_ST *pAudioParams);
int W_AudioSourceConfigsOptions(W_ONVIF_REQ_ST *pReq, W_ONVIF_AUDIO_CAPABILITY_ST *pAudioCapality);
int W_AudioEncodeConfigsOptions(W_ONVIF_REQ_ST *pReq, W_ONVIF_AUDIO_CAPABILITY_ST *pAudioCapality);

int W_GetImageSettings(W_ONVIF_REQ_ST *pReq, W_ONVIF_IMAGE_PARAM_ST *pImageParam);
int W_SetImageSettings(W_ONVIF_REQ_ST *pReq, W_ONVIF_IMAGE_PARAM_ST *pImageParam);

int W_GetLiveStreamUri(W_ONVIF_REQ_ST *pReq, int streamId, char *pLiveUrl);
int W_GetSnapshotUri(W_ONVIF_REQ_ST *pReq, int streamId, char *pSnapUrl);
int W_GetOSDOptions(W_ONVIF_REQ_ST *pReq, W_ONVIF_OSD_CAPABILITY_ST *pOSDCapality);
int W_GetOSDs(W_ONVIF_REQ_ST *pReq, const char* pcEndPoint, W_ONVIF_OSD_PARAMS_ST *pOSDParams);
int W_SetOSDs(W_ONVIF_REQ_ST *pReq, const char* pcEndPoint, W_ONVIF_OSD_PARAMS_ST *pOSDParams);

int W_GetPTZCapality(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_CAPABILITY_ST *pPTZCapality);
int W_PTZControl(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_CTRL_ST *pPTZCtrl);
int W_GetPresets(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_PRESETS_ST *pPresets);
int W_SetPreset(W_ONVIF_REQ_ST *pReq,  W_PTZ_PRESET_ST *pPreset);
int W_DelPreset(W_ONVIF_REQ_ST *pReq,  W_PTZ_PRESET_ST *pPreset);
int W_GotoPreset(W_ONVIF_REQ_ST *pReq, W_PTZ_PRESET_ST *pPreset);
int W_GetPatrols(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_PATROLS_ST *pPatrols);
int W_ModifyPatrols(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_PATROLS_ST *pPatrols);
int W_CreatePatrols(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_PATROLS_ST *pPatrols);
int W_DeletePatrols(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZ_PATROLS_ST *pPatrols);
int W_OperatePatrol(W_ONVIF_REQ_ST *pReq, int patrolId, int operateType);
int W_PTZRelativeMove(W_ONVIF_REQ_ST *pReq, W_ONVIF_PTZRelativeMove_ST *pRelativeMoveParam, W_ONVIF_PTZ_CAPABILITY_ST *ptPTZCapality);

int W_GetVideoAnalyticsCapability(W_ONVIF_REQ_ST *pReq, W_ONVIF_VIDEO_ANALYTICS_CAPABILITY_ST *ptVideoAnaCap);
int W_GetMotionDetect(W_ONVIF_REQ_ST *pReq, W_ONVIF_ALARM_MD_ST *pAlarmMD);
int W_SetMotionDetect(W_ONVIF_REQ_ST *pReq, W_ONVIF_ALARM_MD_ST *pAlarmMD);
int W_Subscription(W_ONVIF_REQ_ST *pReq, W_ONVIF_EVENT_SUB_ST *pEventSub);
int W_DeleteSubscription(W_ONVIF_REQ_ST *pReq, W_ONVIF_EVENT_SUB_ST *pEventSub);
int W_GetRelayOutput(W_ONVIF_REQ_ST *pReq, W_ONVIF_ALARM_IO_ST *ptAlarmIO);
int W_SetRelayOutput(W_ONVIF_REQ_ST *pReq, W_ONVIF_ALARM_IO_ST *ptAlarmIO);
int W_SetRelayOutputState(W_ONVIF_REQ_ST *pReq, W_ONVIF_ALARM_IO_STATE_ST *ptAlarmIOState);

int W_PostMsgToServer(const char *ps8Msg);
int W_GetNetworkInfo(W_ONVIF_NET_INFO_ST *ptNetInfo, W_ONVIF_DNS_ST *ptDNSInfo);
int W_SetNetworkInfo(W_ONVIF_NET_INFO_ST *ptNetInfo, W_ONVIF_DNS_ST *ptDNSInfo);
int W_GetSysNTPInfo(W_ONVIF_NTP_ST *ptNTP);
int W_SetSysNTPInfo(W_ONVIF_NTP_ST *ptNTP);
int W_GetRecordingSummary(int s32ChnId, W_ONVIF_RECORD_ST *ptRecord);
int W_GetSysTime(W_ONVIF_TIME_ST *ptTime);
int W_SetSysTime(W_ONVIF_TIME_ST *ptTime);

#ifdef __cplusplus
}
#endif

#endif

