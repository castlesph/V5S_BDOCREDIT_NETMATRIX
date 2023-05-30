/* 
 * File:   V5Comm.h
 * Author: sam
 *
 * Created on 2012年8月11日, 下午 12:56
 */

#ifndef V5COMM_H
#define    V5COMM_H

#ifdef    __cplusplus
extern "C" {
#endif

#include "../Includes/POSTypedef.h"
    
#define IPCONFIG_STATIC 0
#define IPCONFIG_DHCP 1    
#define BROKEN_PIPE			32		/* Broken pipe */    
    

typedef struct
{
    BOOL boSave;            // Save all setting to module or end of information retrieve on Ethernet module

    STR    strRemoteIP[24];    // Remote IP address
    USHORT usRemotePort;    // Remote port number

    STR    strLocalIP[24];     // Local IP address

    BYTE strMask[24];       // Network mask
    BYTE strGateway[24];    // Gateway address

    BYTE bDHCP;             // IP configuration
    BYTE bAutoConn;         // Connection mode

    BYTE* pbRxStack;        // The pointer to Received stack

    // For configurations getting
    BYTE strVersion[17];    // The version of Ethernet chip
    BYTE strMac[24];        // MAC address
}CTOS_CM_ETHERNET;


typedef struct
{
    BYTE bMode;                        // The mode of Modem connection
    BYTE bHandShake;                // The handshakes of modem connection
    BYTE bCountryCode;                // Country Code

    STR    strRemotePhoneNum[32];        // The dial number

    USHORT usDialDuration;            // Dialing maximum total duration in second. Range: 0~255

    USHORT usHookDuration;            // Minimum on-hook duration in second. Range: 0~255

    USHORT usPreDialDelayTime;        // Pre-dial delay time in ms.

    USHORT usDialToneDetectDuration;    // Dial tone detect duration in ms.
    USHORT usDialToneMinOnTime;        // Dial tone minimum on time in 1 / 7200 second.

    USHORT usDTMFOnTime;            // DTMF on time in ms.
    USHORT usDTMFOffTime;            // DTMF off time in ms.

    USHORT usBusyToneMinTotalTime;    // Busy tone minimum total time in 1 / 7200 second (=Buy Tone Minimum On Time + Buy Tone Minimum Off Time).
    USHORT usBusyToneDeltaTime;        // Busy tone delta time in 1 / 7200 second (=Busy Tone Maximum Total Time + Busy Tone Minimum Total Time).
    USHORT usBusyToneMinOnTime;        // Busy tone minimum on time in 1 / 7200 second.

    USHORT usRingBackToneMinTotalTime;    // Ring back tone minimum total time in 1 / 7200 second (=ring back tone minimum on time + Ring back tone minimum off Time).
    USHORT usRingBackToneDeltaTime;        // Ring back tone delta time in 1 / 7200 second (=ring back tone maximum total time + Ring back tone minimum total time).
    USHORT usRingBackToneMinOnTime;        // Ring back tone minimum on time (in 1 / 7200 second).

    USHORT usAnswerToneWaitDuration;    // Ring back wait duration in second. Range: 0~255

    USHORT usBlindDialDelayTime;        // Blind dial (no detect dial tone) delay time (in second). Range: 0~255

    USHORT usCarrierPresentTime;        // Carrier presence time in 100ms. Range: 1~255

    BYTE* pbRxStack;                    // The pointer to Received stack
}CTOS_CM_MODEM;




typedef struct comm_struct
{
    int (*inInitComm)(TRANS_DATA_TABLE *, int);
    int (*inGetCommConfig)(TRANS_DATA_TABLE *);
    int (*inSetCommConfig)(TRANS_DATA_TABLE *);
	int (*inCheckComm)(TRANS_DATA_TABLE *);
    int (*inConnect)(TRANS_DATA_TABLE *);
    int (*inDisconnect)(TRANS_DATA_TABLE *);
    int (*inSendData)(TRANS_DATA_TABLE *, unsigned char *, unsigned long );
    int (*inRecData)(TRANS_DATA_TABLE *, unsigned char *);
    int (*inEndComm)(TRANS_DATA_TABLE *);

} COMM_FUNC_OBJECT;


CTOS_CM_ETHERNET    srEthernetRec; 
CTOS_CM_MODEM       srModemRec; 
COMM_FUNC_OBJECT    srCommFuncPoint;



ULONG ulStrToLong(IN BYTE *baStr);
USHORT ushStrToShort(IN BYTE *baStr);
BYTE bUnSingeLongToStr(IN ULONG ulValue, OUT BYTE *baStr);
int inInitConnectFuncPoint(TRANS_DATA_TABLE *srTransPara);
int inModem_InitModem(TRANS_DATA_TABLE *srTransPara,int mode);
int inModem_GetConfigFromTable(TRANS_DATA_TABLE *srTransPara);
int inModem_SetConnectConfig(TRANS_DATA_TABLE *srTransPara);
int inModem_CheckComm(TRANS_DATA_TABLE *srTransPara);
int inModem_ConnectHost(TRANS_DATA_TABLE *srTransPara);
int inModem_Disconnection(TRANS_DATA_TABLE *srTransPara);
int inModem_SendData(TRANS_DATA_TABLE *srTransPara,unsigned char *uszSendData,unsigned long ulSendLen);
int inModem_ReceiveData(TRANS_DATA_TABLE *srTransPara,unsigned char *uszRecData);
int inModem_CutOffConnection(TRANS_DATA_TABLE *srTransPara);
int inModem_ReConnectHost(TRANS_DATA_TABLE *srTransPara);


int inEthernet_InitEthernet(TRANS_DATA_TABLE *srTransPara,int mode);
int inEthernet_GetConfigFromTable(TRANS_DATA_TABLE *srTransPara);
int inEthernet_SetConnectConfig(TRANS_DATA_TABLE *srTransPara);
int inEthernet_CheckComm(TRANS_DATA_TABLE *srTransPara);
int inEthernet_ConnectHost(TRANS_DATA_TABLE *srTransPara);
int inEthernet_Disconnection(TRANS_DATA_TABLE *srTransPara);
int inEthernet_SendData(TRANS_DATA_TABLE *srTransPara,unsigned char *uszSendData,unsigned long ulSendLen);
int inEthernet_ReceiveData(TRANS_DATA_TABLE *srTransPara,unsigned char *uszRecData);
int inEthernet_CutOffConnection(TRANS_DATA_TABLE *srTransPara);

int inGPRS_InitGPRS(TRANS_DATA_TABLE *srTransPara,int mode);
int inGPRS_GetConfigFromTable(TRANS_DATA_TABLE *srTransPara);
int inGPRS_SetConnectConfig(TRANS_DATA_TABLE *srTransPara);
int inGPRS_CheckComm(TRANS_DATA_TABLE *srTransPara);
int inGPRS_ConnectHost(TRANS_DATA_TABLE *srTransPara);
int inGPRS_Disconnection(TRANS_DATA_TABLE *srTransPara);
int inGPRS_SendData(TRANS_DATA_TABLE *srTransPara,unsigned char *uszSendData,unsigned long ulSendLen);
int inGPRS_ReceiveData(TRANS_DATA_TABLE *srTransPara,unsigned char *uszRecData);
int inGPRS_CutOffConnection(TRANS_DATA_TABLE *srTransPara);


int incommGPRSCheckState(USHORT RET, int TimeOutValue);
void vdcommGPRSDisplyState(DWORD State);
int inGPRS_GetConfigFromTable(TRANS_DATA_TABLE *srTransPara);
int inCTOS_InitComm(int inCommType);
int inCTOS_CheckInitComm(int inCommType);
int inCTOS_inDisconnect(void);

int inFirstInitConnectFuncPoint(void);
int inDummyFlow(TRANS_DATA_TABLE *srTransPara);


USHORT incommSignal(void);

//sidumili: added
void vdCTOS_DispStatusMessage(char* szMsg);

extern int inCTOS_PreConnect(void);

void vdCTOS_MultiLineDisplayMessage(char *szLine1Msg, char *szLine2Msg, char *szLine3Msg); /*BDO: Display 3 lines of message, disappear both display immediately -- sidumili*/
int inCheckLAN(void);
int inModem_ReceiveData_New(TRANS_DATA_TABLE *srTransPara,unsigned char *uszRecData);
int inCheckEthernetSocketConnected(void);
int inCheckConnection(void); /*currently for IP only*/
int inCheckModemConnected(void);


#ifdef    __cplusplus
}
#endif

#endif    /* V5COMM_H */

//version16
int inEthernet_GetTerminalMac(char *szTerminalMac);
//version16

