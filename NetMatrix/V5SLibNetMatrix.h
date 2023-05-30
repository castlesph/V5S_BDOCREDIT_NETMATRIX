
#ifndef _V5S_LIB_NMX_H_H
#define _V5S_LIB_NMX_H_H


#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef INOUT
#define INOUT
#endif


#define     NMX_OK                      0

#define     NMX_INVALID_PARA        -100
#define     NMX_CAL_MAC_ERR         -101
#define     NMX_ENCRYPT_ERR         -102
#define     NMX_INVALID_ISO         -103
#define     NMX_DECRYPT_ERR         -104
#define     NMX_WRONG_MAC           -105
#define     NMX_FUNCTION_NOT_INIT  -106
#define     NMX_CANCEL               -107
#define     NMX_SEND_DATA_ERR       -108
#define     NMX_RECV_DATA_ERR       -109
#define     NMX_INVALID_RESP        -110
#define     NMX_GET_TSK_ERR         -111
#define     NMX_GET_APPKEY_ERR      -112
#define     NMX_MULTI_AUTH_ERR      -113
#define     NMX_WRONG_PIN            -114
#define     NMX_AUTH_SESSION_ERR    -115
#define     NMX_STORE_KEY_ERR       -116
#define     NMX_DESTROY_KEY_ERR     -117
#define     NMX_SC_SELECTAPP_ERR    -118


#define     NMX_HOST_REJECT         -200

typedef struct
{
    void (*vdEnterSmartCardPIN)(unsigned char *);
    void (*vdEnterSmartCardNewPIN)(unsigned char *);
    int (*inSendData)(void *, unsigned char *, unsigned long );
    int (*inRecData)(void *, unsigned char *);
    
} NMX_FUNC_TABLE;



#define DB_NMX_LIB "/home/ap/pub/NMX.S3DB"


NMX_FUNC_TABLE* vdGetNMX_FUNC_TABLEAddress(void);
int inCTOSS_NMX_Read(int inSeekCnt);
int inCTOSS_NMX_Save(int inSeekCnt);
int inCTOSS_NMX_RKIKeyInjection(IN unsigned char *szTPDU, IN unsigned long ulTraceNO, IN unsigned char *szTID, IN unsigned char *szMID, OUT char *szErrResponse);
int inCTOSS_NMX_TLEDownload(IN int inHDTid, IN unsigned char *szTPDU, IN unsigned long ulTraceNO, IN unsigned char *szTID, IN unsigned char *szMID, OUT char *szErrResponse);
int inCTOSS_NMX_ChangeSamrtCardPIN(OUT char *szErrResponse);
int inCTOSS_NMX_DestroyKeys(void);
int inCTOSS_NMX_ProcessSendData(IN int inHDTid, 
                                            INOUT unsigned char *pstReqBuf, INOUT unsigned int *inReqSiz);
int inCTOSS_NMX_ProcessRecvData(IN int inHDTid, 
                                            IN unsigned char *szSensitiveBitmap,
                                            INOUT unsigned char *pstReqBuf, INOUT unsigned int *inReqSiz, 
                                            OUT char *szErrResponse);

int inCTOSS_NMX_ProcessTLEDownloadSendData(IN int inHDTid, 
                                            IN unsigned char *szSensitiveBitmap,
                                            INOUT unsigned char *pstReqBuf, INOUT unsigned int *inReqSiz);



int inCTOSS_NMX_ProcessTLEDownloadRecvData(IN int inHDTid, 
                                            IN unsigned char *szSensitiveBitmap,
                                            INOUT unsigned char *pstReqBuf, INOUT unsigned int *inReqSiz, 
                                            OUT char *szErrResponse);




#endif

