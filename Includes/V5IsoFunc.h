/* 
 * File:   V5IsoFunc.h
 * Author: Administrator
 *
 * Created on 2012年8月6日, 下午 9:23
 */

#ifndef V5ISOFUNC_H
#define    V5ISOFUNC_H

#ifdef    __cplusplus
extern "C" {
#endif

#include "../Includes/POSTypedef.h"
#include "../Includes/ISOEnginee.h"


#define BIT_MAP_MAX_ARRAY    	30

#define BIT_MAP_SIZE        	8

#define ISO_SEND_SIZE       	2048
#define ISO_REC_SIZE        	2048


//BDO: Revised reversal function - start -- jzg
#define PRE_TXN 0
#define POST_TXN 1
//BDO: Revised reversal function - end -- jzg


/* POC: 2 dip online pin - start -- jzg*/
#define RESP_DO_ONLINE_PIN "70"
/* POC: 2 dip online pin - end -- jzg*/


void vdDispTextMsg(char *szTempMsg);
void vdDecideWhetherConnection(TRANS_DATA_TABLE *srTransPara);
int inBuildAndSendIsoData(void);
int inSaveReversalFile(TRANS_DATA_TABLE *srTransPara, int inTransCode);
int inSnedReversalToHost(TRANS_DATA_TABLE *srTransPara, int inTransCode, short shTxnFlag);
int inProcessReversal(TRANS_DATA_TABLE *srTransPara, short shTxnFlag); //BDO: Revised reversal function -- jzg
int inProcessAdviceTrans(TRANS_DATA_TABLE *srTransPara, int inAdvCnt);
int inProcessEMVTCUpload(TRANS_DATA_TABLE *srTransPara, int inAdvCnt);
int inPackSendAndUnPackData(TRANS_DATA_TABLE *srTransPara, int inTransCode);
int inBuildOnlineMsg(TRANS_DATA_TABLE *srTransPara);
int inBuildDCCOnlineMsg(TRANS_DATA_TABLE *srTransPara);
int inSetBitMapCode(TRANS_DATA_TABLE *srTransPara, int inTransCode);
int inPackMessageIdData(int inTransCode, unsigned char *uszPackData, char *szMTI);
int inPackPCodeData(int inTransCode, unsigned char *uszPackData, char *szPCode);
void vdModifyBitMapFunc(int inTransCode, int *inBitMap);
int inCheckIsoHeaderData(char *szSendISOHeader, char *szReceISOHeader);
int inSendAndReceiveFormComm(TRANS_DATA_TABLE* srTransPara,
                                unsigned char* uszSendData,
                                 int inSendLen,
                                unsigned char* uszReceData);
int inProcessOfflineTrans(TRANS_DATA_TABLE *srTransPara);
int inAnalyseIsoData(TRANS_DATA_TABLE *srTransPara);

int inCheckHostRespCode(TRANS_DATA_TABLE *srTransPara);
int inCheckTransAuthCode(TRANS_DATA_TABLE *srTransPara);

int inAnalyseChipData(TRANS_DATA_TABLE *srTransPara);
int inAnalyseNonChipData(TRANS_DATA_TABLE *srTransPara);

int inAnalyseReceiveData(void);
int inAnalyseAdviceData(int inPackType);
void vdDiapTransFormatDebug(unsigned char *bSendBuf, int inSendLen);
int inPorcessTransUpLoad(TRANS_DATA_TABLE *srTransPara);

int inPackIsoFunc02(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc03(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc04(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc06(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc07(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc11(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc12(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc13(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc14(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc22(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc23(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc24(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc25(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc35(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc37(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc38(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc39(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc41(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc42(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc45(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc48(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc49(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc51(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc52(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc54(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc55(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc56(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc57(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc60(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc61(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc62(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc63(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inPackIsoFunc64(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData);
int inUnPackIsoFunc02(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inUnPackIsoFunc11(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inUnPackIsoFunc12(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inUnPackIsoFunc13(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inUnPackIsoFunc37(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inUnPackIsoFunc38(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inUnPackIsoFunc39(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inUnPackIsoFunc41(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inUnPackIsoFunc48(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inUnPackIsoFunc55(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inUnPackIsoFunc57(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inUnPackIsoFunc61(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inUnPackIsoFunc63(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inPackISOEMVData(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inPackISOPayWaveData(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inPackISOPayPassData(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inCTOS_PackDemoResonse(TRANS_DATA_TABLE *srTransPara,unsigned char *uszRecData);

void vdInitialISOFunction(ISO_FUNC_TABLE *srPackFunc);
int inBaseRespValidation(TRANS_DATA_TABLE *srOrgTransPara,TRANS_DATA_TABLE *srTransPara);
int inCTOS_DialBackupConfig(int shHostIndex);

/*albert - start - July2014 - EFTSEC Server*/
//int inEFTSecEncrypt(TRANS_DATA_TABLE *srTransPara, unsigned char *uszSendData, int *inSendLen);
//int inEFTSecDecrypt(TRANS_DATA_TABLE *srTransPara, unsigned char *uszReceiveData, unsigned char *szErrResponse);
/*albert - end - July2014 - EFTSEC Server*/


//gcitra
//int inDisconnectIfNoPendingADVICEandUPLOAD(TRANS_DATA_TABLE *srTransPara, int inAdvCnt);
//gcitra


/* CTLS: AMEX ExpressPay 3.0 requirement -- jzg */
int inPackISOExpressPayData(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);

int inBDOAutoReversal(TRANS_DATA_TABLE *srTransPara, short shTxnFlag); //BDO: Revised reversal function -- jzg
extern int inCTOS_CommsFallback(int shHostIndex);
extern int inPrintISOPacket(unsigned char *pucTitle,unsigned char *pucMessage, int inLen);
extern int inCTOSS_ISOEngCheckEncrypt(IN int inHDTid, INOUT unsigned char *uszISOData, INOUT int *inISOLen);
extern int inCTOSS_PackIsoDataNoEncryp(int inHDTid, unsigned char *szTPDU, unsigned char *uszSendData, int inTransCode);

void inGetDateAndTime(void);
int inSaveAmexData(void);
BOOL fReversalExist(void);
int inPOSTErrorMessage(void);

int inDisconnectVoidIfNoPendingADVICEandUPLOAD(TRANS_DATA_TABLE *srTransPara, int inAdvCnt);

char *UnpackDCC(char *ptrBitmap, char *ptrBuf);
#define RATE_RESPONSE_FULL "\x01\x70\x37\x31\x30\x30\x39\x63\x66\x34\x63\x32\x64\x64\x34\x38\x66\x34\x63\x32\x30\x38\x34\x35\x37\x32\x35\x32\x38\x30\x30\x31\x33\x36\x30\x35\x30\x30\x20\x20\x20\x20\x20\x20\x20\x20\x31\x31\x31\x32\x33\x34\x35\x36\x37\x38\x39\x31\x30\x30\x33\x36\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x34\x37\x32\x38\x30\x30\x31\x38\x34\x38\x39\x34\x33\x32\x30\x32\x30\x31\x32\x30\x39\x32\x32\x31\x32\x32\x38\x31\x38\x33\x35\x36\x30\x33\x36\x56\x53\x41\x64\x64\x37\x35\x34\x30\x38\x34\x39\x35\x35\x36\x30\x30\x38\x34\x35\x37\x32\x35\x32\x38\x30\x30\x31\x33\x36\x30\x35\x30\x32\x20\x20\x20\x20\x20\x20\x20\x20\x30\x30\x30\x30\x30\x31\x41\x55\x44\x34\x38\x33\x2E\x30\x32\x20\x20\x20\x20\x20\x30\x33\x36"
extern char bitDCC[32][36+1];
extern int inDCCLen[32+1];

void vdIncSTAN(TRANS_DATA_TABLE *srTransPara);

int inProcessTransLogTrans(TRANS_DATA_TABLE *srTransPara, int inAdvCnt, int inRetry, int inMode);

int inSMACUnPackIsoFunc60(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
void vdDisplayErrorMsg86(void);
int inSMACBDORewardsAnalyzeField63(void);

int inProcessEMVTCUpload_Settlement(TRANS_DATA_TABLE *srTransPara, int inAdvCnt);
int inProcessEMVTCUpload_PreAuthDCC(TRANS_DATA_TABLE *srTransPara, int inAdvCnt);
//int inProcessReversalEx(TRANS_DATA_TABLE *srTransPara, short shTxnFlag);

int inPackISODPasData(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);
int inSMACUnPackIsoFunc61(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);

#ifdef    __cplusplus
}
#endif

#endif    /* V5ISOFUNC_H */

