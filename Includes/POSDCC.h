
#ifndef ___POS_DCC___
#define ___POS_DCC___
#define AVAILABILITY	0
#define	GET_PAYMENT_SIGNATURE	1
#define DCC_RATE	4
#define ERR_ENC_INSUFF_BUFFER		-1101
#define CARRIER_FIELD_SZ		512
#define XX 127

/* Tables for encoding/decoding Base 64 */
static const char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char index_64[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,XX,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};
#define CHAR64(c)  (index_64[(unsigned char)(c)])

int inProcessRequestDCC(void);
int inCTOS_ProcessDCCRate(void);
int inSendPendingDCCLogs(void);
int inVoidDCCTransaction(void);
int inRevertToPHP(void);
int inCTOS_DCCOptOut(void);
int inDCCOptOutFlowProcess(void);
int inCTOS_ConfirmOptOutInvAmt(void);
int inCTOS_CheckOptOut(void);

extern int inHDTRead(int inSeekCnt);
extern int inCPTRead(int inSeekCnt);
extern int inCSTRead(int inSeekCnt);
extern int inPITRead(int inSeekCnt);
extern int inMultiAP_CheckMainAPStatus(void);
extern int inMultiAP_CheckSubAPStatus(void);
int inDCCSignPadBody(char *szBuffer, int inType);
int inDCCSignPad_InitCOM(BYTE bCommPort);
int inSignPadSendReceive(BYTE COMMPort, int inType);
void vdGetDCCSignatureFilename(char *ptrNewFilename);
void vdLinuxCommandClearDCCPNG(void);
int inDetectSignPad(BYTE COMMPort);

#endif 

