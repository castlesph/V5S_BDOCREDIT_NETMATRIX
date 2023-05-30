
#ifndef ISOENGINEE_H
#define ISOENGINEE_H


#define CTOSS_BIT_MAP_MAX_ARRAY    64

#define ISO_DATA_ASC      		1 /* a */
#define ISO_DATA_BCD      		2
#define ISO_DATA_NIBBLE_2 		3 /* ..nibble */
#define ISO_DATA_NIBBLE_3 		4 /* ...nibble */
#define ISO_DATA_BYTE_2   		5 /* ..ans */
#define ISO_DATA_BYTE_3   		6 /* ...ans */
#define ISO_DATA_BYTE_2_H 		7 /* ..ans */
#define ISO_DATA_BYTE_3_H 		8 /* ...ans */
#define ISO_DATA_BFD 			99 /* ...BFD */

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef INOUT
#define INOUT
#endif

typedef struct
{
    int (*inPackMTI)(int , unsigned char *, char *);
    int (*inPackPCode)(int , unsigned char *, char *);
    void (*vdModifyBitMap)(int , int *);
    int (*inCheckISOHeader)(char *, char *);
    int (*inTransAnalyse)(void);
    int (*inAdviceAnalyse)(int);
} ISO_FUNC_TABLE;


int inCTOSS_PackIsoData(int inHDTid, unsigned char *szTPDU, unsigned char *uszSendData, int inTransCode);
int inCTOSS_UnPackIsodata(int inHDTid, unsigned char* uszSendData, int inSendLen, unsigned char *uszReceData, int inReceLen);
int inCTOSS_PackIsoDataUnionPay(int inHDTid, unsigned char *szISOHeader, unsigned char *szTPDU, unsigned char *uszSendData, int inTransCode);
int inCTOSS_UnPackIsodataUnionPay(int inHDTid, unsigned char *szRecvISOHeader, unsigned char *szSendMTI, unsigned char *szRecvdMTI, unsigned char* uszSendData, int inSendLen, unsigned char *uszReceData, int inReceLen);
int inCTOSS_CheckBitmapSetBit(BYTE bit);
void vdCTOSS_SetBitMapOff(int *inTransBitMap, int inBit);
void vdCTOSS_SetBitMapOn(int *inTransBitMap, int inBit);

int inCTOSS_PackIsoDataEx(IN int inHDTid, IN unsigned char *szTPDU, OUT unsigned char *uszSendData, IN int inTransCode);
int inCTOSS_UnPackIsodataEx(IN int inHDTid, IN unsigned char* uszSendData, IN int inSendLen, IN unsigned char *uszReceData, IN int inReceLen);
int* inCTOSS_GetBitMap(void);

int inCTOSS_GetISOFieldData(IN int inField, OUT unsigned char *szData, OUT int *inLen);
int inCTOSS_SetISOFieldData(IN int inField, IN unsigned char *szData, IN int inLen);
int inCTOSS_Process_8583_UnPack(IN int inHDTid, IN unsigned char *uszISOData, IN int inISOLen, OUT unsigned char *uszTPDU, OUT unsigned char *uszMTI, OUT unsigned char *uszBitmap);
int inCTOSS_Process_8583_Pack(IN int inHDTid, OUT unsigned char *uszISOData, OUT int *inISOLen, IN unsigned char *uszTPDU, IN unsigned char *uszMTI, IN unsigned char *uszBitmap);
#endif



