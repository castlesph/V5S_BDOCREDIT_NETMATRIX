
#ifndef ___POS_BINVER___
#define ___POS_BINVER___

int inCTOS_BINCheckFlowProcess(void);
int inCTOS_BINCHECK(void);
int inCTOS_GetBINVerData(void);
int inCTOS_ProceedToSale(void);
int inUnPackBINVer63(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);


int inCTOS_INSTBINCHECK(void);
int inCTOS_INSTBINCheckFlowProcess(void);

char szField63[999];
char szField60[999];
char szField61[999];

extern int inCTOS_WaveFlowProcess(void);
extern void vdCTOSS_SetWaveTransType(int type);
extern ULONG inCTOSS_CLMOpenAndGetVersion(void);
extern void vdCTOSS_CLMClose(void);
extern int inCTOS_InstallmentFlowProcess(void);
int  inCheckIfFleetCard(void);



#endif //end ___POS_SALE___

