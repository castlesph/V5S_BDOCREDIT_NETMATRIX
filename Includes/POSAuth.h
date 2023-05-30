
#ifndef ___POS_AUTH___
#define ___POS_AUTH___

int inCTOS_PREAUTH(void);
int inCTOS_PreAuthFlowProcess(void);
int inModifyTIDMID_DCC(void);

extern void vdCTOSS_SetWaveTransType(int type);
extern ULONG inCTOSS_CLMOpenAndGetVersion(void);
extern void vdCTOSS_CLMClose(void);


#endif //end ___POS_AUTH___

