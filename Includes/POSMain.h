
#ifndef ___POS_MAIN_H___
#define ___POS_MAIN_H___


int inCTOS_DisplayIdleBMP(void);
int inCTOS_DisplayComTypeICO(void);
int inCTOS_ValidFirstIdleKey(void);
BYTE chGetFirstIdleKey(void);
void vdSetFirstIdleKey(BYTE bFirstKey);
int inCTOS_IdleEventProcess(void);
int inCTOSS_InitAP(void);

int inDoAutosettlement(void);

extern int inCTOSS_GetCtlsMode(void);
int inCTOS_InitWIFI(void);

//smac
BOOL fSMACTRAN;
BOOL fAdviceTras;
//smac


/* BDO: Terminal screen lock -- jzg */
int inDisplayLockScreen(void);
void vdCTOSS_ClearTouchPanelTest(void); 

//powersave
int inCTOSS_JumpToSleepMode(void);
void vdSetIdleEvent(BYTE bIdleEvent);
BYTE chGetIdleEvent(void);
//powersave
void vdSetGPRSResetTimeOut(int bTimeOut);
int chGetGPRSResetTimeOut(void);
int inDimScreen(void);
vdMenuOverwrite(void);



#endif //end ___POS_MAIN_H___

