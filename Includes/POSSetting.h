#ifndef ___POS_SETTING_H___
#define ___POS_SETTING_H___

#define STR_HEAD            0
#define STR_BOTTOM          1
#define STR_ALL             2


void vdCTOS_uiPowerOff(void);
void vdCTOS_IPConfig(void);
int inCTOS_SelectHostSetting(void);
void vdCTOS_DialConfig(void);
int vdCTOS_ModifyEdcSetting(void);
void vdCTOS_DeleteBatch(void);
void vdCTOS_DeleteReversal(void);

void vdCTOS_PrintEMVTerminalConfig(void);
void vdCTOS_GPRSSetting(void);
void vdCTOS_Debugmode(void);
void vdCTOSS_CtlsMode(void);
void vdCTOS_TipAllowd(void);
void vdCTOS_DemoMode(void);
void DelCharInStr(char *str, char c, int flag);
void vdConfigEditAddHeader(void);
void vdCTOSS_DownloadMode(void);
void vdCTOSS_CheckMemory(void);
void CTOSS_SetRTC(void);
int inCTOSS_GetCtlsMode(void);

//gcitra
int inCTOS_DialBackupConfig(int shHostIndex);
//gcitra
/*albert - start - August2014 - manual settlement*/
int inCTOS_ManualSettle(void);
/*albert - end - August2014 - manual settlement*/
//VS_BOOL fGPRSSetting;
//0901

int inCTOS_CommsFallback(int shHostIndex);
void vdCTOS_ThemesSetting(void);


/*sidumili: Issue#:000087 [prompt password]*/
int inCTOS_PromptPassword(void);
void vdCTOSS_EditTable(void);

//--Inject Key
void vdCTOSS_InjectMKKey(void);

//BDO UAT 0007: Change comms shortcut - start -- jzg
void vdChangeComms(void);

//BDO: [Restart] -- sidumili
void vdCTOS_uiRestart(BOOL fConfirm);

//BDO: [Select Telco Setting] -- sidumili
int inSelectTelcoSetting(void);


extern int inCTOSS_GetCtlsMode(void);
extern int inCTOS_SettlementClearBathAndAccum(BOOL fManualSettlement);
extern void vdSetGolbFontAttrib(USHORT FontSize,USHORT X_Zoom,USHORT Y_Zoom,USHORT X_Space,USHORT Y_Space);
extern int inCTOS_IdleEventProcess(void);
extern int inCTOS_ChkBatchEmpty(void);


/* BDO CLG: Revised menu functions -- jzg */
void vdDisplaySetup(void);


/* BDO: Manual settlement prompt after failed settlement -- jzg */
int inBDOManualSettle();

void put_env_int(char *tag, int value);
int get_env_int (char *tag);

void vdCTOS_PrintISOMode(void); //aaronnino for BDOCLG ver 9.0 fix on issue #0073 No terminal function for enable/disable on ISO packet 3 of 3

void vdCTOS_TMSReSet(void);
void vdCTOS_TMSSetting(void);
int  inCTOS_TMSPreConfigSetting(void);

void vdChangeLockPassword(); /* BDOCLG-00131: Separate password for lock screen -- jzg */
int inAutoManualSettle(); //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed 
void vdCTOSS_SelectPinpadType(void);
void vdCTOS_EditEnvParamDB(void);
void vdCTOS_ModemReceivingTime(void);
void vdCTOS_BINRouting(void);
void vdSetECRConfig(void); /*ECR Configuration -- sidumili*/
void vdCTOS_SMFunctionKey(void);
int inECRLogMenu(void);
int inCTOS_SelectHostSettingWithIndicator(int inIndicator);
void vdCTOS_PingIPAddress(void);
void vdCTOS_ISOLogger(void);
void put_env_char(char *tag, char *value);

//powersave
void vdCTOS_uiIDLESleepMode(void);
int inCTOSS_CheckBatteryChargeStatus(void);
void vdCTOS_uiIDLEWakeUpSleepMode(void);
//powersave

void vdCTOS_TMSRangeSetting(void);
int inCTOS_vdSetDCCMode(void);
int inCTOS_SelectPreAuthHostSettingWithIndicator(int inIndicator);
void put_env_charEx(char *tag, char *value);
int inCTOS_ADC_ERM_DeInit(void);



#endif //end ___POS_SETTING_H___
	
