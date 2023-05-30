
#ifndef ___POS_LOGON___
#define ___POS_LOGON___

int inCTOS_LogonFlowProcess(void);
int inCTOS_LOGON(void);
int inCTOS_SelectDebitHost(void);
int inCTOS_DoAutoLogon(void);
int inCTOS_SelectLogonIIT(void);
int inCTOS_SeletLogonPIT(void);

extern int inHDTRead(int inSeekCnt);
extern int inCPTRead(int inSeekCnt);
extern int inCSTRead(int inSeekCnt);
extern int inPITRead(int inSeekCnt);
extern int inMultiAP_CheckMainAPStatus(void);
extern int inMultiAP_CheckSubAPStatus(void);

#endif //end ___POS_SALE___

