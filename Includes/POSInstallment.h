
#ifndef ___POS_INSTALLMENT___
#define ___POS_INSTALLMENT___

int inCTOS_InstallmentFlowProcess(void);
int inCTOS_INSTALLMENT(void);

extern ULONG inCTOSS_CLMOpenAndGetVersion(void);
extern void vdCTOSS_CLMClose(void);
int inCheckInstallmentEMVEnable(void);
void vdInstallmentPromptToSwipe(void);


//gcitra
//int inGetPolicyNumber(void);
//gcitra

#endif //end ___POS_SALE___

