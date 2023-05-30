
#ifndef ___POS_SALE___
#define ___POS_SALE___

int inCTOS_SaleFlowProcess(void);
int inCTOS_SALE(void);

void vdSetATPBinRouteFlag(int flag);
int inGetATPBinRouteFlag(void);

int inCTOSS_ATPBinRoutingProcess(void);
int inCTOSS_ATPBinRoutingProcessCompCheck(void);

//gcitra
int inGetPolicyNumber(void);
//gcitra

void inGetDateAndTime();

#endif //end ___POS_SALE___

