
#ifndef POSPOWRFAIL_H
#define POSPOWRFAIL_H

#include "../Includes/POSTypedef.h"


#define PFR_FIME_NAME	"powrfail.fail"


typedef enum
{
    PFR_IDLE_STATE	 = 0,
	PFR_BEGIN_SEND_ISO,
	PFR_BEGIN_BATCH_UPDATE,
    PFR_BATCH_UPDATE_COMPLETE,	  
    PFR_BATCH_SETTLEMENT_PRINT,//1204
}PFR_CODE_TABLE;



typedef struct TagPOWRFAIL_REC
{
	short inPowrfailtag;
	TRANS_DATA_TABLE srTransPowerRec;
	
} POWRFAIL_REC;

int inCTLOS_Updatepowrfail(short inPowrfailtag);
int inCTLOS_Getpowrfail(void);


#endif


