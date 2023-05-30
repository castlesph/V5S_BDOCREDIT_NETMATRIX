
#ifndef _DATABASEDCCFUNC__H
#define	_DATABASEDCCFUNC__H

#ifdef	__cplusplus
extern "C" {
#endif

#include "../Includes/POSTypedef.h"
#include "../FileModule/myFileFunc.h"

int inDatabase_TransLogSave(TRANS_DATA_TABLE *transData);
int inDatabase_TransLogNumRecord(int inMode);
int inDatabase_TransLogDelete(TRANS_DATA_TABLE *transData, int inMode);
int inDatabase_TransLogGetTransId(TRANS_DATA_TABLE *transData, int inTranID[], int inMode);
int inDatabase_TransLogReadByTransId(STRUCT_ADVICE *strAdvice, int inTransDataid);
int inDatabase_TransLogRead(int inTransDataid, STRUCT_ADVICE *strAdvice, TRANS_DATA_TABLE *transData);
int inDatabase_TransLogUpdatePackType(TRANS_DATA_TABLE *transData);

#endif	/* _DATABASEDCCFUNC__H */

