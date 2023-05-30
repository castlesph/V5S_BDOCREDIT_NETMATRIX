/* 
 * File:   TransFunc.h
 * Author: Administrator
 *
 * Created on 2012年8月23日, 下午 6:35
 */

#ifndef TRANSFUNC_H
#define	TRANSFUNC_H
//aaa fix on issue #000210 Terminal displays "Batch empty, skip" on all hosts when trying to settle hosts with no transactions 6 of 6 start
#define SINGLE_SETTLE 0
#define MULTI_SETTLE 1
//aaa fix on issue #000210 Terminal displays "Batch empty, skip" on all hosts when trying to settle hosts with no transactions 6 of 6 end

#ifdef	__cplusplus
extern "C" {
#endif
//format amount 10+2 change all ULONG to DOUBLE
#define DOUBLE   double        		 // 8byte

typedef struct  
{
    USHORT usSaleCount;
    DOUBLE  ulSaleTotalAmount;
    USHORT usRefundCount;
    DOUBLE  ulRefundTotalAmount;
    USHORT usTipCount;
    DOUBLE  ulTipTotalAmount;   
    USHORT usVoidSaleCount;
    DOUBLE  ulVoidSaleTotalAmount;
    USHORT usOffSaleCount;
    DOUBLE  ulOffSaleTotalAmount; 
	//1105
	USHORT usCashAdvCount;
	DOUBLE  ulCashAdvTotalAmount;

	USHORT usVoidCashAdvCount;
    DOUBLE ulVoidCashAdvTotalAmount;

	DOUBLE ulLocalSaleTotalAmount;
    DOUBLE ulLocalRefundTotalAmount;
    DOUBLE ulLocalTipTotalAmount;   
    DOUBLE ulLocalVoidSaleTotalAmount;
    DOUBLE ulLocalOffSaleTotalAmount; 
	DOUBLE ulLocalCashAdvTotalAmount;
    DOUBLE ulLocalVoidCashAdvTotalAmount;
	USHORT usPreAuthCount;
	DOUBLE ulPreAuthTotalAmount;
	USHORT usKitSaleCount;
	DOUBLE ulKitSaleTotalAmount;
	USHORT usRenewalCount;
	DOUBLE ulRenewalTotalAmount;
	USHORT usPtsAwardCount;
	DOUBLE ulPtsAwardTotalAmount;
	//1105
}STRUCT_TOTAL;


#define MAX_ISSUERS		103


typedef struct
{
    STRUCT_TOTAL stCardTotal[MAX_ISSUERS];
    STRUCT_TOTAL stHOSTTotal;
    USHORT usEMVTCCount;
}TRANS_TOTAL;


BYTE szOriginTipTrType;


typedef struct
{
    STRUCT_TOTAL stSettledCardTotal[10];
    BYTE	szSettledCardLabel[10][25] ;
    BYTE        szSettledDate[3+1];
    BYTE	szSettledBatchNo[3+1];
    BYTE        szSettledTime[3+1];
    BYTE	szSettledHostLabel[16] ;
    BYTE	szSettledMID[15+1];
    BYTE	szSettledTID[8+1];
}SETTLEDTRANS_TOTAL;



#ifdef	__cplusplus
}
#endif

#endif	/* TRANSFUNC_H */

