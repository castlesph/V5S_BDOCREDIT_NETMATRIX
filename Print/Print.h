/* 
 * File:   Print.h
 * Author: ASUS
 *
 * Created on 2012年8月25日, 上午 1:35
 */

#ifndef PRINT_H
#define	PRINT_H

#ifdef	__cplusplus
extern "C" {
#endif

#define d_LINE_DOT 12
#define d_LINE_SIZE 44
#define d_FIRST_PAGE 1
#define d_SECOND_PAGE 2
//1027
#define d_THIRD_PAGE 3

#define BANK_COPY_RECEIPT 1
#define CUSTOMER_COPY_RECEIPT 2
#define MERCHANT_COPY_RECEIPT 3

#define TTF_FONT_REGULAR			0
#define TTF_FONT_ITALIC			1
#define TTF_FONT_BOLD				2
#define TTF_FONT_BOLD_ITALIC		3


#define NORMAL_SIZE	1
#define DOUBLE_SIZE	2

#define PRINT_SALE_REPORT 0
#define PRINT_REFUNT_REPORT 1
#define PRINT_SETTLE_REPORT 2

#define DIVIDING_LINE 1
#define DIVIDING_LINE_DOUBLE 2    
    
#define PRINT_HOST_TOTAL 0
#define PRINT_CARD_TOTAL 1   

//0720
#define DETAIL_REPORT_TOTAL 2
#define DETAIL_REPORT_GRANDTOTAL 3
//0720

#define SETTLE_PRINT 1
#define TOTAL_REPORT 0

#define PRINT_CARD_MASKING_1 0
#define PRINT_CARD_MASKING_2 1
#define PRINT_CARD_MASKING_3 3
#define PRINT_CARD_MASKING_4 4
#define PRINT_CARD_MASKING_5 5

#define V3_DESKTOP 1
#define V3_MOBILE 2

#define DATE 1
#define TIME 2
#define DL_TIME_END 3

#define DB_SIGN_BMP "signtest.bmp"

#define ONE_LINE_DOT	"\n"

#define SINGE_HEADER_FOOTER_TEXT 

short printCheckPaper(void);  
USHORT printDateTime(void);
USHORT ushCTOS_printReceipt(void);
USHORT ushCTOS_PrintAgreement(void);
USHORT batchAllRecord(BOOL isPrint);
void vdPrintEMVTags(void);
void vdPrintCenter(unsigned char *strIn);
USHORT printBatchInvoiceNO(void);
void setTotalCountandAmountCardWise(int i);
void PrintTotalCountandAmountCardWise (int inReportType, USHORT usSaleCount, 
    ULONG ulSaleTotalAmount,    
    USHORT usSaleAloneCount,
    ULONG  ulSaleAloneTotalAmount,
    USHORT usRefundCount,
    ULONG  ulRefundTotalAmount,    
    USHORT usVoidSaleCount,
    ULONG  ulVoidSaleTotalAmount,
    USHORT usOffSaleCount,
    ULONG  ulOffSaleTotalAmount);

void vdPrintTitleCenter(unsigned char *strIn);
void vdPrintTerminalConfig(void);
void printCardHolderName(void);

USHORT ushCTOS_printAll(int page);
USHORT ushCTOS_PrintHeader(int page);
USHORT ushCTOS_PrintBody(int page);
USHORT ushCTOS_PrintFooter(int page);
int inCTOS_rePrintReceipt(void);
int inCTOS_PrintSettleReport(BOOL fManualSettlement);

USHORT ushCTOS_printReceipt(void);
int inCTOS_REPRINT_ANY(void);
int inCTOS_REPRINT_LAST(void);
int inCTOS_PRINTF_SUMMARY(void);
int inCTOS_PRINTF_DETAIL(void);
int inCTOS_REPRINTF_LAST_SETTLEMENT(void);


int inCTOS_rePrintLastReceipt(void);
void vdCTOS_PrintSummaryReport(void);
USHORT ushCTOS_printErrorReceipt(void);
USHORT ushCTOS_printBatchRecordHeader(void);
USHORT ushCTOS_printBatchRecordFooter(void);
USHORT ushCTOS_GetFontInfor(void);
USHORT ushCTOS_ReprintLastSettleReport(void);
void vdCTOSS_PrinterBMPPic(unsigned int usX,unsigned int y, const char *path);

void vdCTOS_HostInfo(void);
int inPrint(unsigned char *strPrint);


void vdCTOS_PrintAccumeByHostAndCard(int inReportType,
	USHORT usSaleCount, 
	double ulSaleTotalAmount,    
	USHORT usRefundCount,
	double ulRefundTotalAmount,    
	USHORT usVoidSaleCount,
	double ulVoidSaleTotalAmount,
	USHORT usOffSaleCount,
	double ulOffSaleTotalAmount,
	//1105
	USHORT usCashAdvCount,
	double ulCashAdvTotalAmount,
	USHORT usTipCount,
	double ulTipTotalAmount 
	//1105
);


int inCTOS_SelectFont(int inFontMode,int inFontSize ,int inFontStyle,char * szFontName);

extern void vdCTOS_Pad_String(char * str,int padlen,char padval,int padtype);
extern void vdComputeCRC(unsigned long lnCRC,char * ptrCRC);

//gcitra
USHORT ushCTOS_PrintCashLoyaltyBody(void);
int inPrintISOPacket(unsigned char *pucTitle,unsigned char *pucMessage, int inLen);

//gcitra
void vdCTOS_PrintManualPosting(void);
void vdCTOS_PrintCRC(void);

int inPrintLeftRight(unsigned char *strLeft, unsigned char *strRight, int inMode);
void cardMasking(char *szPan, int style);
void vdCTOSS_PrintFooterLogoBMPPic(unsigned int usX,unsigned int y, const char *path);

void vdBDO_PrintSettlementReportFooter(void);

int inPrintDebug(unsigned char *strPrint);
void vdCTOS_PrintDetailReportForManualSettlement(int shHostIndex);
void vdTrimSpaces(char* pchString);
void vdCTOS_PrintDetailTotals(void);
int inPrintLeftRight2(unsigned char *strLeft, unsigned char *strRight, int inMode); 

void vdRemoveSpace(char* szDestination, char* szSource);


/* BDO: Include detailed report to settlement receipt -- jzg */
void vdCTOS_PrintDetailReport(BOOL fAddtoSettleReport, BOOL fLastSettleReport);

//smac
USHORT ushCTOS_PrintSMACBody(int page);
//smac

int inPrint(unsigned char *strPrint);

void vdStrCat2(char szStr1[40], char szStr2[21], short shStr2Pos, char *szOutPut); /* BDOCLG-00134: Reformat cardtype line -- jzg */

int inCTOS_PRINT_DETAIL_ALL(void);
int inCTOS_PrintDetailAllOperation(void);
void vdCTOS_PrintDetailReportAll(void);

int inCTOS_PRINT_SUMMARY_ALL(void);
int inCTOS_PrintMerchantSummaryAllOperation(void);
void vdCTOS_PrintMerchantSummaryReportAll(void);
void vdCTOS_PrintMerchantSummaryReport(void);
void SetReportTime(void);
USHORT ushCTOS_PrintSMGuarantorBody(int page); /*BDO: For SM Guarantor -- sidumili*/

int inCTOS_PRINT_SUMMARY_SELECTION(void);
int inCTOS_PRINT_DETAIL_SELECTION(void);

void printCardHolderNameV10(void);	// v10.0 change
USHORT ushCTOS_PrintSMHeader(int page);
USHORT ushCTOS_PrintSMBody(int page);
USHORT ushCTOS_PrintSMFooter(int page);

void vdCTOS_PrintReceiptCopies(BOOL BankCopy, BOOL CustCopy, BOOL MercCopy, BOOL fERM);

void vdLineFeed(BOOL fFooterLogo);
void vdPrintHeaderText(void);
void vdPrintFooterText(void);	
void vdCTOS_PrintIP(void);

void vdCTOS_GetROOTFS(char* ucBuffer);
void vdCTOS_PrintRS232Report(void);
void vdPrintISOECRLog();

void vdPrintDCCFooter(void);
void vdDCCCenter(unsigned char *szLocCur, unsigned char *szForCur);
//void vdCTOS_DCCPrintAccumeByHostAndCard (int inReportType, STRUCT_TOTAL Totals);

void vdPrintISOLog(void);
USHORT ushCTOS_ReprintLastSettleReportAll(void);
void vdCTOS_SMHostInfo(void);

int ushCTOS_ePadSignature(void);
int ushCTOS_ePadPrintSignature(void);	
int ushCTOS_ClearePadSignature(void);
void vdPrintISOOption(unsigned char *pucTitle,unsigned char *uszData, int inLen);

void vdCTOS_PrintSettleMerchantDetailReport(void);
USHORT ushCTOS_ReprintBatchRecordHeader(void);
//void vdCTOS_SMInstallmentHostInfo(void);
int inSMACPrintField60(void);
void vdSetSMACFooterFontSize(int inFontSize,int inLineLen);
void vdSMACFooterPrintCenter(unsigned char *strIn);
USHORT printLastSettleDateTime(void);
USHORT printBatchInvoiceNOEx(void);
USHORT usPrintReceiptDCCCopies(BOOL BankCopy, BOOL CustCopy, BOOL MercCopy, BOOL fERM);
USHORT ushCTOS_PrintDCCRateBody(int page);
USHORT ushCTOS_PrintDCCRateFooter(int page);
USHORT ushCTOS_printOptOutReceipt(void);
void vdPrintDCCFooterForPrintDCCRates(void);
USHORT ushCTOS_PrintDCCRateFooterEx(int page);
USHORT printBatchInvoiceNOExForDCCPrint(void);
USHORT printBatchInvoiceNOForDCCPrint(void);
USHORT printSMDateTime(void);

void vdCTOS_PrintPreAuthReport(void);
void vdCTOS_PrintMerchantPreAuthReport(void);
USHORT ushCTOS_printPreAuthBatchRecordHeader(void);
USHORT ushCTOS_printPreAuthBatchRecordFooter(void);
void vdCTOS_PrintSMAccumeByHostAndCard(int inReportType,
	USHORT usSaleCount, 
	double ulSaleTotalAmount,    
	USHORT usRefundCount,
	double ulRefundTotalAmount,    
	USHORT usVoidSaleCount,
	double ulVoidSaleTotalAmount,
	USHORT usOffSaleCount,
	double ulOffSaleTotalAmount,
	//1105
	USHORT usCashAdvCount,
	double ulCashAdvTotalAmount,
	USHORT usTipCount,
	double ulTipTotalAmount,
	USHORT usKitSaleCount,
	double ulKitSaleTotalAmount,
	USHORT usRenewalCount,
	double ulRenewalTotalAmount,
	USHORT usPtsAwardCount,
	double ulPtsAwardTotalAmount); 

void vdGetADCDateTime(int inData, CTOS_RTC *SetRTC, char *szStr);
USHORT ushCTOS_PrintADCReportBody(void);
USHORT ushCTOS_PrintADCReportBatchNotEmpty(int inType);
int inPrintADCReport(int  inBodyType);
int inPrintDCCSingPadPacket(char *pucTitle, unsigned char *pucMessage, int inLen);
int inPrintPNG(void);
int inCurlPrintPacket(unsigned char *pucTitle,unsigned char *pucMessage, int inLen, BOOL fRequest);

#ifdef	__cplusplus
}
#endif

#endif	/* PRINT_H */

