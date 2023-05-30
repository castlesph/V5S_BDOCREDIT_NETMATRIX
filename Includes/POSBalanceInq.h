
#ifndef ___POS_BALANCE_INQ___
#define ___POS_BALANCE_INQ___

int inCTOS_BalanceInquiryFlowProcess(void);
int inCTOS_BALANCE_INQUIRY(void);

	

int InDisplayBalance(void);
int inUnPackIsoFunc04(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf);

int inCTOS_CheckCardTypeAllowd(void);

extern int inCTOS_CheckCardTypeAllowd(void);
extern int inInitializePinPad(void);
extern int inGetIPPPin(void);
extern int InDisplayBalance(void);
extern unsigned int wub_hex_2_str(unsigned char * hex,unsigned char * str,unsigned int len);
int inSMGuarantorDisplayBalance(void);


#endif //end ___POS_SALE___

