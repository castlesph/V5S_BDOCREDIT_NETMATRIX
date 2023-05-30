WITH FIXES FOR THE FF ISSUES:


BDO CREDIT APP
1. 00111 - Incorrect display of processing and receiving when performing the transaction MCD04 Test 01 Scenario 01 and Card Details screen is DISABLED
2. 00113 - Missing BDO Loyalty menu from menu id 1 to menu id 48
3. 00129 - Missing RRN in transaction receipt when performing CREDIT SALE or DCC SALE via fallback and manual
4. 00137 - SM: Incorrect host name (MMT)  and host label (HDT) for EASTWEST BNP installment
5. 00142 - RRN is not printed when performing Credit DCC Sale when VISA Receipt config is equal to masked
6. 00143 - NO SIGNATURE REQUIRED is printed when amount is greater than NSP Limit
7. 00125 - SM: Different stan # / invoice # in SMAC QR data and  MTI 200 sale request

02282023
1. 00136 - SM: No delimiter pipe ( I ) on smac qrcode 
03092023
1. 00126 - Prority 6 - out of range via ECR.


03022023
1. With fix for MerchName, RCTheader 1 -5 from nmt table.
> #00136 inCTOS_WaveFlowProcess FOOTER FROM NMT TABLE

03132023
with fix for 

1.	No pending reversal sent before points inquiry.
2.	Approved reversal data was sent on request for next redemption txn.
3.	To send Reversal on Settlement
4. 	00144 - Asterisk “*” is missing in Clear Reversal

03142023
1.	00144 (Asterisk “*” is missing in Clear Reversal) - Fixed
2.	00149 (No Reversal is sent on the next online BDO Loyalty transaction (Bal Inq or Redemption)) 
3.	00166 (Approved reversal data was sent on request for next BDO Loyalty redemption transaction) 
4.	00165 (REVERSAL APPROVED is displayed during successful reversal on Balance inquiry or Redemption transaction for BDO Loyalty.
5.	00166 (7 to 8 seconds white screen displayed on request after reversal approved displayed in BDO Loyalty
6.	00167 (No reversal is sent before processing BDO Loyalty settlement)
7.	invoice # mismatch/ audit number mismatch, reversal file not deleted.

LINK:
https://www.dropbox.com/s/90qp9c1my2w265t/BDO_V3_PACKAGE_v16_03142023.rar?dl=0
> RELEASE PACKAGE TO SQA CREDIT CRC: 621d1c67

03152023
1. 00151 - Incorrect UI of Processing and Receiving screen when ATP BR = ON (swipe or fallback)
2. 00152 - Last 4 digits of card number overlapped in  amount displayed during processing
> both unable to replicate. instead put clearLine(3) and clearLine(5)
3. 00159 - Incorrect transaction flow in SMAC QR via amount entry
4. 00160 - No SCAN label printed in Smac QR void receipt

03162023
1. 00045 - Incorrect error message when performing JCB vis MS TAP





03082023
1. With fix for 00125 - SM: Different stan # / invoice # in SMAC QR data and  MTI 200 sale request
refer to :inCTOS_WaveFlowProcess
2. 00158 - Same invoice # in MTI  200 request for SMAC transaction
3. 00145 - Incorrect data element in Smac QR  Sale Reversal & Void Reversal
4. 00133 - SM: Incomplete details printed in barcode for smac qr sareceipt 
	> fix card num printout.
5. 00134 - SM: Card number not printed in card type for smac qr redemption receipt
NOTE: update ISOENGINEE57 for inUnPackIsoFunc02 , related to 00134, 00145

Released application to Romy, compiled application by Glady [BDO_V3_PACKAGE_v16_03082023]

QRPAY APP
1. 00121 - Missing Retrieve Menu when GrabPay is selected




INSTALLMENT APP
1. 00117 - No signature required printed in BDO  installment receipt  - FOR CONFIRMATION, NEED LOGS
2. 00124 - Missing DE23 and DE55 in i sale or sale reversal for  installment CTLS  using JCB, DINERS, AMEX and CUP
3. 00099 - SM: Eastwest BNPL host not sequence printed in host info report and selection per host in settlement
> The fix is to add, 
1=TERMINAL\MMT\fMMTEnable\MMTid\706=1;EASTWEST BNPL 12 Merchant1-ON(1)/OFF(0)
1=TERMINAL\MMT\fMMTEnable\MMTid\711=1;EASTWEST BNPL 18 Merchant1-ON(1)/OFF(0)
1=TERMINAL\MMT\fMMTEnable\MMTid\716=1;EASTWEST BNPL 24 Merchant1-ON(1)/OFF(0)
> in SM setup PRM file. > C:\WORK\BDO_V3_VERSION_16\V5S_BDOCREDIT\Dist\V5S\BDOCREDIT\10V5S_App\xV5S_BDOCREDIT_SM
> Case #1 Fix for SELECTION PER HOST IN SETTLEMENT (Refer to inMMTReadHostName()). 
> Case #2 AS FOR THE HOST INFO REPORT, IT CHECK HOST TO PRINT IN HDT TABLE REFER TO inHDTReadinSequenceEx();


03092023
> hardcoded installment CRC to 311m91fk, since wub_lrc in not working. released the application package to romy BDO_V3_PACKAGE_v16_03092023C
> refer to vdGetCRC postrans.c of installment application.

BDO DEBIT APP
1. 00128 - Incorrect STAN # in Debit Void  transaction


GLADY DONE:
106
107
108
109
110
112
114
116
145
146


21 REMAINING ISSUES.