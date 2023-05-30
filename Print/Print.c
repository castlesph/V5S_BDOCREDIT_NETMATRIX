#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctosapi.h>
#include <ctype.h>
#include <EMVAPLib.h>
#include <EMVLib.h>
#include <vwdleapi.h>

#include "../Includes/wub_lib.h"
#include "../Includes/myEZLib.h"
#include "../Includes/msg.h"

#include "Print.h"
#include "../FileModule/myFileFunc.h"
#include "../UI/Display.h"
#include "../Includes/POSTypedef.h"
#include "..\Includes\CTOSInput.h"
#include "../accum/accum.h"
#include "../DataBase/DataBaseFunc.h"
#include "..\debug\debug.h"
#include "..\Includes\Showbmp.h"                                        
#include "..\Includes\POSHost.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\POSSetting.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "..\Aptrans\MultiShareEMV.h"
#include "../Ctls/POSCtls.h"
#include "..\POWRFAIL\POSPOWRFAIL.h"
#include "..\Includes\POSSale.h"
#include "..\Includes\epad.h"
#include "..\Erm\PosErm.h"
#include "..\Includes\POSBinVer.h"


#include "..\Aptrans\MultiShareCOM.h"
#include "..\Includes\Possmac.h"
#include "..\TMS\TMS.h"
#include "../Includes/POSDCC.h"

extern BOOL fAUTOManualSettle;

extern BYTE szIP[50+1];
extern BYTE szDNS1[50+1];
extern BYTE szDNS2[50+1];
extern BYTE szGateWay[50+1];
extern BYTE szSubnetMask[50+1];
extern BOOL fRouteToSpecificHost;
extern BOOL fECRTxnFlg;

BYTE		TempszTID[TERMINAL_ID_BYTES+1];
BYTE		TempszMID[MERCHANT_ID_BYTES+1];

BOOL fERMTransaction=FALSE;
extern BOOL fBatchNotEmpty;
extern int inDLTrigger;
extern BOOL fECRBuildSendOK;

#define DB_SIGN_BMP_GZ "signtest.bmp.gz"
extern BOOL fSmacScan;

extern BYTE g_szEmail[100];
extern BYTE szSMACBalPAN;


const BYTE baPrinterBufferLogo_Single[]={ //Width=60, Height=49
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,                                         
                                                                                       
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0xC0,0x60,0x30,0x18,0x18,0x8C,0xC4,0xC6,      
    0x66,0x66,0x22,0x22,0x22,0x22,0x22,0x62,0x66,0x46,0xC4,0x84,0x8C,0x18,0x10,0x30,      
    0x60,0xC0,0xC0,0xE0,0x38,0x0E,0x07,0x1E,0x38,0xE0,0x80,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,                                         
                                                                                       
    0x00,0x00,0x00,0x00,0xC0,0xF8,0x0E,0x03,0x81,0xF0,0x1C,0x0E,0x03,0xC1,0xF0,0xF8,      
    0x7C,0x3C,0x1C,0x1E,0x1E,0x1E,0xFE,0xFC,0xFC,0xFC,0xF8,0xF0,0xC1,0x83,0xCE,0x7C,      
    0x1C,0x07,0x81,0xE0,0x70,0x1C,0x0E,0x1C,0x70,0xC0,0x83,0x07,0x1C,0x70,0xE0,0x80,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,                                         
                                                                                      
    0x00,0x00,0x00,0x00,0x0F,0x7F,0xC0,0x00,0x03,0x3F,0xF0,0x80,0x00,0x0F,0x3F,0x7F,  
    0xFF,0xFC,0xFC,0xFC,0xFC,0xFE,0xF3,0xFB,0xFF,0xFF,0x7F,0x3F,0x0F,0x03,0x81,0xE0,  
    0x38,0x0E,0x03,0xC0,0xF0,0x1C,0x1C,0x38,0xE0,0x81,0x03,0x0E,0x38,0x70,0xC0,0x03,  
    0x0E,0x1C,0x70,0xC0,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0xE0,  
    0xF0,0x78,0x18,0x18,0x0C,0x0C,0x0C,0x0C,0x08,0x18,0x38,0x30,0x00,0x00,0x00,0x00,  
    0x80,0x80,0xC0,0xC0,0xC0,0xC0,0x80,0xC0,0xC0,0xC0,0x00,0x00,0x00,0x00,0x80,0xC0,  
    0xC0,0xC0,0xC0,0x80,0x00,0x00,0xC0,0xFC,0xFC,0xFC,0xC0,0xC0,0x00,0xFC,0xFC,0xFC,  
    0x00,0x00,0x00,0x80,0x80,0xC0,0xC0,0xC0,0xC0,0xC0,0x80,0x80,0x00,0x00,0x00,0x00,  
    0x80,0xC0,0xC0,0xC0,0xC0,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0C,0x0C,  
    0x0C,0xFC,0xFC,0xFC,0x0C,0x0C,0x00,0x00,0x00,0x00,0x80,0xC0,0xC0,0xC0,0xC0,0xC0,  
    0x80,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x80,0xC0,0xC0,0xC0,0xC0,0xC0,0x80,  
    0x00,0x00,0x00,0x00,0xFC,0xFC,0xFC,0x80,0xC0,0xC0,0xC0,0x80,0x00,0x00,0x00,0x00,  
    0xC0,0xC0,0xC0,0xC0,0x80,0xC0,0xC0,0xC0,0x80,0x00,0x00,0x00,0x00,0x00,0x80,0x80,  
    0xC0,0xC0,0xC0,0xC0,0x80,0x80,0x00,0x00,0x00,0x00,0xFC,0xFC,0xFC,0x00,0x00,0x00,  
    0x00,0x80,0xC0,0xC0,0xC0,0xC0,0xC0,0x80,0x80,0x00,0x00,0x00,0x00,0x00,0x80,0xC0,  
    0xC0,0xC0,0xC0,0x80,0x80,0xC0,0xC0,0xC0,0x00,0x00,0x40,0xC0,0xC0,0x80,0x00,0x00,  
    0x00,0x00,0x80,0xC0,0xC0,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0xE0,  
    0xF0,0x78,0x18,0x18,0x0C,0x0C,0x0C,0x0C,0x0C,0x18,0x38,0x30,0x00,0x00,0x00,0x00,  
    0x80,0x80,0xC0,0xC0,0xC0,0xC0,0xC0,0x80,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
    0x00,0xFC,0xFC,0xFC,0x00,0x00,0x00,0x00,0xC0,0xC0,0xFC,0xFC,0xFC,0xC0,0x00,0x00,  
    0x00,0x80,0xC0,0xC0,0xC0,0xC0,0x80,0x80,0xFC,0xFC,0xFC,0x00,0x00,0x00,0x00,0x00,  
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,                                     
                                                                                      
    0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x07,0x0E,0x18,0x30,0x61,0x63,0xC6,0x8C,0x88,  
    0x98,0x98,0x11,0x11,0x11,0x11,0x11,0x11,0x90,0x98,0x88,0x8C,0xC6,0x63,0x61,0x30,  
    0x18,0x0C,0x07,0x01,0x00,0x00,0x00,0x00,0x00,0x03,0x07,0x1C,0x70,0xE0,0x81,0x07,  
    0x0E,0x38,0xE0,0xC1,0x07,0x0E,0x38,0x70,0xC0,0x00,0x00,0x00,0x00,0x00,0x0F,0x3F,  
    0x7F,0xF0,0xC0,0xC0,0x80,0x80,0x80,0x80,0xC0,0xC0,0xE0,0x60,0x00,0x00,0x00,0x3F,  
    0xFF,0xFF,0xC1,0x80,0x80,0x80,0xC1,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x03,0xCF,0x8F,  
    0x9E,0x9C,0xFC,0xF8,0x20,0x00,0x00,0xFF,0xFF,0xFF,0x00,0x00,0x00,0xFF,0xFF,0xFF,  
    0x00,0x00,0x3E,0x7F,0xFF,0xCD,0x8C,0x8C,0x8C,0x8C,0xCF,0xCF,0x0E,0x08,0x00,0x03,  
    0xC7,0x8F,0x8E,0x9C,0xFC,0xF9,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
    0x00,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x3E,0x7F,0xFF,0xCD,0xCC,0x8C,0x8C,0x8C,  
    0xCF,0xCF,0x0F,0x0C,0x00,0x00,0x1C,0x7F,0xFF,0xE3,0xC1,0x80,0x80,0x80,0xC1,0xC1,  
    0x41,0x00,0x00,0x00,0xFF,0xFF,0xFF,0x01,0x00,0x00,0xFF,0xFF,0xFF,0x00,0x00,0x00,  
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x01,0xFF,0xFF,0xFF,0x00,0x00,0x08,0x3E,0x7F,0xFF,  
    0xC1,0x80,0x80,0x80,0xC1,0xFF,0x7F,0x3E,0x00,0x00,0xFF,0xFF,0xFF,0x00,0x00,0x3E,  
    0x7F,0xFF,0xC1,0x80,0x80,0x80,0xC1,0xE3,0x7F,0x3F,0x08,0x00,0x0C,0x7F,0xFF,0xE3,  
    0xC1,0x80,0x80,0x80,0xC1,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x03,0x0F,0x3F,0xFC,0xF0,  
    0xF8,0x7E,0x1F,0x07,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0F,0x3F,  
    0x7F,0xF0,0xC0,0xC0,0x80,0x80,0x80,0x80,0xC0,0xC0,0xE0,0x60,0x00,0x00,0x08,0x3E,  
    0x7F,0xFF,0xC1,0x80,0x80,0x80,0xC1,0xFF,0x7F,0x3E,0x00,0x00,0x80,0xC0,0xC0,0x00,  
    0x00,0x00,0x00,0x00,0xC0,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
    0x00,0xFF,0xFF,0xFF,0x80,0x80,0x80,0x00,0x00,0x00,0xFF,0xFF,0xFF,0x00,0x00,0x1C,  
    0x7F,0xFF,0xE1,0xC0,0x80,0x80,0xC0,0xE1,0xFF,0xFF,0xFF,0x00,0x00,0x00,0xC0,0xC0,  
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,                                     
                                                                                      
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,  
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,  
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,  
    0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
    0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
    0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x01,  
    0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x01,0x01,0x01,  
    0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
    0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
    0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x01,  
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x00,  
    0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,  
    0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,  
    0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,  
    0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x0E,0x0E,  
    0x0D,0x09,0x09,0x08,0x0C,0x0F,0x07,0x03,0x00,0x00,0x00,0x00,0x00,0x0C,0x0F,0x0F,  
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
    0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
    0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,  
    0x00,0x00,0x00,0x07,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
    0x00,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,  
    0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x01,0x01,  
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,                                     
};

TRANS_TOTAL stBankTotal;
BOOL	fRePrintFlag = FALSE; 
extern BOOL fManualSettle; //aaronnino for BDOCLG ver 9.0 fix on issue #00102 Manual settle prints settlement closed instead of summary report 3 of 4


static CTOS_FONT_ATTRIB stgFONT_ATTRIB;

/* Issue# 000096: BIN VER Checking - start -- jzg*/
extern BOOL fBINVer;
extern char szBINVerSTAN[8];
/* Issue# 000096: BIN VER Checking - end -- jzg*/

//extern int inHostOrigNumber;
//extern fVirtualCard;



void vdSetGolbFontAttrib(USHORT FontSize, USHORT X_Zoom, USHORT Y_Zoom, USHORT X_Space, USHORT Y_Space)
{
    memset(&stgFONT_ATTRIB, 0x00, sizeof(stgFONT_ATTRIB));
    
    stgFONT_ATTRIB.FontSize = FontSize;      // Font Size = 12x24
	stgFONT_ATTRIB.X_Zoom = X_Zoom;		    // The width magnifies X_Zoom diameters
	stgFONT_ATTRIB.Y_Zoom = Y_Zoom;		    // The height magnifies Y_Zoom diameters

    stgFONT_ATTRIB.X_Space = X_Space;      // The width of the space between the font with next font
    stgFONT_ATTRIB.Y_Space = Y_Space;      // The Height of the space between the font with next font      
    
}

short printCheckPaper(void)
{
	unsigned short inRet;
	unsigned char key;
	int inLine = 3;

	if( (strTCT.byTerminalType%2) == 0 )
		inLine=2;
	
	while(1)
	{
		inRet = CTOS_PrinterStatus();
		if (inRet==d_OK)
			return 0;
		else if(inRet==d_PRINTER_PAPER_OUT)
		{
			vduiClearBelow(inLine);
			vduiWarningSound();
			#if 0
			vduiDisplayStringCenter(3,"PRINTER OUT OF");
			vduiDisplayStringCenter(4,"PAPER, INSERT");
			vduiDisplayStringCenter(5,"PAPER AND PRESS");
			vduiDisplayStringCenter(6,"ANY KEY TO PRINT.");
			#else
			vduiDisplayStringCenter(4,"OUT OF PAPER");
			#endif
			//vduiDisplayStringCenter(8,"[X] CANCEL PRINT");

			CTOS_KBDGet(&key);
			//if(key==d_KBD_CANCEL)
			//	return -1;	
		}		
	}	
}


void cardMasking(char *szPan, int style)
{
    int num;
    int i;
	char szTemp[30];
    if (style == PRINT_CARD_MASKING_1)
    {
        num = strlen(szPan) - 10;
        if (num > 0)
        {
            for (i = 0; i < num; i++)
            {
                szPan[6+i] = '*';
            }
        }
    }
    else if (style == PRINT_CARD_MASKING_2)
    {
        num = strlen(szPan) - 12;
        if (num > 0)
        {
            for (i = 0; i < num; i++)
            {
                szPan[12+i] = '*';
            }
        }
    }

	else if (style == PRINT_CARD_MASKING_3)
	{
		//strcpy(szPan, "1234567890123456789");
        //strcpy(szPan, "123456789012345678");
		
        memset(szTemp, 0x00, sizeof(szTemp));
        num = strlen(szPan) - 4;
		if(strlen(szPan) > 16)
        {
            memset(szTemp, 0x2a, num);	
            memcpy(&szTemp[num],&szPan[num],4);
        }
		else	
		{
            strcpy(szTemp,"**** **** **** ");
            memcpy(&szTemp[num+3],&szPan[num],4);
		}
		//strcpy(szPan,szTemp);
		memcpy(szPan, szTemp, strlen(szTemp));
	}

	
	else if (style == PRINT_CARD_MASKING_4){
		
		memset(szTemp, 0x00, sizeof(szTemp));
		num = strlen(szPan) - 4;

		
		for (i = 0; i < num; i++)
		{
			szTemp[i] = '*';
		}

		
		memcpy(&szTemp[num],&szPan[num],4);
		strcpy(szPan,szTemp);


	}

	
	else if (style == PRINT_CARD_MASKING_5)
	{
		//strcpy(szPan, "1234567890123456789");
        //strcpy(szPan, "123456789012345678");
		
        memset(szTemp, 0x00, sizeof(szTemp));
        num = strlen(szPan) - 4;
		if(strlen(szPan) > 16)
        {
            memset(szTemp, 0x2a, num);				
		    memcpy(szTemp, szPan, 6);
            memcpy(&szTemp[num],&szPan[num],4);
        }
		else	
		{
		    memcpy(szTemp, szPan, 4);
			memcpy(&szTemp[4]," ",1);
			memcpy(&szTemp[5],&szPan[4],2);
			memcpy(&szTemp[7],"** **** ",8);
            memcpy(&szTemp[num+3],&szPan[num],4);
		}
		//strcpy(szPan,szTemp);
		memcpy(szPan, szTemp, strlen(szTemp));
	}


}

USHORT printDateTime(void)
{
    char szStr[d_LINE_SIZE + 1];
    char szTemp[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    USHORT result;
    BYTE baTemp[PAPER_X_SIZE * 64];
  	CTOS_RTC SetRTC;
	char szYear[3];
//1102
	char sMonth[4];
	char szTempMonth[3];
	char szMonthNames[40];

	memset(sMonth,0x00,4);
	memset(szMonthNames,0x00,40);
	strcpy(szMonthNames,"JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC");
	memset(szTempMonth, 0x00, 3);

//1102
	
    memset(szStr, ' ', d_LINE_SIZE);
    memset(szTemp, ' ', d_LINE_SIZE);


	CTOS_RTCGet(&SetRTC);
	sprintf(szYear ,"%02d",SetRTC.bYear);
	memcpy(srTransRec.szYear,szYear,2);
	vdDebug_LogPrintf("year[%s],date[%02x][%02x]",srTransRec.szYear,srTransRec.szDate[0],srTransRec.szDate[1]);
    wub_hex_2_str(srTransRec.szDate, szTemp,DATE_BCD_SIZE);
    wub_hex_2_str(srTransRec.szTime, szTemp1,TIME_BCD_SIZE);
	vdDebug_LogPrintf("date[%s],time[%s]atol(szTemp)=[%d](atol(szTemp1)=[%d]",szTemp,szTemp1,atol(szTemp),atol(szTemp1) );

	if(atol(szTemp) == 0)
	{
		//sprintf(szTemp ,"%02d%02d",SetRTC.bDay,SetRTC.bMonth);
		sprintf(szTemp ,"%02d%02d",SetRTC.bMonth, SetRTC.bDay);	

	}
	
	if(atol(szTemp1) == 0)
	{
		sprintf(szTemp1 ,"%02d%02d%02d",SetRTC.bHour,SetRTC.bMinute,SetRTC.bSecond);	
	}
	vdDebug_LogPrintf("date[%s],time[%s]",szTemp,szTemp1);
	memcpy(szTempMonth,&szTemp[0],2);
	memcpy(sMonth, &szMonthNames[(atoi(szTempMonth) - 1)* 3], 3);

#if 0 //removed for version 11

	if (strTCT.fSMReceipt== 1)
		sprintf(szStr,"Date/Time    : %02lu/%02lu/%04lu         %02lu:%02lu:%02lu",atol(szTemp)/100,atol(szTemp)%100,atol(srTransRec.szYear)+2000,atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100);
	else
#endif
		sprintf(szStr,"DATE/TIME    : %s %02lu, %02lu    %02lu:%02lu:%02lu",sMonth,atol(szTemp)%100,atol(srTransRec.szYear),atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100);
//1102    
    //memset (baTemp, 0x00, sizeof(baTemp));		
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
    //inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
    inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
	
    return(result);
     
}

// v10.0 change - new function
USHORT printDateTimeAndApprovalCode(void)
{
    char szStr[d_LINE_SIZE + 1];
    char szTemp[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    USHORT result;
    BYTE baTemp[PAPER_X_SIZE * 64];
  	CTOS_RTC SetRTC;
	char szYear[3];
//1102
	char sMonth[4];
	char szTempMonth[3];
	char szMonthNames[40];

	memset(sMonth,0x00,4);
	memset(szMonthNames,0x00,40);
	strcpy(szMonthNames,"JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC");
	memset(szTempMonth, 0x00, 3);

//1102
	
    memset(szStr, ' ', d_LINE_SIZE);
    memset(szTemp, ' ', d_LINE_SIZE);


	CTOS_RTCGet(&SetRTC);
	sprintf(szYear ,"%02d",SetRTC.bYear);
	memcpy(srTransRec.szYear,szYear,2);
	vdDebug_LogPrintf("year[%s],date[%02x][%02x]",srTransRec.szYear,srTransRec.szDate[0],srTransRec.szDate[1]);
    wub_hex_2_str(srTransRec.szDate, szTemp,DATE_BCD_SIZE);
    wub_hex_2_str(srTransRec.szTime, szTemp1,TIME_BCD_SIZE);
	vdDebug_LogPrintf("date[%s],time[%s]atol(szTemp)=[%d](atol(szTemp1)=[%d]",szTemp,szTemp1,atol(szTemp),atol(szTemp1) );

	if(atol(szTemp) == 0)
	{
		//sprintf(szTemp ,"%02d%02d",SetRTC.bDay,SetRTC.bMonth);
		sprintf(szTemp ,"%02d%02d",SetRTC.bMonth, SetRTC.bDay);	

	}
	
	if(atol(szTemp1) == 0)
	{
		sprintf(szTemp1 ,"%02d%02d%02d",SetRTC.bHour,SetRTC.bMinute,SetRTC.bSecond);	
	}
	vdDebug_LogPrintf("date[%s],time[%s]",szTemp,szTemp1);
//1102	
    //sprintf(szStr,"DATE/TIME : %02lu/%02lu/%02lu    %02lu:%02lu:%02lu",atol(szTemp)%100,atol(szTemp)/100,atol(srTransRec.szYear),atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100);
	memcpy(szTempMonth,&szTemp[0],2);
	memcpy(sMonth, &szMonthNames[(atoi(szTempMonth) - 1)* 3], 3);
	//sprintf(szStr,"DATE/TIME : %s %02lu, %02lu    %02lu:%02lu:%02lu",sMonth,atol(szTemp)%100,atol(srTransRec.szYear),atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100);
	sprintf(szStr,"%s %02lu, %02lu    %02lu:%02lu:%02lu   APP CODE:%s",sMonth,atol(szTemp)%100,atol(srTransRec.szYear),atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100, srTransRec.szAuthCode);	// v10.0 change
//1102    
   // memset (baTemp, 0x00, sizeof(baTemp));		

    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
    
    return(d_OK);
     
}


// v10.0 change - new function
USHORT printDateTimeAndOther(unsigned char *strOther, int inMode)
{
    char szStr[d_LINE_SIZE + 1];
    char szTemp[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    USHORT result;
    BYTE baTemp[PAPER_X_SIZE * 64];
  	CTOS_RTC SetRTC;
	char szYear[3];
//1102
	char sMonth[4];
	char szTempMonth[3];
	char szMonthNames[40];

	memset(sMonth,0x00,4);
	memset(szMonthNames,0x00,40);
	strcpy(szMonthNames,"JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC");
	memset(szTempMonth, 0x00, 3);

//1102
	
    memset(szStr, ' ', d_LINE_SIZE);
    memset(szTemp, ' ', d_LINE_SIZE);


	CTOS_RTCGet(&SetRTC);
	sprintf(szYear ,"%02d",SetRTC.bYear);
	memcpy(srTransRec.szYear,szYear,2);
	vdDebug_LogPrintf("year[%s],date[%02x][%02x]",srTransRec.szYear,srTransRec.szDate[0],srTransRec.szDate[1]);
    wub_hex_2_str(srTransRec.szDate, szTemp,DATE_BCD_SIZE);
    wub_hex_2_str(srTransRec.szTime, szTemp1,TIME_BCD_SIZE);
	vdDebug_LogPrintf("date[%s],time[%s]atol(szTemp)=[%d](atol(szTemp1)=[%d]",szTemp,szTemp1,atol(szTemp),atol(szTemp1) );

	if(atol(szTemp) == 0)
	{
		//sprintf(szTemp ,"%02d%02d",SetRTC.bDay,SetRTC.bMonth);
		sprintf(szTemp ,"%02d%02d",SetRTC.bMonth, SetRTC.bDay);	

	}
	
	if(atol(szTemp1) == 0)
	{
		sprintf(szTemp1 ,"%02d%02d%02d",SetRTC.bHour,SetRTC.bMinute,SetRTC.bSecond);	
	}
	vdDebug_LogPrintf("date[%s],time[%s]",szTemp,szTemp1);
//1102	
    //sprintf(szStr,"DATE/TIME : %02lu/%02lu/%02lu    %02lu:%02lu:%02lu",atol(szTemp)%100,atol(szTemp)/100,atol(srTransRec.szYear),atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100);
	memcpy(szTempMonth,&szTemp[0],2);
	memcpy(sMonth, &szMonthNames[(atoi(szTempMonth) - 1)* 3], 3);
	//sprintf(szStr,"DATE/TIME : %s %02lu, %02lu    %02lu:%02lu:%02lu",sMonth,atol(szTemp)%100,atol(srTransRec.szYear),atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100);
	sprintf(szStr,"%s %02lu, %02lu %02lu:%02lu:%02lu",sMonth,atol(szTemp)%100,atol(srTransRec.szYear),atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100);
	inPrintLeftRight(szStr, strOther, inMode);
//1102    
    //memset (baTemp, 0x00, sizeof(baTemp));		

    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
    
    return(result);
     
}

//version16
//USHORT printTIDMID(void)
USHORT printTIDMID(BOOL fReport)
{
    char szStr[d_LINE_SIZE + 1];
    USHORT result;
    BYTE baTemp[PAPER_X_SIZE * 64];
	char szOutTID[d_LINE_SIZE + 1] = {0};
	char szOutMID[d_LINE_SIZE + 1] = {0};
	char chPadChar = '0';

	//version16
	int inMasking = 0;
	char szMaskTID[10];
	char szMaskMID[10];

	//testlang-remove later
	//put_env_char("VisaMaskTID","********");
	//put_env_char("VisaMaskMID","***************");
	//put_env_int("VisaMaskIDS",2);
	//put_env_char("VisaMaskAID","***************");
    //test-remove later

	memset(szOutTID, 0x00, sizeof(szOutTID));
	memset(szOutMID, 0x00, sizeof(szOutMID));
	
    if (fReport == TRUE){
		if (fRePrintFlag == TRUE)
		{
		    vdDebug_LogPrintf("reprint flag true");
	 		strcpy(szOutTID, TempszTID);
			strcpy(szOutMID, TempszMID);
		}else{
			vdDebug_LogPrintf("copy tid and mid");
	 		strcpy(szOutTID, srTransRec.szTID);
			strcpy(szOutMID, srTransRec.szMID);
			vdDebug_LogPrintf("tid %s mid %s",szOutTID, szOutMID );
		}
    }else{

		//vdDebug_LogPrintf("print TID MID maskIDS %d", inMaskIDS);
		//inMasking = strIIT.inMaskIDS; 


        if (strIIT.inIssuerNumber == 2){ 
		 	inMasking = get_env_int("VisaMaskIDS");
        }else if (strIIT.inIssuerNumber == 21){
            if (srTransRec.szPAN[0] == '4')
				inMasking = get_env_int("VisaMaskIDS");
			else
				inMasking = 1;
        }else{
			inMasking = 1;
        }
		
    	if (inMasking == 0){ 
			memset(szOutTID, 0x00, sizeof(szOutTID));
			memset(szOutMID, 0x00, sizeof(szOutMID));
			//return d_OK;
    	}else if (inMasking == 1){
			if (fRePrintFlag == TRUE)
			{
	 			strcpy(szOutTID, TempszTID);
				strcpy(szOutMID, TempszMID);
			}else{
	 			strcpy(szOutTID, srTransRec.szTID);
				strcpy(szOutMID, srTransRec.szMID);
		}
		}else if (inMasking == 2){ //value 2 is masking
        	vdDebug_LogPrintf("masking is equls to 2");
			memset(szMaskTID, 0x00, sizeof(szMaskTID));

			inCTOSS_GetEnvDB("VisaMaskTID",szMaskTID);
			inCTOSS_GetEnvDB("VisaMaskMID",szMaskMID);
            //check if MASKing string is not complet in length
            if (strlen (szMaskTID) < 8  && strlen (szMaskTID) > 0) {
				chPadChar = szMaskTID[0];
            	vdCTOS_Pad_String(szMaskTID, 8, chPadChar, POSITION_RIGHT);
            }

			if (strlen (szMaskMID) < 15 && strlen (szMaskMID) > 0){
				chPadChar = szMaskMID[0];
            	vdCTOS_Pad_String(szMaskMID, 15, chPadChar, POSITION_RIGHT);
            }

			
			if (fRePrintFlag == TRUE)
			{
				vdCTOS_FormatHeader(szMaskTID, TempszTID, szOutTID); // Format TID -- sidumili
				vdCTOS_FormatHeader(szMaskMID, TempszMID, szOutMID); // Format MID -- sidumili
			}else{
				vdCTOS_FormatHeader(szMaskTID, srTransRec.szTID, szOutTID); // Format TID -- sidumili
				vdCTOS_FormatHeader(szMaskMID, srTransRec.szMID, szOutMID); // Format MID -- sidumili
			}
		}
    }

	//vdDebug_LogPrintf("--printTIDMID--");
	//vdDebug_LogPrintf("strIIT.szMaskTID=[%s]", strIIT.szMaskTID);
	//vdDebug_LogPrintf("strIIT.szMaskMID=[%s]", strIIT.szMaskMID);
	//vdDebug_LogPrintf("strIIT.szMaskAID=[%s]", strIIT.szMaskAID);

	
	memset(szStr, ' ', d_LINE_SIZE);
	vdDebug_LogPrintf("szOutTID=[%s]", szOutTID);
	vdDebug_LogPrintf("szOutMID=[%s]", szOutMID);
	
	sprintf(szStr, "TID: %-16.16sMID: %s", szOutTID,szOutMID);
		
    //memset (baTemp, 0x00, sizeof(baTemp));		 
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
	//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
    inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);

//    memset(szStr, ' ', d_LINE_SIZE);
//    sprintf(szStr, "MER# %s", srTransRec.szMID);
//    memset (baTemp, 0x00, sizeof(baTemp));		 
//    CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
//    result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 



    return (d_OK);

}

USHORT printBatchInvoiceNO(void)
{
    char szStr[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    char szTemp2[d_LINE_SIZE + 1];
    USHORT result;
    BYTE baTemp[PAPER_X_SIZE * 64];
        
    memset(szStr, ' ', d_LINE_SIZE);
    memset(szTemp1, ' ', d_LINE_SIZE);
    memset(szTemp2, ' ', d_LINE_SIZE);
	
	wub_hex_2_str(srTransRec.szBatchNo,szTemp1,3);
    wub_hex_2_str(srTransRec.szInvoiceNo, szTemp2, INVOICE_BCD_SIZE);
    vdMyEZLib_LogPrintf("invoice no: %s",szTemp2);

    sprintf(szStr, "BATCH: %-14.14sINVOICE: %s", szTemp1, szTemp2);	// v10.0 change
    memset (baTemp, 0x00, sizeof(baTemp));		

    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
	//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
    inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB, fERMTransaction);
    return(d_OK);
}

USHORT printBatchNO(void)
{
	char szStr[d_LINE_SIZE + 1] = {0};
	char szTemp[d_LINE_SIZE + 1] = {0};
	BYTE baTemp[PAPER_X_SIZE * 64] = {0};
	USHORT result = 0;
	char szBuff[46] = {0};

	memset(szStr, ' ', d_LINE_SIZE);
	memset(szTemp, ' ', d_LINE_SIZE);
	memset(szBuff,0x00,sizeof(szBuff));
	wub_hex_2_str(srTransRec.szBatchNo,szTemp,3);
	sprintf(szStr, "BATCH %s         HOST", szTemp);
	sprintf(szBuff,"%s",srTransRec.szHostLabel);

	inPrintLeftRight(szStr,szBuff,42);
}

USHORT printHostLabel(void)
{
    char szStr[d_LINE_SIZE + 1];
    BYTE baTemp[PAPER_X_SIZE * 64];
    USHORT result;

    memset(szStr, 0x00, sizeof(szStr));
    sprintf(szStr, "HOST: %s", srTransRec.szHostLabel);
    memset (baTemp, 0x00, sizeof(baTemp));		

    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
    return(d_OK);
}


void vdPrintCenter(unsigned char *strIn)
{
	unsigned char tucPrint [24*4+1];
	short i,spacestring;
    USHORT usCharPerLine = 32;
    BYTE baTemp[PAPER_X_SIZE * 64];
    int inSpacing=3;
	
    if(d_FONT_24x24 == stgFONT_ATTRIB.FontSize && NORMAL_SIZE == stgFONT_ATTRIB.X_Zoom)
        usCharPerLine = 32;
    else if(d_FONT_24x24 == stgFONT_ATTRIB.FontSize && DOUBLE_SIZE == stgFONT_ATTRIB.X_Zoom)
         usCharPerLine = 16;
    else if(d_FONT_16x16 == stgFONT_ATTRIB.FontSize && NORMAL_SIZE == stgFONT_ATTRIB.X_Zoom)
        usCharPerLine = 42;
    else if(d_FONT_16x16 == stgFONT_ATTRIB.FontSize && DOUBLE_SIZE == stgFONT_ATTRIB.X_Zoom)
        usCharPerLine = 24;
    else
        usCharPerLine = 32;

    if(stgFONT_ATTRIB.X_Zoom == DOUBLE_SIZE)
         inSpacing=4;
	
    i = strlen(strIn);
	spacestring=(usCharPerLine-i)/2;
				
	memset(tucPrint,0x20,55);
	memcpy(tucPrint+spacestring,strIn,usCharPerLine);	
	
	tucPrint[i+spacestring]=0;
    memset (baTemp, 0x00, sizeof(baTemp));
      
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, tucPrint, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, inSpacing); 
		
    //inCCTOS_PrinterBufferOutput(tucPrint,&stgFONT_ATTRIB,1);
    inCCTOS_PrinterBufferOutput(tucPrint,&stgFONT_ATTRIB,fERMTransaction);
	
}

void vdPrintCenterReverseMode(unsigned char *strIn)
{
	unsigned char tucPrint [24*4+1];
	short i,spacestring;
    USHORT usCharPerLine = 32;
    BYTE baTemp[PAPER_X_SIZE * 64];
    int inSpacing=3;
		
    if(d_FONT_24x24 == stgFONT_ATTRIB.FontSize && NORMAL_SIZE == stgFONT_ATTRIB.X_Zoom)
        usCharPerLine = 32;
    else if(d_FONT_24x24 == stgFONT_ATTRIB.FontSize && DOUBLE_SIZE == stgFONT_ATTRIB.X_Zoom)
        usCharPerLine = 16;
    else if(d_FONT_16x16 == stgFONT_ATTRIB.FontSize && NORMAL_SIZE == stgFONT_ATTRIB.X_Zoom)
        usCharPerLine = 42;
    else if(d_FONT_16x16 == stgFONT_ATTRIB.FontSize && DOUBLE_SIZE == stgFONT_ATTRIB.X_Zoom)
        usCharPerLine = 24;
    else
        usCharPerLine = 32;
        
    i = strlen(strIn);
	spacestring=(usCharPerLine-i)/2;
				
	memset(tucPrint,0x20,55);
	memcpy(tucPrint+spacestring,strIn,usCharPerLine);	
	
	tucPrint[i+spacestring]=0;
    memset (baTemp, 0x00, sizeof(baTemp));
    strcpy(baTemp, "\fr");
	strcat(baTemp, tucPrint);
	strcpy(tucPrint, baTemp);
	vdCTOS_Pad_String(tucPrint, 42, ' ', POSITION_RIGHT);
	memset(baTemp, 0x00, sizeof(baTemp));
    //CTOS_PrinterPutString(baTemp);

    if(stgFONT_ATTRIB.X_Zoom == DOUBLE_SIZE)
         inSpacing=4;
      
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, tucPrint, &stgFONT_ATTRIB);
    //if((d_FONT_24x24 == stgFONT_ATTRIB.FontSize) || (d_FONT_12x24 == stgFONT_ATTRIB.FontSize)
		//&& DOUBLE_SIZE == stgFONT_ATTRIB.X_Zoom)
    	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 4); 
	//else
	    //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 

    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, tucPrint, &stgFONT_ATTRIB);
    //CTOS_PrinterBufferOutput((BYTE *)baTemp, inSpacing); 

		inCCTOS_PrinterBufferOutput(tucPrint,&stgFONT_ATTRIB,1);
		
}


void vdPrintTitleCenter(unsigned char *strIn)
{
	unsigned char tucPrint [24*4+1];
	short i,spacestring;
    USHORT usCharPerLine = 16;
    BYTE baTemp[PAPER_X_SIZE * 64];

    vdSetGolbFontAttrib(d_FONT_24x24, DOUBLE_SIZE, NORMAL_SIZE, 0, 0);
    
    i = strlen(strIn);
	spacestring=(usCharPerLine-i)/2;
				
	memset(tucPrint,0x20,30);
	
	memcpy(tucPrint+spacestring,strIn,usCharPerLine);	
	
	tucPrint[i+spacestring]=0;
        
    //memset (baTemp, 0x00, sizeof(baTemp));	
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, tucPrint, &stgFONT_ATTRIB);
    //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
	inCCTOS_PrinterBufferOutput(tucPrint,&stgFONT_ATTRIB,1);

    vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);
    
}

USHORT printDividingLine(int style)
{
    if (style == DIVIDING_LINE_DOUBLE)
       // return(CTOS_PrinterPutString("==========================================="));
		return(inCCTOS_PrinterBufferOutput("===========================================",&stgFONT_ATTRIB,1));
    else
        //return(CTOS_PrinterPutString("-------------------------------------------"));
	return(inCCTOS_PrinterBufferOutput("-------------------------------------------",&stgFONT_ATTRIB,1));
}

void vdCTOSS_GetEMVTagsDescription(USHORT usTag, char *szValue)
{
    switch(usTag)
    {
        case TAG_50:
            strcpy(szValue, "Appl Label");
            break;

        case TAG_57:
            strcpy(szValue, "Track2 Data");
            break;

        case TAG_5F2A_TRANS_CURRENCY_CODE:
            strcpy(szValue, "Txn CurrCode");
            break;

        case TAG_5F34_PAN_IDENTFY_NO:
            strcpy(szValue, "PAN Seq Num");
            break;

        case TAG_82_AIP:
            strcpy(szValue, "AIP");
            break;

        case TAG_8A_AUTH_CODE:
            strcpy(szValue, "Auth Code");
            break;

        case TAG_8F:
            strcpy(szValue, "CAPK Index");
            break;

        case TAG_91_ARPC:
            strcpy(szValue, "ARPC");
            break;

        case TAG_95:
            strcpy(szValue, "TVR");
            break;

        case TAG_9A_TRANS_DATE:
            strcpy(szValue, "Txn Date");
            break;

        case TAG_9B:
            strcpy(szValue, "TSI");
            break;

        case TAG_9C_TRANS_TYPE:
            strcpy(szValue, "Txn Type");
            break;

        case TAG_9F02_AUTH_AMOUNT:
            strcpy(szValue, "Txn Amt");
            break;

        case TAG_9F03_OTHER_AMOUNT:
            strcpy(szValue, "Other Amt");
            break;

        case TAG_9F10_IAP:
            strcpy(szValue, "IAP");
            break;

        case TAG_9F12:
            strcpy(szValue, "Appl Pref Name");
            break;

        case TAG_9F1A_TERM_COUNTRY_CODE:
            strcpy(szValue, "Term CurrCode");
            break;

        case TAG_9F1B_TERM_FLOOR_LIMIT:
            strcpy(szValue, "FloorLimit");
            break;

        case TAG_9F26_EMV_AC:
            strcpy(szValue, "AC");
            break;

        case TAG_9F27:
            strcpy(szValue, "CID");
            break;

        case TAG_9F33_TERM_CAB:
            strcpy(szValue, "Term Cab");
            break;

        case TAG_9F34_CVM:
            strcpy(szValue, "CVM");
            break;

        case TAG_9F36_ATC:
            strcpy(szValue, "ATC");
            break;

        case TAG_9F37_UNPREDICT_NUM:
            strcpy(szValue, "Unpredict Num");
            break;

        case TAG_9F5B:
            strcpy(szValue, "Script Result");
            break;

        case TAG_71:
            strcpy(szValue, "Issuer Script1");
            break;

        case TAG_72:
            strcpy(szValue, "Issuer Script2");
            break;

        default :
            szValue[0] = 0x00;
            break;
    }
}

void vdPrintEMVTags(void)
{
    BYTE   EMVtagVal[64];
    USHORT EMVtagLen;
    USHORT usPrintTag;
    USHORT usPrintTagLen;
    USHORT usOffset;
    char szStr[d_LINE_SIZE + 1];
    char szTagDesp[50];
    char szEMVTagList[512];
    char szEMVTagListHex[256];
    BYTE szOutEMVData[2048];
    USHORT inTagLen = 0;

	vdCTOSS_PrinterStart(100);
    CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
    if( printCheckPaper()==-1)
    	return ;
    CTOS_LanguagePrinterFontSize(d_FONT_16x16, 0, TRUE);	
    vdPrintTitleCenter("EMV TAGS DATA");

    memset(szOutEMVData,0x00,sizeof(szOutEMVData));

    usCTOSS_EMV_MultiDataGet(PRINT_EMV_TAGS_LIST, &inTagLen, szOutEMVData);
    DebugAddHEX("PRINT_EMV_TAGS_LIST",szOutEMVData,inTagLen);

    memset(szEMVTagList,0x00,sizeof(szEMVTagList));
    memset(szEMVTagListHex,0x00,sizeof(szEMVTagListHex));
    strcpy(szEMVTagList, PRINT_EMV_TAGS_LIST);
    wub_str_2_hex(szEMVTagList, szEMVTagListHex, strlen(szEMVTagList));
	usOffset = 0;
	vdPrintReportDisplayBMP();
	
    while(szEMVTagListHex[usOffset] != 0x00)
    {
        //CTOS_PrinterFline(d_LINE_DOT * 1);
        vdCTOS_PrinterFline(1);
				
        memset(szStr, 0x00, sizeof(szStr));
        if ((szEMVTagListHex[usOffset] & 0x1F) == 0x1F)	// If the least 5 bits of the first byte are set, it is a two byte Tag
    	{
    		usPrintTag = szEMVTagListHex[usOffset];
    		usPrintTag = ((usPrintTag << 8) | szEMVTagListHex[usOffset+1]);
    		usPrintTagLen = 2;		
    	}
    	else
    	{
    		usPrintTag = szEMVTagListHex[usOffset];
            usPrintTag = usPrintTag & 0x00FF;
            usPrintTagLen = 1;
    	}
        memcpy(szStr, &szEMVTagList[usOffset*2], usPrintTagLen*2);
        usOffset += usPrintTagLen;

        memset(szTagDesp,0x00,sizeof(szTagDesp));
        vdCTOSS_GetEMVTagsDescription(usPrintTag, szTagDesp);
        vdDebug_LogPrintf("szStr[%s] usPrintTag[%X] szTagDesp[%s]", szStr, usPrintTag, szTagDesp);  
        vdMyEZLib_Printf("%s (%s)", szStr,szTagDesp);
        memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
        EMVtagLen = 0;
        usCTOSS_FindTagFromDataPackage(usPrintTag, EMVtagVal, &EMVtagLen, szOutEMVData, inTagLen);
        memset(szStr, ' ', d_LINE_SIZE);
        if(EMVtagLen == 0)
            memcpy(szStr,"No DATA" , 7);
        else    
            wub_hex_2_str(EMVtagVal, szStr, EMVtagLen);
		vdMyEZLib_Printf("Len:%d val:%s", EMVtagLen, szStr);
    }
        
    //CTOS_PrinterFline(d_LINE_DOT * 1);
    vdCTOS_PrinterFline(1);
    vdPrintTitleCenter("END OF REPORT");
    //CTOS_PrinterFline(d_LINE_DOT * 10); 
    vdCTOS_PrinterFline(10);
	vdCTOSS_PrinterEnd();
  
}

void vdPrintTerminalConfig(void)
{
    int inResult;
    int shHostIndex = 1;
    int inNum = 0;
    int inNumOfHost = 0;
    int inNumOfMerchant = 0;
    int inLoop =0 ;
    BYTE szStr[50];
    BYTE szBuf[50];
    BYTE baTemp[PAPER_X_SIZE * 64];

    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
    vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);
    
    CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  

	ushCTOS_PrintHeader(0);

    //CTOS_PrinterFline(d_LINE_DOT * 1);
    vdCTOS_PrinterFline(1);
		
    memset(szStr, 0x00, sizeof(szStr));
    memset(szBuf, 0x00, sizeof(szBuf));
    wub_hex_2_str(strTCT.szInvoiceNo, szBuf, 3);
    sprintf(szStr, "INVOICE NO: %s", szBuf);                        
    memset (baTemp, 0x00, sizeof(baTemp));
    CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

    memset(szStr, 0x00, sizeof(szStr));
    sprintf(szStr, "PABX: %s", strTCT.szPabx);                        
    memset (baTemp, 0x00, sizeof(baTemp));
    CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

    memset(szStr, 0x00, sizeof(szStr));
    if(strTCT.fTipAllowFlag)
        sprintf(szStr, "TIP ALLOWED: %s", "YES");      
    else
        sprintf(szStr, "TIP ALLOWED: %s", "NO");
    memset (baTemp, 0x00, sizeof(baTemp));
    CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
    
    //check host num
    inNumOfHost = inHDTNumRecord();
    
    vdDebug_LogPrintf("[inNumOfHost]-[%d]", inNumOfHost);
    for(inNum =1 ;inNum <= inNumOfHost; inNum++)
    {
        if(inHDTRead(inNum) == d_OK)
        {                
            inCPTRead(inNum);

            //CTOS_PrinterFline(d_LINE_DOT * 1);
            vdCTOS_PrinterFline(1);
            
            memset(szStr, 0x00, sizeof(szStr));
            sprintf(szStr, "HOST: %s", strHDT.szHostLabel);                        
            memset (baTemp, 0x00, sizeof(baTemp));
            CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
            CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 

            memset(szStr, 0x00, sizeof(szStr));
            memset(szBuf, 0x00, sizeof(szBuf));
            wub_hex_2_str(strHDT.szTPDU, szBuf, 5);
            sprintf(szStr, "TPDU: %s", szBuf);                        
            memset (baTemp, 0x00, sizeof(baTemp));
            CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
            CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 

            memset(szStr, 0x00, sizeof(szStr));
            if(strCPT.inCommunicationMode == ETHERNET_MODE)
            {   
                sprintf(szStr, "COMM TYPE: %s", "ETHERNET");           
            }
            else if(strCPT.inCommunicationMode == DIAL_UP_MODE)
            {
                sprintf(szStr, "COMM TYPE: %s", "DIAL_UP");         
            }       
            else if(strCPT.inCommunicationMode == GPRS_MODE)
            {
                sprintf(szStr, "COMM TYPE: %s", "GPRS");                 
            }
            memset (baTemp, 0x00, sizeof(baTemp));
            CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
            CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

            memset(szStr, 0x00, sizeof(szStr));
            sprintf(szStr, "PRI NUM : %s", strCPT.szPriTxnPhoneNumber);                        
            memset (baTemp, 0x00, sizeof(baTemp));
            CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
            CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

            memset(szStr, 0x00, sizeof(szStr));
            sprintf(szStr, "SEC NUM : %s", strCPT.szSecTxnPhoneNumber);                        
            memset (baTemp, 0x00, sizeof(baTemp));
            CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
            CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 

            memset(szStr, 0x00, sizeof(szStr));
            sprintf(szStr, "PRI IP  : %s", strCPT.szPriTxnHostIP);                        
            memset (baTemp, 0x00, sizeof(baTemp));
            CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
            CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

            memset(szStr, 0x00, sizeof(szStr));
            sprintf(szStr, "PRI PORT: %d", strCPT.inPriTxnHostPortNum);                        
            memset (baTemp, 0x00, sizeof(baTemp));
            CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
            CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

            memset(szStr, 0x00, sizeof(szStr));
            sprintf(szStr, "SEC IP  : %s", strCPT.szSecTxnHostIP);                        
            memset (baTemp, 0x00, sizeof(baTemp));
            CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
            CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

            memset(szStr, 0x00, sizeof(szStr));
            sprintf(szStr, "SEC PORT: %d", strCPT.inSecTxnHostPortNum);                        
            memset (baTemp, 0x00, sizeof(baTemp));
            CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
            CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

            inMMTReadNumofRecords(strHDT.inHostIndex,&inNumOfMerchant);
        
            vdDebug_LogPrintf("[inNumOfMerchant]-[%d]strHDT.inHostIndex[%d]", inNumOfMerchant,strHDT.inHostIndex);
            for(inLoop=1; inLoop <= inNumOfMerchant;inLoop++)
            {
                if((inResult = inMMTReadRecord(strHDT.inHostIndex,inLoop)) !=d_OK)
                {
                    vdDebug_LogPrintf("[read MMT fail]-Mitid[%d]strHDT.inHostIndex[%d]inResult[%d]", inLoop,strHDT.inHostIndex,inResult);
                    continue;
                    //break;
                }
                else 
                {
                    if(strMMT[0].fMMTEnable)
                    {                        
                        memset(szStr, 0x00, sizeof(szStr));
                        #ifdef SINGE_HEADER_FOOTER_TEXT
						    inNMTReadRecord(inLoop);
                            sprintf(szStr, "MERCHANT:%s", strSingleNMT.szMerchName);
                        #else
                            sprintf(szStr, "MERCHANT:%s", strMMT[0].szMerchantName);   
                        #endif
						
                        memset (baTemp, 0x00, sizeof(baTemp));
                        CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
                        CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

                        memset(szStr, 0x00, sizeof(szStr));
                        sprintf(szStr, "TID : %s", strMMT[0].szTID);                        
                        memset (baTemp, 0x00, sizeof(baTemp));
                        CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
                        CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

                        memset(szStr, 0x00, sizeof(szStr));
                        sprintf(szStr, "MID : %s", strMMT[0].szMID);                        
                        memset (baTemp, 0x00, sizeof(baTemp));
                        CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
                        CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

                        memset(szStr, 0x00, sizeof(szStr));
                        memset(szBuf, 0x00, sizeof(szBuf));
                        wub_hex_2_str(strMMT[0].szBatchNo, szBuf, 3);
                        sprintf(szStr, "BATCH NO: %s", szBuf);                        
                        memset (baTemp, 0x00, sizeof(baTemp));
                        CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
                        CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

                    }                    

                }
            }
        }
        else
            continue;

    }

    //CTOS_PrinterFline(d_LINE_DOT * 5);
    vdCTOS_PrinterFline(5);
		
    return ;
}

void printCardHolderName(void)
{
    USHORT shLen;
    char szStr[d_LINE_SIZE + 1];
    BYTE baTemp[PAPER_X_SIZE * 64];

		vdTrimSpaces(srTransRec.szCardholderName);
		
    shLen = strlen(srTransRec.szCardholderName);

    if(shLen > 0)
    {
        memset(szStr, 0x00, d_LINE_SIZE);
				if (shLen > 30)		
					memcpy(szStr, srTransRec.szCardholderName, CARD_HOLD_NAME_DIGITS); 
				else
					memcpy(szStr, srTransRec.szCardholderName, shLen); 
        	//strcpy(szStr, srTransRec.szCardholderName);


        //while(0x20 == szStr[--shLen] && shLen >= 0)
        //    szStr[shLen] = 0x00;

    	
		//memset (baTemp, 0x00, sizeof(baTemp));  
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
    }
}



void vdTrimSpaces(char* pchString) {
    int inIndex;

    while (1) {
        inIndex = strlen(pchString);
        if (inIndex) {
            if (pchString[inIndex - 1] == IS_SPACE) {
                pchString[inIndex - 1] = IS_NULL_CH;
                continue;
            }
        }
        break;
    }
}


USHORT ushCTOS_PrintDemo(void)
{
    BYTE strIn[40];
    unsigned char tucPrint [24*4+1];
    short i,spacestring;
    USHORT usCharPerLine = 16;
    BYTE baTemp[PAPER_X_SIZE * 64];

    vdSetGolbFontAttrib(d_FONT_24x24, DOUBLE_SIZE, NORMAL_SIZE, 0, 0);
    memset(strIn, 0x00, sizeof(strIn));
    strcpy(strIn, "DEMO");
    i = strlen(strIn);
    spacestring=(usCharPerLine-i)/2;
                
    memset(tucPrint,0x20,30);
    
    memcpy(tucPrint+spacestring,strIn,usCharPerLine);   
    
    tucPrint[i+spacestring]=0;

#if 0 //removed for version 11

	if (strTCT.fSMReceipt == 1)
        vdSetGolbFontAttrib(d_FONT_24x24, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	else
#endif
	    vdSetGolbFontAttrib(d_FONT_24x24, DOUBLE_SIZE, NORMAL_SIZE, 0, 0);
	    //CTOS_PrinterFline(d_LINE_DOT * 1);
	    vdCTOS_PrinterFline(1);
        
    //memset (baTemp, 0x00, sizeof(baTemp));  
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, tucPrint, &stgFONT_ATTRIB);
    //if((d_FONT_24x24 == stgFONT_ATTRIB.FontSize) || (d_FONT_12x24 == stgFONT_ATTRIB.FontSize)
	//	&& DOUBLE_SIZE == stgFONT_ATTRIB.Y_Zoom)
   // 	CTOS_PrinterBufferOutput((BYTE *)baTemp, 4); 
	//else
	//    CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 

	//inCCTOS_PrinterBufferOutput(tucPrint,&stgFONT_ATTRIB,1);
    inCCTOS_PrinterBufferOutput(tucPrint,&stgFONT_ATTRIB,fERMTransaction);

	//CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);
	
  vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);

    return d_OK;
    
}



USHORT ushCTOS_PrintHeader_V9(int page)
{	
    
	//print Logo	
	if(strTCT.fSMLogo == TRUE)
		vdCTOSS_PrinterBMPPic(0, 0, strTCT.szSMReceiptLogo);
	else	
	    vdCTOSS_PrinterBMPPic(0, 0, strTCT.szBDOReceiptLogo);

	if(fRePrintFlag == TRUE)
    {   
        vdDebug_LogPrintf("srTransRec.HDTid[%d] srTransRec.MITid[%d]",srTransRec.HDTid, srTransRec.MITid);
		if ( inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid) != d_OK)
        {
            vdSetErrorMessage("LOAD MMT ERR");
            return(d_NO);
        }
        vdDebug_LogPrintf("srTransRec.HDTid[%d] srTransRec.MITid[%d] strMMT[0].szRctHdr1[%s]",srTransRec.HDTid, srTransRec.MITid, strMMT[0].szRctHdr1);
    }
  //aaronnino for BDOCLG ver 9.0 fix on issue #00085 All Header lines are not printing on the first host info report start
	if(strlen(strMMT[0].szRctHdr1) <= 0)
		 inMMTReadRecord(1,1);
	//aaronnino for BDOCLG ver 9.0 fix on issue #00085 All Header lines are not printing on the first host info report end
    
	//merhcant name and address
	if(strlen(strMMT[0].szRctHdr1) > 0)
		vdPrintCenter(strMMT[0].szRctHdr1);
	if(strlen(strMMT[0].szRctHdr2) > 0)
		vdPrintCenter(strMMT[0].szRctHdr2);
	if(strlen(strMMT[0].szRctHdr3) > 0)
    	vdPrintCenter(strMMT[0].szRctHdr3);
	if(strlen(strMMT[0].szRctHdr4) > 0)
    	vdPrintCenter(strMMT[0].szRctHdr4);
	if(strlen(strMMT[0].szRctHdr5) > 0)
    	vdPrintCenter(strMMT[0].szRctHdr5);

	//issue-00420
	if (strlen(strTCT.szAppVersionHeader) > 0)
		vdPrintCenter(strTCT.szAppVersionHeader);

    if(VS_TRUE == strTCT.fDemo)
    {
        ushCTOS_PrintDemo();
    }

    if(fRePrintFlag == TRUE)
    {
        vdSetGolbFontAttrib(d_FONT_24x24, DOUBLE_SIZE, NORMAL_SIZE, 0, 0);
        vdPrintCenter("DUPLICATE");
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    }
    
    
	return d_OK;
	
}

USHORT ushCTOS_PrintHeader(int page)
{	
    char szLogoPath[50+1];
	//print Logo	
#if 0
		//print Logo	
		if(strTCT.fSMLogo == TRUE)
			vdCTOSS_PrinterBMPPic(0, 0, strTCT.szSMReceiptLogo);
		else	
			vdCTOSS_PrinterBMPPic(0, 0, strTCT.szBDOReceiptLogo);
#else

		vdDebug_LogPrintf("print header");
		memset(szLogoPath,0x00,sizeof(szLogoPath));
		if(strTCT.fSMLogo == TRUE)
			sprintf(szLogoPath,"%s%s",LOCAL_PATH,strTCT.szSMReceiptLogo);
		else
			sprintf(szLogoPath,"%s%s",LOCAL_PATH,strTCT.szBDOReceiptLogo);
	
		vdCTOSS_PrinterBMPPic(0, 0, szLogoPath);
#endif

	
	if(fRePrintFlag == TRUE)
    {   
        vdDebug_LogPrintf("srTransRec.HDTid[%d] srTransRec.MITid[%d]",srTransRec.HDTid, srTransRec.MITid);
		if ( inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid) != d_OK)
        {
            vdSetErrorMessage("LOAD MMT ERR");
            return(d_NO);
        }
        vdDebug_LogPrintf("srTransRec.HDTid[%d] srTransRec.MITid[%d] strMMT[0].szRctHdr1[%s]",srTransRec.HDTid, srTransRec.MITid, strMMT[0].szRctHdr1);
    }
  //aaronnino for BDOCLG ver 9.0 fix on issue #00085 All Header lines are not printing on the first host info report start
	if(strlen(strMMT[0].szRctHdr1) <= 0)
		 inMMTReadRecord(1,1);

	vdDebug_LogPrintf("sztid %s", srTransRec.szTID);
	vdDebug_LogPrintf("szmid %s", srTransRec.szMID);

	//aaronnino for BDOCLG ver 9.0 fix on issue #00085 All Header lines are not printing on the first host info report end
	
	//merhcant name and address
    vdPrintHeaderText();

	//issue-00420
	if (strlen(strTCT.szAppVersionHeader) > 0)
		vdPrintCenter(strTCT.szAppVersionHeader);

    if(fRePrintFlag == TRUE)
    {
        ///vdSetGolbFontAttrib(d_FONT_24x24, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
        //vdPrintCenterReverseMode("DUPLICATE");
        //vdSetGolbFontAttrib(d_FONT_24x24, DOUBLE_SIZE, NORMAL_SIZE, 0, 0);
		vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
        vdPrintCenter("DUPLICATE");
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    }

    if(VS_TRUE == strTCT.fDemo)
    {
        ushCTOS_PrintDemo();
    }

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    
    
	return d_OK;
	
}

// code cleanup
#if 0
USHORT ushCTOS_PrintBody_V9(int page)
{	
    char szStr[d_LINE_SIZE + 3];
    char szTemp[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    char szTemp3[d_LINE_SIZE + 1];
    char szTemp4[d_LINE_SIZE + 1];
    char szTemp5[d_LINE_SIZE + 1];
    char szFormatPAN[strlen(srTransRec.szPAN) + 7];//to account for space as in PAN format and to include additional PAN no. 7 has been added -Meena 08/01/2012
    int inFmtPANSize;
    BYTE baTemp[PAPER_X_SIZE * 64];
    USHORT result;
    int num,i,inResult;
    unsigned char tucPrint [24*4+1];	
    BYTE   EMVtagVal[64];
    USHORT EMVtagLen; 
    short spacestring;
    BYTE   key;

	char szAmountBuff[20], szTemp6[47];
	int inPADSize,x;
	char szSPACE[40];

	char szPOSEntry[21] = {0}; /* BDOCLG-00134: Reformat cardtype line -- jzg */

	if(d_FIRST_PAGE == page)
	{
		#if 0	// v10.0 change start
    	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		if (srTransRec.byEntryMode == CARD_ENTRY_WAVE)
		{	
			memset(szStr, 0x00, sizeof(szStr));
			strcpy(szStr, "CONTACTLESS");
			vdPrintCenter(szStr);
		}

		#endif	// v10.0 change start
    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    printTIDMID(); 

	    printBatchInvoiceNO();	// v10.0 change: move from below
		/* BDOCLG-00136: "CONTACTLESS" should be printed before cardtype - start -- jzg */

    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		/* BDOCLG-00136: "CONTACTLESS" should be printed before cardtype - end -- jzg */

    //card type
		memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
		EMVtagLen = 0;
		memset(szStr, ' ', d_LINE_SIZE);
		vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);
		//aaronnino for BDOCLG ver 9.0 fix on issue #00134 No ENTRY MODE indicated in the receipt if card was SWIPE,CHIP or FALLBACK   1 of 3 start
		switch(srTransRec.byEntryMode)
		{
			case CARD_ENTRY_MSR:
	     strcat(szPOSEntry, "SWIPE");
			 break;
			case CARD_ENTRY_MANUAL:
			 strcat(szPOSEntry, "MANUAL");
			 break;
			case CARD_ENTRY_ICC:
       strcat(szPOSEntry, "CHIP");   
			 break;
      case CARD_ENTRY_FALLBACK:
			 strcat(szPOSEntry, "FALLBACK");   
			 break;
		}

		#if 0	// v10.0 change start
		if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
			(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
			(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
			(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC)){

			memset(szStr, ' ', d_LINE_SIZE);
            EMVtagLen = srTransRec.stEMVinfo.T84_len;
			memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
			memcpy(EMVtagVal, srTransRec.stEMVinfo.T84, EMVtagLen);
			memset(szTemp, ' ', d_LINE_SIZE);
			wub_hex_2_str(EMVtagVal, szTemp, EMVtagLen);
			sprintf(szStr, "AID: %s",szTemp);
			
			vdStrCat2(srTransRec.szCardLable, szTemp, 21, szStr);

		}else{	
			strcpy(szStr, srTransRec.szCardLable);
		}

		//vdStrCat2(srTransRec.szCardLable, szPOSEntry, 21, szStr);

		
		//aaronnino for BDOCLG ver 9.0 fix on issue #00134 No ENTRY MODE indicated in the receipt if card was SWIPE,CHIP or FALLBACK  1 of 3 end
		vdMyEZLib_LogPrintf("Card label: %s",srTransRec.szCardLable);

		memset (baTemp, 0x00, sizeof(baTemp));
		CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
		#endif	// v10.0 change start
		
		memset(szTemp5, 0x00, sizeof(szTemp5));
		//BDO: Enable PAN Masking for each receipt - start -- jzg
#if 0
		strcpy(szTemp5, srTransRec.szPAN);
		cardMasking(szTemp5, PRINT_CARD_MASKING_3);
#else
    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 4 of 21
		if(strTCT.inCustomerCopy == 1)
		   vdCTOS_FormatPAN2(strIIT.szMaskCustomerCopy, srTransRec.szPAN, szTemp5);
		if(strTCT.inMerchantCopy == 1)
		   vdCTOS_FormatPAN2(strIIT.szMaskMerchantCopy, srTransRec.szPAN, szTemp5);
		if(strTCT.inBankCopy == 1)
		   vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp5);
		//aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 4 of 21
#endif
		//BDO: Enable PAN Masking for each receipt - end -- jzg

    	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		memset(szTemp6, 0x00, sizeof(szTemp6));
		memset(szTemp4, 0x00, sizeof(szTemp4));
		
		if (strlen(srTransRec.szPAN) > 16)
			vdRemoveSpace(szTemp6, szTemp5);		
		else
			strcpy(szTemp6, szTemp5);
				
		strcpy(szTemp4, szTemp6);

		#if 0
//issue-00255 - Align PAN and Entry mode - normal Font size	
        inPrintLeftRight(szTemp4,szPOSEntry,42);
//end
		#else	// v10.0 change
		memset(szStr, 0x00, sizeof(szStr));
		vdCTOS_Pad_String(szTemp4, 33, ' ', POSITION_RIGHT);
		sprintf(szStr, "%s%s", szTemp4, szPOSEntry);
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		#endif
				
        //card holder name
		printCardHolderName();

		//Trans type
      vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

			memset(szStr, 0x00, sizeof(szStr));
			
			if (srTransRec.byTransType == PRE_AUTH)
				strcpy(szStr,"CARD VERIFY");
			else if (srTransRec.byTransType == CASH_ADVANCE)
				strcpy(szStr,"CASH ADVANCE");
		else if ((srTransRec.byTransType == SALE) &&	// v10.0 change
			(srTransRec.byEntryMode == CARD_ENTRY_WAVE))
			strcpy(szStr,"CONTACTLESS SALE");
		else if ((srTransRec.byTransType == SALE) &&	// v10.0 change
			(srTransRec.byEntryMode != CARD_ENTRY_WAVE))
			strcpy(szStr,"CREDIT SALE");
			else
				szGetTransTitle(srTransRec.byTransType, szStr); 
			
		#if 0
			memset (baTemp, 0x00, sizeof(baTemp));
			CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		#else	// v10.0 change
		vdPrintCenter(szStr);
		#endif

			if (srTransRec.byTransType == PRE_AUTH)
				strcpy(szStr,"CARD VERIFY");

        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

		//Issue# 000164 - start -- jzg
		//issue-00244 - Only print policy number for sale
		//if ((strIIT.fGetPolicyNumber == TRUE) && (srTransRec.byTransType == SALE))/* BDO-00060: Policy number should be per issuer -- jzg */
		if ((strIIT.fGetPolicyNumber == TRUE) && (strlen(srTransRec.szPolicyNumber) > 0))
		{
										memset(szStr, 0, d_LINE_SIZE);
										memset (baTemp, 0x00, sizeof(baTemp));
										sprintf(szStr, "POLICY NO. %s", srTransRec.szPolicyNumber);
										//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
										//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
										inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		//Issue# 000164 - end -- jzg
		
		/* Issue# 000096: BIN VER Checking - start -- jzg*/
		if (srTransRec.fBINVer)
		{
			//BIN Ver
			vdDebug_LogPrintf("fBINVer = [%d]", fBINVer);
			vdDebug_LogPrintf("BIN Ver STAN = [%s]", szBINVerSTAN);
			
			memset(szStr, 0, d_LINE_SIZE);
			memset(baTemp, 0, sizeof(baTemp)); //BDO: Fix for overlapping BIN Check line on receipt --sidumili
			vdCTOS_Pad_String(srTransRec.szBINVerSTAN, 6, '0', POSITION_LEFT);   //sidumili: modified using stTransRec to get record during reprint/void
			sprintf(szStr, "BIN CHECK: %s", srTransRec.szBINVerSTAN);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		/* Issue# 000096: BIN VER Checking - end -- jzg*/

		if ((strIIT.fGetPolicyNumber == TRUE) && (strlen(srTransRec.szPolicyNumber) > 0))
		{
										memset(szStr, 0, d_LINE_SIZE);
										memset (baTemp, 0x00, sizeof(baTemp));
										sprintf(szStr, "POLICY NO. %s", srTransRec.szPolicyNumber);
										//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
										//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
										inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		//Issue# 000164 - end -- jzg



		//BDO: Moved and reformatted approval code line - start -- jzg
		//Reference num
		memset(szStr, ' ', d_LINE_SIZE);
		memset (baTemp, 0x00, sizeof(baTemp));
		memset(szStr, ' ', d_LINE_SIZE);

		//Approval Code
		memset(szStr, ' ', d_LINE_SIZE);
		memset (baTemp, 0x00, sizeof(baTemp));					
		memset(szStr, ' ', d_LINE_SIZE);

    //aaronnino for BDOCLG ver 9.0 fix on issue #00066 "APPR.CODE" single width printed on transaction receipt 6 of 8 start
		if (strTCT.fDutyFreeMode == TRUE){
			printDateTime();	// v10.0 change

		   //Reference num
		   sprintf(szStr, "REF. NO. %s", srTransRec.szRRN);
		   memset (baTemp, 0x00, sizeof(baTemp));	   
		   //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		  // CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		   inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			
		   vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);  
		   sprintf(szStr, "APPR. CODE: %s", srTransRec.szAuthCode);
		   vdCTOS_Pad_String(szStr, 23, ' ', POSITION_LEFT);
		   memset (baTemp, 0x00, sizeof(baTemp));	   
		   //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		   //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		   inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		   vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		}else{
			printDateTimeAndApprovalCode();	// v10.0 change
			 vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
			if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||	// v10.0 change - depends on srTransRec.byEntryMode
				/* EMV: Revised EMV details printing - start -- jzg */
				(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
				(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
				(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
				(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||		
                (srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
				(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
				/* EMV: Revised EMV details printing - end -- jzg */
			{
				if(strlen(srTransRec.szRRN) <= 0)
					//sprintf(szStr, "REF. NO.               APPR. CODE: %s",srTransRec.szAuthCode);
					sprintf(szStr, "RRN:                     APP: %s",srTransRec.szCardLable);	// v10.0 change
				else
					//sprintf(szStr, "REF. NO. %s  APPR. CODE: %s", srTransRec.szRRN,srTransRec.szAuthCode);
					sprintf(szStr, "RRN: %s        APP: %s", srTransRec.szRRN,srTransRec.szCardLable);	// v10.0 change
			}
			else	// v10.0 change - depends on srTransRec.byEntryMode
			{
				if(strlen(srTransRec.szRRN) <= 0)
					strcpy(szStr, "RRN:");
				else
					sprintf(szStr, "RRN: %s", srTransRec.szRRN);
			}
			memset (baTemp, 0x00, sizeof(baTemp)); 	 
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}

		// v10.0 change start
		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		memset(szTemp1, ' ', d_LINE_SIZE);
		if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
			/* EMV: Revised EMV details printing - start -- jzg */
			(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
			(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
			(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||	
		    (srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
			(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
			/* EMV: Revised EMV details printing - end -- jzg */
		{
			//AID
			memset(szStr, ' ', d_LINE_SIZE);
            EMVtagLen = srTransRec.stEMVinfo.T84_len;
			memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
			memcpy(EMVtagVal, srTransRec.stEMVinfo.T84, EMVtagLen);
			memset(szTemp, ' ', d_LINE_SIZE);
			wub_hex_2_str(EMVtagVal, szTemp1, EMVtagLen);
			
			//TC
			//issue-00770
			if (srTransRec.byTransType != SALE_OFFLINE && srTransRec.byOrgTransType!= SALE_OFFLINE){
				wub_hex_2_str(srTransRec.stEMVinfo.T9F26, szTemp, 8);
				sprintf(szStr, "TC: %s   AID: %s", szTemp, szTemp1);
			}
			else
			{
				if (srTransRec.byEntryMode == CARD_ENTRY_WAVE)
				{
					wub_hex_2_str(srTransRec.stEMVinfo.T9F26, szTemp, 8);
					sprintf(szStr, "TC: %s   AID: %s", szTemp, szTemp1);
				}
				else
				sprintf(szStr, "                    AID: %s",szTemp1);
			}
			
			memset (baTemp, 0x00, sizeof(baTemp));		
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		// v10.0 change end


		/* BDO CLG: Fleet card support - start -- jzg */
		if((srTransRec.fFleetCard == TRUE) && (strTCT.fFleetGetLiters == TRUE)) /* BDOCLG-00347: should be controlled also be parameterized -- jzg */
		{
			memset(szStr, ' ', d_LINE_SIZE);
			memset (baTemp, 0x00, sizeof(baTemp));
			memset(szStr, ' ', d_LINE_SIZE);
			
			sprintf(szStr, "NO. OF LITERS: %d", srTransRec.inFleetNumofLiters); //BDOCLG-00322 --jzg
			memset (baTemp, 0x00, sizeof(baTemp));		
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		/* BDO CLG: Fleet card support - end -- jzg */


		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		memset(szTemp1, ' ', d_LINE_SIZE);
		memset(szTemp3, ' ', d_LINE_SIZE);
		wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szTipAmount, szTemp3, AMT_BCD_SIZE);

        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		//1025 - ADD OFFLINE SALE
		if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == SALE_OFFLINE))
		{

			//Base amount
			memset(szStr, ' ', d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));

			
		  if (strTCT.fTipAllowFlag == CN_FALSE){	
				strcpy(szTemp6,"TOTAL:");
			
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			
				sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
				inPrintLeftRight(szTemp6,szAmountBuff,23);
		  }else{
					memset(szStr, 0x00, d_LINE_SIZE);
					memset(szAmountBuff,0x00,20);
					memset(szTemp4, 0x00, sizeof(szTemp4));
					memset(szTemp6,0x00, sizeof(szTemp6));
				strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change
					vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
					sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
					inPrintLeftRight(szTemp6,szAmountBuff,23);
					/*********************************************************/
					/*TIP*/
					memset(szStr, 0x00, d_LINE_SIZE);
					memset(szAmountBuff,0x00,20);
					memset(szTemp4, 0x00, sizeof(szTemp4));
					memset(szTemp6,0x00, sizeof(szTemp6));
					strcpy(szTemp6,"TIP:");
					if (atol(szTemp3)> 0)
					{
						vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
						sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
					}
					inPrintLeftRight(szTemp6,szAmountBuff,23); 
					/*********************************************************/

				//CTOS_PrinterPutString("          _____________________");	// v10.0 change
					
					memset(szStr, 0x00, d_LINE_SIZE);
					memset(szAmountBuff,0x00,20);
					memset(szTemp4, 0x00, sizeof(szTemp4));
					memset(szTemp6,0x00, sizeof(szTemp6));
					strcpy(szTemp6,"TOTAL:");

					if (atol(szTemp3)> 0){	
						vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp4);// patrick add code 20141216 	
						sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
					}
					inPrintLeftRight(szTemp6,szAmountBuff,23); 
		  }
			
		}
		else if ((srTransRec.byTransType == SALE_TIP) ||(srTransRec.byOrgTransType == SALE_TIP))
		{

			//Base amount
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		

			if (srTransRec.byTransType == VOID)
				sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
			else
				sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,23);
            /*********************************************************/
            /*TIP*/
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"TIP:");
			if (atol(szTemp3)> 0)
			{
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
				if (srTransRec.byTransType == VOID)
					sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
				else
					sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			}
			inPrintLeftRight(szTemp6,szAmountBuff,23); 
	 		/*********************************************************/

			//CTOS_PrinterPutString("          _____________________");	// v10.0 change
			
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"TOTAL:");
			
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp4);// patrick add code 20141216		
			if (srTransRec.byTransType == VOID)
				sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
			else
				sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,23); 
		
		}
		else
		{
			if ((strTCT.fTipAllowFlag == CN_TRUE) && (srTransRec.byTransType != PRE_AUTH) && (srTransRec.byTransType != CASH_ADVANCE))
			{
				//Base amount
				memset(szStr, 0x00, d_LINE_SIZE);
				memset(szAmountBuff,0x00,20);
				memset(szTemp4, 0x00, sizeof(szTemp4));
				memset(szTemp6,0x00, sizeof(szTemp6));
				strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		

				if (srTransRec.byTransType == VOID)
					sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
				else
					sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
				inPrintLeftRight(szTemp6,szAmountBuff,23);
	            /*********************************************************/
	            /*TIP*/
				memset(szStr, 0x00, d_LINE_SIZE);
				memset(szAmountBuff,0x00,20);
				memset(szTemp4, 0x00, sizeof(szTemp4));
				memset(szTemp6,0x00, sizeof(szTemp6));
				strcpy(szTemp6,"TIP:");

				if (atol(szTemp3)> 0)
				{
					vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
					if (srTransRec.byTransType == VOID)
						sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
					else
						sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
				}
				inPrintLeftRight(szTemp6,szAmountBuff,23); 
		 		/*********************************************************/

				//CTOS_PrinterPutString("          _____________________");	// v10.0 change
			}

			memset(szStr, ' ', d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"TOTAL:");

			if ((atol(szTemp3)> 0) || (srTransRec.byTransType == PRE_AUTH) || (srTransRec.byTransType == CASH_ADVANCE))
			{
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
				if (srTransRec.byTransType == VOID)
					sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
				else
					sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			}
			//fix for void receipt - if TIP is off
			else if ((strTCT.fTipAllowFlag == CN_FALSE) &&	(srTransRec.byTransType != PRE_AUTH) && (srTransRec.byTransType != CASH_ADVANCE)){
					vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
					if (srTransRec.byTransType == VOID)
						sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
					else
						sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
				
			}
			//fix for void receipt - if TIP is off
			inPrintLeftRight(szTemp6,szAmountBuff,23); 
		}

   vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

		/* BDO CLG: Fleet card support - start -- jzg */
		if((srTransRec.fFleetCard == TRUE) && 
			(strTCT.fFleetGetLiters == TRUE) &&
			(strTCT.fGetDescriptorCode == TRUE)) /* BDOCLG-00347: should be controlled also be parameterized -- jzg */
		{
			//CTOS_PrinterFline(d_LINE_DOT * 1);
      vdCTOS_PrinterFline(1);
			
			memset(szStr, ' ', d_LINE_SIZE);
			memset (baTemp, 0x00, sizeof(baTemp));
			memset(szStr, ' ', d_LINE_SIZE);
			
			sprintf(szStr, "%s    %s", srTransRec.szFleetProductDesc, srTransRec.szFleetProductCode);
			memset (baTemp, 0x00, sizeof(baTemp));		
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

			//CTOS_PrinterFline(d_LINE_DOT * 2);
      vdCTOS_PrinterFline(2);
			
		}
		/* BDO CLG: Fleet card support - end -- jzg */

	 //gcitra-012015 
	 //if((srTransRec.byOffline == CN_TRUE) && (srTransRec.byTransType != SALE_TIP)){
   if ((srTransRec.byOffline == CN_TRUE) && (srTransRec.byTransType == SALE_OFFLINE)){ //aaronnino for BDOCLG ver 9.0 fix on issue #00068 No "offline entered" on offline sale with tip adjust receipt 1 of 3
		 //CTOS_PrinterFline(d_LINE_DOT * 1);
     vdCTOS_PrinterFline(1); 
		 
		 vdPrintCenter("* Completion/Checkout Entered *");
	 }
	 //gcitra-012015

	    
		#if 0 	// v10.0 change start - move up
		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
			/* EMV: Revised EMV details printing - start -- jzg */
			(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
			(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
			(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
			/* EMV: Revised EMV details printing - end -- jzg */
		{
			CTOS_PrinterFline(d_LINE_DOT * 1);

			/* EMV: Get Application Label - start -- jzg */
			memset(szStr, ' ', d_LINE_SIZE);
			sprintf(szStr, "APP.: %s", srTransRec.stEMVinfo.szChipLabel);
			memset (baTemp, 0x00, sizeof(baTemp));		
			CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			/* EMV: Get Application Label - end -- jzg */

			//AC
			//issue-00770
			if (srTransRec.byTransType != SALE_OFFLINE && srTransRec.byOrgTransType!= SALE_OFFLINE){
				wub_hex_2_str(srTransRec.stEMVinfo.T9F26, szTemp, 8);
				sprintf(szStr, "TC: %s", szTemp);
				memset (baTemp, 0x00, sizeof(baTemp));		
				CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
				CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);	
			}
			//AID
			memset(szStr, ' ', d_LINE_SIZE);
            EMVtagLen = srTransRec.stEMVinfo.T84_len;
			memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
			memcpy(EMVtagVal, srTransRec.stEMVinfo.T84, EMVtagLen);
			memset(szTemp, ' ', d_LINE_SIZE);
			wub_hex_2_str(EMVtagVal, szTemp, EMVtagLen);
			sprintf(szStr, "AID: %s",szTemp);
			memset (baTemp, 0x00, sizeof(baTemp));		
			CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		}
		#endif 	// v10.0 change end
		
	}
	else if(d_SECOND_PAGE == page)
	{
		#if 0	// v10.0 change start
		vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		
		if (srTransRec.byEntryMode == CARD_ENTRY_WAVE)
		{	
			memset(szStr, 0x00, sizeof(szStr));
			strcpy(szStr, "CONTACTLESS");
			vdPrintCenter(szStr);
		}

		#endif	// v10.0 change start
        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
        printTIDMID(); 
	    printBatchInvoiceNO();	// v10.0 change: move from below

		/* BDOCLG-00136: "CONTACTLESS" should be printed before cardtype - start -- jzg */

    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		/* BDOCLG-00136: "CONTACTLESS" should be printed before cardtype - end -- jzg */

        //card type
		memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
		EMVtagLen = 0;
		memset(szStr, ' ', d_LINE_SIZE);
		vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);
		//aaronnino for BDOCLG ver 9.0 fix on issue #00134 No ENTRY MODE indicated in the receipt if card was SWIPE,CHIP or FALLBACK  2 of 3 start
		switch(srTransRec.byEntryMode)
		{
			case CARD_ENTRY_MSR:
	     strcat(szPOSEntry, "SWIPE");
			 break;
			case CARD_ENTRY_MANUAL:
			 strcat(szPOSEntry, "MANUAL");
			 break;
			case CARD_ENTRY_ICC:
       strcat(szPOSEntry, "CHIP");   
			 break;
      case CARD_ENTRY_FALLBACK:
			 strcat(szPOSEntry, "FALLBACK");   
			 break;
		}

		#if 0	// v10.0 change start
		if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
			(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
			(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
			(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC)){

			memset(szStr, ' ', d_LINE_SIZE);
            EMVtagLen = srTransRec.stEMVinfo.T84_len;
			memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
			memcpy(EMVtagVal, srTransRec.stEMVinfo.T84, EMVtagLen);
			memset(szTemp, ' ', d_LINE_SIZE);
			wub_hex_2_str(EMVtagVal, szTemp, EMVtagLen);
			sprintf(szStr, "AID: %s",szTemp);
			
			vdStrCat2(srTransRec.szCardLable, szTemp, 21, szStr);

		}else{	
			strcpy(szStr, srTransRec.szCardLable);
		}

		//vdStrCat2(srTransRec.szCardLable, szPOSEntry, 21, szStr);


		
		//aaronnino for BDOCLG ver 9.0 fix on issue #00134 No ENTRY MODE indicated in the receipt if card was SWIPE,CHIP or FALLBACK  2 of 3 end
		vdMyEZLib_LogPrintf("Card label: %s",srTransRec.szCardLable);

		memset (baTemp, 0x00, sizeof(baTemp));
		CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
		#endif	// v10.0 change start

		//pan
				//BDO: Enable PAN Masking for each receipt - start -- jzg
#if 0
				strcpy(szTemp5, srTransRec.szPAN);
				cardMasking(szTemp5, PRINT_CARD_MASKING_3);
#else
        //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 5 of 21
       if(strTCT.inMerchantCopy == 2)
          vdCTOS_FormatPAN2(strIIT.szMaskMerchantCopy, srTransRec.szPAN, szTemp5);
			 if(strTCT.inBankCopy == 2)
          vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp5);
       if(strTCT.inCustomerCopy == 2)
				  vdCTOS_FormatPAN2(strIIT.szMaskCustomerCopy, srTransRec.szPAN, szTemp5);
			  //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 5 of 21
#endif
				//BDO: Enable PAN Masking for each receipt - end -- jzg
		
    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		memset(szTemp6, 0x00, sizeof(szTemp6));
		memset(szTemp4, 0x00, sizeof(szTemp4));
		
		if (strlen(srTransRec.szPAN) > 16)
			vdRemoveSpace(szTemp6, szTemp5);		
		else
			strcpy(szTemp6, szTemp5);
				
		strcpy(szTemp4, szTemp6);
		#if 0
		//issue-00255 - Align PAN and Entry mode - normal Font size 
				inPrintLeftRight(szTemp4,szPOSEntry,42);
		//end
		#else	// v10.0 change
		memset(szStr, 0x00, sizeof(szStr));
		vdCTOS_Pad_String(szTemp4, 33, ' ', POSITION_RIGHT);
		sprintf(szStr, "%s%s", szTemp4, szPOSEntry);
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		#endif
		
        //card holder name
		printCardHolderName();
		
		//Trans type
        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		
		memset(szStr, 0x00, sizeof(szStr));
		
		if (srTransRec.byTransType == PRE_AUTH)
			strcpy(szStr,"CARD VERIFY");
		else if (srTransRec.byTransType == CASH_ADVANCE)
			strcpy(szStr,"CASH ADVANCE");
		else if ((srTransRec.byTransType == SALE) &&	// v10.0 change
			(srTransRec.byEntryMode == CARD_ENTRY_WAVE))
			strcpy(szStr,"CONTACTLESS SALE");
		else if ((srTransRec.byTransType == SALE) &&	// v10.0 change
			(srTransRec.byEntryMode != CARD_ENTRY_WAVE))
			strcpy(szStr,"CREDIT SALE");
		else
			szGetTransTitle(srTransRec.byTransType, szStr); 

		#if 0
		memset (baTemp, 0x00, sizeof(baTemp));
		CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		#else	// v10.0 change
		vdPrintCenter(szStr);
		#endif

		if (srTransRec.byTransType == PRE_AUTH)
			strcpy(szStr,"CARD VERIFY");
        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

		//Issue# 000164 - start -- jzg
		//issue-00244 - Only print policy number for sale
		//if ((strIIT.fGetPolicyNumber == TRUE) && (srTransRec.byTransType == SALE))/* BDO-00060: Policy number should be per issuer -- jzg */	
		if ((strIIT.fGetPolicyNumber == TRUE) && (strlen(srTransRec.szPolicyNumber) > 0))
		{
			memset(szStr, 0, d_LINE_SIZE);
			memset (baTemp, 0x00, sizeof(baTemp));
			sprintf(szStr, "POLICY NO. %s", srTransRec.szPolicyNumber);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		//Issue# 000164 - end -- jzg

		/* Issue# 000096: BIN VER Checking - start -- jzg*/
		if (srTransRec.fBINVer)
		{
			//BIN Ver
			vdDebug_LogPrintf("fBINVer = [%d]", fBINVer);
			vdDebug_LogPrintf("BIN Ver STAN = [%s]", szBINVerSTAN);
			
			memset(szStr, 0, d_LINE_SIZE);
			memset(baTemp, 0, sizeof(baTemp)); //BDO: Fix for overlapping BIN Check line on receipt --sidumili
			vdCTOS_Pad_String(srTransRec.szBINVerSTAN, 6, '0', POSITION_LEFT);   //sidumili: modified using stTransRec to get record during reprint/void
			sprintf(szStr, "BIN CHECK: %s", srTransRec.szBINVerSTAN);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		/* Issue# 000096: BIN VER Checking - end -- jzg*/


		//Issue# 000164 - start -- jzg
		//issue-00244 - Only print policy number for sale
		//if ((strIIT.fGetPolicyNumber == TRUE) && (srTransRec.byTransType == SALE))/* BDO-00060: Policy number should be per issuer -- jzg */	
		if ((strIIT.fGetPolicyNumber == TRUE) && (strlen(srTransRec.szPolicyNumber) > 0))
		{
			memset(szStr, 0, d_LINE_SIZE);
			memset (baTemp, 0x00, sizeof(baTemp));
			sprintf(szStr, "POLICY NO. %s", srTransRec.szPolicyNumber);
			CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		}
		//Issue# 000164 - end -- jzg
        

    //BDO: Moved and reformatted approval code line - start -- jzg
    //Reference num
    memset(szStr, ' ', d_LINE_SIZE);
    memset (baTemp, 0x00, sizeof(baTemp));
    memset(szStr, ' ', d_LINE_SIZE);


    //Approval Code
    memset(szStr, ' ', d_LINE_SIZE);
    memset (baTemp, 0x00, sizeof(baTemp));          
    memset(szStr, ' ', d_LINE_SIZE);

    //aaronnino for BDOCLG ver 9.0 fix on issue #00066 "APPR.CODE" single width printed on transaction receipt 7 of 8 start
	if (strTCT.fDutyFreeMode == TRUE){
			printDateTime();	// v10.0 change
	
	   //Reference num
	   sprintf(szStr, "REF. NO. %s", srTransRec.szRRN);
	   memset (baTemp, 0x00, sizeof(baTemp));	   
	   //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	   //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	   inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		
	   vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);  
	   sprintf(szStr, "APPR. CODE: %s", srTransRec.szAuthCode);
	   vdCTOS_Pad_String(szStr, 23, ' ', POSITION_LEFT);
	   memset (baTemp, 0x00, sizeof(baTemp));	   
	   //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	   //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	   inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	   vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	}else{
			printDateTimeAndApprovalCode();	// v10.0 change
		 vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
			if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||	// v10.0 change - depends on srTransRec.byEntryMode
				/* EMV: Revised EMV details printing - start -- jzg */
				(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
				(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
				(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
				(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
				(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||
				(srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
				(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
				/* EMV: Revised EMV details printing - end -- jzg */
			{
				if(strlen(srTransRec.szRRN) <= 0)
					//sprintf(szStr, "REF. NO.               APPR. CODE: %s",srTransRec.szAuthCode);
					sprintf(szStr, "RRN:                     APP: %s",srTransRec.szCardLable);	// v10.0 change
				else
					//sprintf(szStr, "REF. NO. %s  APPR. CODE: %s", srTransRec.szRRN,srTransRec.szAuthCode);
					sprintf(szStr, "RRN: %s        APP: %s", srTransRec.szRRN,srTransRec.szCardLable);	// v10.0 change
			}
			else	// v10.0 change - depends on srTransRec.byEntryMode
			{
				if(strlen(srTransRec.szRRN) <= 0)
					strcpy(szStr, "RRN:");
				else
					sprintf(szStr, "RRN: %s", srTransRec.szRRN);
			}
		 memset (baTemp, 0x00, sizeof(baTemp)); 	 
		 //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		 //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		 inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	
	}
    //BDO: Moved and reformatted approval code line - end -- jzg

		// v10.0 change start
		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		memset(szTemp1, ' ', d_LINE_SIZE);
		if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
			/* EMV: Revised EMV details printing - start -- jzg */
			(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
			(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
			(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||
			(srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
			(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
			/* EMV: Revised EMV details printing - end -- jzg */
		{
			//AID
			memset(szStr, ' ', d_LINE_SIZE);
            EMVtagLen = srTransRec.stEMVinfo.T84_len;
			memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
			memcpy(EMVtagVal, srTransRec.stEMVinfo.T84, EMVtagLen);
			memset(szTemp, ' ', d_LINE_SIZE);
			wub_hex_2_str(EMVtagVal, szTemp1, EMVtagLen);
			
			//TC
			//issue-00770
			if (srTransRec.byTransType != SALE_OFFLINE && srTransRec.byOrgTransType!= SALE_OFFLINE){
				wub_hex_2_str(srTransRec.stEMVinfo.T9F26, szTemp, 8);
				sprintf(szStr, "TC: %s     AID: %s", szTemp, szTemp1);
			}
			else
				sprintf(szStr, "                    AID: %s",szTemp1);
			
			memset (baTemp, 0x00, sizeof(baTemp));		
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		// v10.0 change end


		/* BDO CLG: Fleet card support - start -- jzg */
    if((srTransRec.fFleetCard == TRUE) && (strTCT.fFleetGetLiters == TRUE)) /* BDOCLG-00347: should be controlled also be parameterized -- jzg */
		{
			memset(szStr, ' ', d_LINE_SIZE);
			memset (baTemp, 0x00, sizeof(baTemp));
			memset(szStr, ' ', d_LINE_SIZE);
			
			sprintf(szStr, "NO. OF LITERS: %d", srTransRec.inFleetNumofLiters); //BDOCLG-00322 --jzg
			memset (baTemp, 0x00, sizeof(baTemp));		
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		/* BDO CLG: Fleet card support - end -- jzg */

		
		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		memset(szTemp1, ' ', d_LINE_SIZE);
		memset(szTemp3, ' ', d_LINE_SIZE);
		wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szTipAmount, szTemp3, AMT_BCD_SIZE);

        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		//1025 - ADD OFFLINE SALE
		if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == SALE_OFFLINE))
		{
			//Base amount
			memset(szStr, ' ', d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			
		  if (strTCT.fTipAllowFlag == CN_FALSE){	
				strcpy(szTemp6,"TOTAL:");
			
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			
				sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
				inPrintLeftRight(szTemp6,szAmountBuff,23);
		  }else{
					memset(szStr, 0x00, d_LINE_SIZE);
					memset(szAmountBuff,0x00,20);
					memset(szTemp4, 0x00, sizeof(szTemp4));
					memset(szTemp6,0x00, sizeof(szTemp6));
				strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change
					vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
					sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
					inPrintLeftRight(szTemp6,szAmountBuff,23);
					/*********************************************************/
					/*TIP*/
					memset(szStr, 0x00, d_LINE_SIZE);
					memset(szAmountBuff,0x00,20);
					memset(szTemp4, 0x00, sizeof(szTemp4));
					memset(szTemp6,0x00, sizeof(szTemp6));
					strcpy(szTemp6,"TIP:");
					if (atol(szTemp3)> 0){
						vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
						sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
					}
					inPrintLeftRight(szTemp6,szAmountBuff,23); 
					/*********************************************************/

				//CTOS_PrinterPutString("          _____________________");	// v10.0 change
					
					memset(szStr, 0x00, d_LINE_SIZE);
					memset(szAmountBuff,0x00,20);
					memset(szTemp4, 0x00, sizeof(szTemp4));
					memset(szTemp6,0x00, sizeof(szTemp6));
					strcpy(szTemp6,"TOTAL:");

					if (atol(szTemp3)> 0){	
						vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp4);// patrick add code 20141216 	
						sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
					}
					inPrintLeftRight(szTemp6,szAmountBuff,23); 
		  }
			
		}
		else if ((srTransRec.byTransType == SALE_TIP) ||(srTransRec.byOrgTransType == SALE_TIP))
		{

			//Base amount
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			if (srTransRec.byTransType == VOID)
				sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
			else
				sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,23);
            /*********************************************************/
            /*TIP*/
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"TIP:");
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
			if (srTransRec.byTransType == VOID)
				sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
			else
				sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,23); 
	 		/*********************************************************/

			//CTOS_PrinterPutString("          _____________________");	// v10.0 change
			
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"TOTAL:");
			
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp4);// patrick add code 20141216		
			if (srTransRec.byTransType == VOID)
				sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
			else
				sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,23); 
		
		}
		else
		{
			if ((strTCT.fTipAllowFlag == CN_TRUE) &&	(srTransRec.byTransType != PRE_AUTH) && (srTransRec.byTransType != CASH_ADVANCE))
			{
				//Base amount
				memset(szStr, 0x00, d_LINE_SIZE);
				memset(szAmountBuff,0x00,20);
				memset(szTemp4, 0x00, sizeof(szTemp4));
				memset(szTemp6,0x00, sizeof(szTemp6));
				strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			
				if (srTransRec.byTransType == VOID)
					sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
				else
					sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
				inPrintLeftRight(szTemp6,szAmountBuff,23);
							/*********************************************************/
							/*TIP*/
				memset(szStr, 0x00, d_LINE_SIZE);
				memset(szAmountBuff,0x00,20);
				memset(szTemp4, 0x00, sizeof(szTemp4));
				memset(szTemp6,0x00, sizeof(szTemp6));
				strcpy(szTemp6,"TIP:");

				
				if (atol(szTemp3)> 0)
				{
					vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
					if (srTransRec.byTransType == VOID)
						sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
					else
						sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
				}
				inPrintLeftRight(szTemp6,szAmountBuff,23); 
				/*********************************************************/
			
				//CTOS_PrinterPutString("          _____________________");	// v10.0 change
			}
		
			memset(szStr, ' ', d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"TOTAL:");

			if ((atol(szTemp3)> 0) || (srTransRec.byTransType == PRE_AUTH) || (srTransRec.byTransType == CASH_ADVANCE))
			{
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
				if (srTransRec.byTransType == VOID)
					sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
				else
					sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			}
			//fix for void receipt - if TIP is off
			else if ((strTCT.fTipAllowFlag == CN_FALSE) &&	(srTransRec.byTransType != PRE_AUTH) && (srTransRec.byTransType != CASH_ADVANCE)){
					vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
					if (srTransRec.byTransType == VOID)
						sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
					else
						sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
				
			}
			//fix for void receipt - if TIP is off
			inPrintLeftRight(szTemp6,szAmountBuff,23); 
		}

        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

		/* BDO CLG: Fleet card support - start -- jzg */
    if((srTransRec.fFleetCard == TRUE) && 
			(strTCT.fFleetGetLiters == TRUE) &&
			(strTCT.fGetDescriptorCode == TRUE)) /* BDOCLG-00347: should be controlled also be parameterized -- jzg */
		{
			//CTOS_PrinterFline(d_LINE_DOT * 1);
      vdCTOS_PrinterFline(1);
			
			memset(szStr, ' ', d_LINE_SIZE);
			memset (baTemp, 0x00, sizeof(baTemp));
			memset(szStr, ' ', d_LINE_SIZE);
			
			sprintf(szStr, "%s    %s", srTransRec.szFleetProductDesc, srTransRec.szFleetProductCode);
			memset (baTemp, 0x00, sizeof(baTemp));		
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

			//CTOS_PrinterFline(d_LINE_DOT * 2);
      vdCTOS_PrinterFline(2);
			
		}
		/* BDO CLG: Fleet card support - end -- jzg */

		//gcitra-012015 
		//if((srTransRec.byOffline == CN_TRUE) && (srTransRec.byTransType != SALE_TIP)){
    if ((srTransRec.byOffline == CN_TRUE) && (srTransRec.byTransType == SALE_OFFLINE)){ //aaronnino for BDOCLG ver 9.0 fix on issue #00068 No "offline entered" on offline sale with tip adjust receipt 2 of 3
		  //CTOS_PrinterFline(d_LINE_DOT * 1);
		  vdCTOS_PrinterFline(1);
			vdPrintCenter("* Completion/Checkout Entered *");
		}
		//gcitra-012015


	    #if 0 	// v10.0 change start - move up
		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
			/* EMV: Revised EMV details printing - start -- jzg */
			(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
			(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
			(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
			/* EMV: Revised EMV details printing - end -- jzg */
		{
			CTOS_PrinterFline(d_LINE_DOT * 1);

			/* EMV: Get Application Label - start -- jzg */
			memset(szStr, ' ', d_LINE_SIZE);
			sprintf(szStr, "APP.: %s", srTransRec.stEMVinfo.szChipLabel);
			memset (baTemp, 0x00, sizeof(baTemp));		
			CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			/* EMV: Get Application Label - end -- jzg */

			//AC
			//issue-00770
			if (srTransRec.byTransType != SALE_OFFLINE && srTransRec.byOrgTransType!= SALE_OFFLINE){
				wub_hex_2_str(srTransRec.stEMVinfo.T9F26, szTemp, 8);
				sprintf(szStr, "TC: %s", szTemp);
				memset (baTemp, 0x00, sizeof(baTemp));		
				CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
				CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);	
			}
			//AID
			memset(szStr, ' ', d_LINE_SIZE);
            EMVtagLen = srTransRec.stEMVinfo.T84_len;
			memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
			memcpy(EMVtagVal, srTransRec.stEMVinfo.T84, EMVtagLen);
			memset(szTemp, ' ', d_LINE_SIZE);
			wub_hex_2_str(EMVtagVal, szTemp, EMVtagLen);
			sprintf(szStr, "AID: %s",szTemp);
			memset (baTemp, 0x00, sizeof(baTemp));		
			CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		}
		#endif 	// v10.0 change end
		
	}


//1027
	else if(d_THIRD_PAGE == page)
	{
		#if 0	// v10.0 change start
		vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		
		if (srTransRec.byEntryMode == CARD_ENTRY_WAVE)
		{	
			memset(szStr, 0x00, sizeof(szStr));
			strcpy(szStr, "CONTACTLESS");
			vdPrintCenter(szStr);
		}
	
	if (srTransRec.byEntryMode == CARD_ENTRY_WAVE)
	{	
		memset(szStr, 0x00, sizeof(szStr));
		strcpy(szStr, "CONTACTLESS");
		vdPrintCenter(szStr);
	}
	#endif	// v10.0 change start
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		printTIDMID(); 

	    printBatchInvoiceNO();	// v10.0 change: move from below

		/* BDOCLG-00136: "CONTACTLESS" should be printed before cardtype - start -- jzg */

		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		/* BDOCLG-00136: "CONTACTLESS" should be printed before cardtype - end -- jzg */
		
		//card type
		memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
		EMVtagLen = 0;
		memset(szStr, ' ', d_LINE_SIZE);
		vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);
	  	//aaronnino for BDOCLG ver 9.0 fix on issue #00134 No ENTRY MODE indicated in the receipt if card was SWIPE,CHIP or FALLBACK  3 of 3 start
		switch(srTransRec.byEntryMode)
		{
			case CARD_ENTRY_MSR:
			 strcat(szPOSEntry, "SWIPE");
			 break;
			case CARD_ENTRY_MANUAL:
			 strcat(szPOSEntry, "MANUAL");
			 break;
			case CARD_ENTRY_ICC:
			 strcat(szPOSEntry, "CHIP");	 
			 break;
			case CARD_ENTRY_FALLBACK:
			 strcat(szPOSEntry, "FALLBACK");	 
			 break;
		}

		#if 0	// v10.0 change start
		if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
			(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
			(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
			(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC)){
		
			memset(szStr, ' ', d_LINE_SIZE);
			EMVtagLen = srTransRec.stEMVinfo.T84_len;
			memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
			memcpy(EMVtagVal, srTransRec.stEMVinfo.T84, EMVtagLen);
			memset(szTemp, ' ', d_LINE_SIZE);
			wub_hex_2_str(EMVtagVal, szTemp, EMVtagLen);
			sprintf(szStr, "AID: %s",szTemp);
			
			vdStrCat2(srTransRec.szCardLable, szTemp, 21, szStr);
		
		}else{	
			strcpy(szStr, srTransRec.szCardLable);
		}
		
		//vdStrCat2(srTransRec.szCardLable, szPOSEntry, 21, szStr);

	  	//aaronnino for BDOCLG ver 9.0 fix on issue #00134 No ENTRY MODE indicated in the receipt if card was SWIPE,CHIP or FALLBACK  3 of 3 end
		vdMyEZLib_LogPrintf("Card label: %s",srTransRec.szCardLable);
		
		memset (baTemp, 0x00, sizeof(baTemp));
		CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
		#endif	// v10.0 change start
		
		//pan
		memset(szTemp5, 0x00, sizeof(szTemp5));
				
		//BDO: Enable PAN Masking for each receipt - start -- jzg
#if 0
		strcpy(szTemp5, srTransRec.szPAN);
		cardMasking(szTemp5, PRINT_CARD_MASKING_3);
#else
		//aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 6 of 21
		if(strTCT.inCustomerCopy == 3)
			vdCTOS_FormatPAN2(strIIT.szMaskCustomerCopy, srTransRec.szPAN, szTemp5);
		if(strTCT.inBankCopy == 3)
			vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp5);
		if(strTCT.inMerchantCopy == 3)
			vdCTOS_FormatPAN2(strIIT.szMaskMerchantCopy, srTransRec.szPAN, szTemp5);
		//aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 6 of 21
#endif
						//BDO: Enable PAN Masking for each receipt - end -- jzg
				
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		memset(szTemp6, 0x00, sizeof(szTemp6));
		memset(szTemp4, 0x00, sizeof(szTemp4));
		
		if (strlen(srTransRec.szPAN) > 16)
			vdRemoveSpace(szTemp6, szTemp5);		
		else
			strcpy(szTemp6, szTemp5);
				
		strcpy(szTemp4, szTemp6);
		
		#if 0
//issue-00255 - Align PAN and Entry mode - normal Font size	
        inPrintLeftRight(szTemp4,szPOSEntry,42);
//end
		#else	// v10.0 change
		memset(szStr, 0x00, sizeof(szStr));
		vdCTOS_Pad_String(szTemp4, 33, ' ', POSITION_RIGHT);
		sprintf(szStr, "%s%s", szTemp4, szPOSEntry);
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		#endif
	
	//card holder name
	printCardHolderName();

	//Trans type
	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

	memset(szStr, 0x00, sizeof(szStr));
	memset(szStr, 0x00, sizeof(szStr));
	
	if (srTransRec.byTransType == PRE_AUTH)
		strcpy(szStr,"CARD VERIFY");
	else if (srTransRec.byTransType == CASH_ADVANCE)
		strcpy(szStr,"CASH ADVANCE");
		else if ((srTransRec.byTransType == SALE) &&	// v10.0 change
			(srTransRec.byEntryMode == CARD_ENTRY_WAVE))
			strcpy(szStr,"CONTACTLESS SALE");
		else if ((srTransRec.byTransType == SALE) &&	// v10.0 change
			(srTransRec.byEntryMode != CARD_ENTRY_WAVE))
			strcpy(szStr,"CREDIT SALE");
	else
		szGetTransTitle(srTransRec.byTransType, szStr); 

		#if 0
	memset (baTemp, 0x00, sizeof(baTemp));
	CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		#else	// v10.0 change
		vdPrintCenter(szStr);
		#endif

		if (srTransRec.byTransType == PRE_AUTH)
			strcpy(szStr,"CARD VERIFY");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	//Issue# 000164 - start -- jzg
	//issue-00244 - Only print policy number for sale
	//if ((strIIT.fGetPolicyNumber == TRUE) && (srTransRec.byTransType == SALE))/* BDO-00060: Policy number should be per issuer -- jzg */
	if ((strIIT.fGetPolicyNumber == TRUE) && (strlen(srTransRec.szPolicyNumber) > 0))
	{
		memset(szStr, 0, d_LINE_SIZE);
		memset (baTemp, 0x00, sizeof(baTemp));
		sprintf(szStr, "POLICY NO. %s", srTransRec.szPolicyNumber);
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	}
	//Issue# 000164 - end -- jzg

	/* Issue# 000096: BIN VER Checking - start -- jzg*/
	if (srTransRec.fBINVer)
		{
			//BIN Ver
			vdDebug_LogPrintf("fBINVer = [%d]", fBINVer);
			vdDebug_LogPrintf("BIN Ver STAN = [%s]", szBINVerSTAN);
			
			memset(szStr, 0, d_LINE_SIZE);
			memset(baTemp, 0, sizeof(baTemp)); //BDO: Fix for overlapping BIN Check line on receipt --sidumili
			vdCTOS_Pad_String(srTransRec.szBINVerSTAN, 6, '0', POSITION_LEFT);   //sidumili: modified using stTransRec to get record during reprint/void
			sprintf(szStr, "BIN CHECK: %s", srTransRec.szBINVerSTAN);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	}
	/* Issue# 000096: BIN VER Checking - end -- jzg*/

	//Issue# 000164 - start -- jzg
	//issue-00244 - Only print policy number for sale
	//if ((strIIT.fGetPolicyNumber == TRUE) && (srTransRec.byTransType == SALE))/* BDO-00060: Policy number should be per issuer -- jzg */
	if ((strIIT.fGetPolicyNumber == TRUE) && (strlen(srTransRec.szPolicyNumber) > 0))
	{
		memset(szStr, 0, d_LINE_SIZE);
		memset (baTemp, 0x00, sizeof(baTemp));
		sprintf(szStr, "POLICY NO. %s", srTransRec.szPolicyNumber);
		CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	}
	//Issue# 000164 - end -- jzg
		
	
	//BDO: Moved and reformatted approval code line - start -- jzg
	//Reference num
	memset(szStr, ' ', d_LINE_SIZE);
	memset (baTemp, 0x00, sizeof(baTemp));
	memset(szStr, ' ', d_LINE_SIZE);
	
	
	//Approval Code
	memset(szStr, ' ', d_LINE_SIZE);
	memset (baTemp, 0x00, sizeof(baTemp));					
	memset(szStr, ' ', d_LINE_SIZE);

	//aaronnino for BDOCLG ver 9.0 fix on issue #00066 "APPR.CODE" single width printed on transaction receipt 8 of 8 start
	if (strTCT.fDutyFreeMode == TRUE){
			printDateTime();	// v10.0 change
	
	   //Reference num
	   sprintf(szStr, "REF. NO. %s", srTransRec.szRRN);
	   memset (baTemp, 0x00, sizeof(baTemp));	   
	   //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	   //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	   inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		
	   vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);  
	   sprintf(szStr, "APPR. CODE: %s", srTransRec.szAuthCode);
	   vdCTOS_Pad_String(szStr, 23, ' ', POSITION_LEFT);
	   memset (baTemp, 0x00, sizeof(baTemp));	   
	   //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	   //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	   inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	   vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	}else{
			printDateTimeAndApprovalCode();	// v10.0 change
		 vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
			if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||	// v10.0 change - depends on srTransRec.byEntryMode
				/* EMV: Revised EMV details printing - start -- jzg */
				(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
				(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
				(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
				(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
				//(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||	
				(srTransRec.bWaveSID == 0x63) ||
				(srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
				(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
				/* EMV: Revised EMV details printing - end -- jzg */
			{
				if(strlen(srTransRec.szRRN) <= 0)
					//sprintf(szStr, "REF. NO.               APPR. CODE: %s",srTransRec.szAuthCode);
					sprintf(szStr, "RRN:                     APP: %s",srTransRec.szCardLable);	// v10.0 change
				else
					//sprintf(szStr, "REF. NO. %s  APPR. CODE: %s", srTransRec.szRRN,srTransRec.szAuthCode);
					sprintf(szStr, "RRN: %s        APP: %s", srTransRec.szRRN,srTransRec.szCardLable);	// v10.0 change
			}
			else	// v10.0 change - depends on srTransRec.byEntryMode
			{
				if(strlen(srTransRec.szRRN) <= 0)
					strcpy(szStr, "RRN:");
				else
					sprintf(szStr, "RRN: %s", srTransRec.szRRN);
			}
			memset (baTemp, 0x00, sizeof(baTemp)); 	 
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		//BDO: Moved and reformatted approval code line - end -- jzg

		// v10.0 change start
		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		memset(szTemp1, ' ', d_LINE_SIZE);
		if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
			/* EMV: Revised EMV details printing - start -- jzg */
			//(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
			(srTransRec.bWaveSID == 0x65) ||
			(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
			(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
			//(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||
			(srTransRec.bWaveSID == 0x63) ||
			(srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
			(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
			/* EMV: Revised EMV details printing - end -- jzg */
		{
			//AID
			memset(szStr, ' ', d_LINE_SIZE);
            EMVtagLen = srTransRec.stEMVinfo.T84_len;
			memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
			memcpy(EMVtagVal, srTransRec.stEMVinfo.T84, EMVtagLen);
			memset(szTemp, ' ', d_LINE_SIZE);
			wub_hex_2_str(EMVtagVal, szTemp1, EMVtagLen);
			
			//TC
			//issue-00770
			if (srTransRec.byTransType != SALE_OFFLINE && srTransRec.byOrgTransType!= SALE_OFFLINE){
				wub_hex_2_str(srTransRec.stEMVinfo.T9F26, szTemp, 8);
				sprintf(szStr, "TC: %s   AID: %s", szTemp, szTemp1);
			}
			else
			{
				if (srTransRec.byEntryMode == CARD_ENTRY_WAVE)
				{
					wub_hex_2_str(srTransRec.stEMVinfo.T9F26, szTemp, 8);
					sprintf(szStr, "TC: %s   AID: %s", szTemp, szTemp1);
				}
				else
				sprintf(szStr, "                    AID: %s",szTemp1);
			}
			
			memset (baTemp, 0x00, sizeof(baTemp));		
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		// v10.0 change end

	/* BDO CLG: Fleet card support - start -- jzg */
	if((srTransRec.fFleetCard == TRUE) && (strTCT.fFleetGetLiters == TRUE)) /* BDOCLG-00347: should be controlled also be parameterized -- jzg */
	{
		memset(szStr, ' ', d_LINE_SIZE);
		memset (baTemp, 0x00, sizeof(baTemp));
		memset(szStr, ' ', d_LINE_SIZE);
		
		sprintf(szStr, "NO. OF LITERS: %d", srTransRec.inFleetNumofLiters); //BDOCLG-00322 --jzg
		memset (baTemp, 0x00, sizeof(baTemp));		
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	}
	/* BDO CLG: Fleet card support - end -- jzg */

	memset(szStr, ' ', d_LINE_SIZE);
	memset(szTemp, ' ', d_LINE_SIZE);
	memset(szTemp1, ' ', d_LINE_SIZE);
	memset(szTemp3, ' ', d_LINE_SIZE);
	wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
	wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
	wub_hex_2_str(srTransRec.szTipAmount, szTemp3, AMT_BCD_SIZE);
	
	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	//1025 - ADD OFFLINE SALE
	if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == SALE_OFFLINE))
	{
		//Base amount
		memset(szStr, ' ', d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
		if (strTCT.fTipAllowFlag == CN_FALSE){	
			strcpy(szTemp6,"TOTAL:");
		
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
		
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,23);
		}else{
				memset(szStr, 0x00, d_LINE_SIZE);
				memset(szAmountBuff,0x00,20);
				memset(szTemp4, 0x00, sizeof(szTemp4));
				memset(szTemp6,0x00, sizeof(szTemp6));
				strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
				sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
				inPrintLeftRight(szTemp6,szAmountBuff,23);
				/*********************************************************/
				/*TIP*/
				memset(szStr, 0x00, d_LINE_SIZE);
				memset(szAmountBuff,0x00,20);
				memset(szTemp4, 0x00, sizeof(szTemp4));
				memset(szTemp6,0x00, sizeof(szTemp6));
				strcpy(szTemp6,"TIP:");
				if (atol(szTemp3)> 0){
					vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
					sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
				}
				inPrintLeftRight(szTemp6,szAmountBuff,23); 
				/*********************************************************/

				//CTOS_PrinterPutString("          _____________________");	// v10.0 change
				
				
				memset(szStr, 0x00, d_LINE_SIZE);
				memset(szAmountBuff,0x00,20);
				memset(szTemp4, 0x00, sizeof(szTemp4));
				memset(szTemp6,0x00, sizeof(szTemp6));
				strcpy(szTemp6,"TOTAL:");
		
				if (atol(szTemp3)> 0){ 
					vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp4);// patrick add code 20141216 	
					sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
				}
				inPrintLeftRight(szTemp6,szAmountBuff,23); 
		}
	}
	else if ((srTransRec.byTransType == SALE_TIP) || (srTransRec.byOrgTransType == SALE_TIP))
	{
	
		//Base amount
		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
		if (srTransRec.byTransType == VOID)
			sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
		else
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
		inPrintLeftRight(szTemp6,szAmountBuff,23);
		/*********************************************************/
		/*TIP*/
		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
		strcpy(szTemp6,"TIP:");
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
		if (srTransRec.byTransType == VOID)
			sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
		else
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
		inPrintLeftRight(szTemp6,szAmountBuff,23); 
		/*********************************************************/

			//CTOS_PrinterPutString("          _____________________");	// v10.0 change
		
		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
		strcpy(szTemp6,"TOTAL:");
		
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp4);// patrick add code 20141216		
		if (srTransRec.byTransType == VOID)
			sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
		else
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
		inPrintLeftRight(szTemp6,szAmountBuff,23); 
	
	}
	else
	{
		if ((strTCT.fTipAllowFlag == CN_TRUE) &&  (srTransRec.byTransType != PRE_AUTH) && (srTransRec.byTransType != CASH_ADVANCE))
		{
			//Base amount
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
				strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		

			if (srTransRec.byTransType == VOID)
				sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
			else
				sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,23);
			/*********************************************************/
			/*TIP*/
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"TIP:");

			if (atol(szTemp3)> 0)
			{
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
				if (srTransRec.byTransType == VOID)
					sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
				else
					sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			}
			inPrintLeftRight(szTemp6,szAmountBuff,23); 
			/*********************************************************/

				//CTOS_PrinterPutString("          _____________________");	// v10.0 change
		}

		memset(szStr, ' ', d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
		strcpy(szTemp6,"TOTAL:");

		if ((atol(szTemp3)> 0) || (srTransRec.byTransType == PRE_AUTH) || (srTransRec.byTransType == CASH_ADVANCE))
		{
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			if (srTransRec.byTransType == VOID)
				sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
			else
				sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
		}
		//fix for void receipt - if TIP is off
		else if ((strTCT.fTipAllowFlag == CN_FALSE) &&	(srTransRec.byTransType != PRE_AUTH) && (srTransRec.byTransType != CASH_ADVANCE)){
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
				if (srTransRec.byTransType == VOID)
					sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
				else
					sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			
		}
		//fix for void receipt - if TIP is off
		inPrintLeftRight(szTemp6,szAmountBuff,23); 
	}
	
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	/* BDO CLG: Fleet card support - start -- jzg */
	if((srTransRec.fFleetCard == TRUE) && 
		(strTCT.fFleetGetLiters == TRUE) &&
		(strTCT.fGetDescriptorCode == TRUE)) /* BDOCLG-00347: should be controlled also be parameterized -- jzg */
	{
		//CTOS_PrinterFline(d_LINE_DOT * 1);
    vdCTOS_PrinterFline(1);
		
		memset(szStr, ' ', d_LINE_SIZE);
		memset (baTemp, 0x00, sizeof(baTemp));
		memset(szStr, ' ', d_LINE_SIZE);
		
		sprintf(szStr, "%s    %s", srTransRec.szFleetProductDesc, srTransRec.szFleetProductCode);
		memset (baTemp, 0x00, sizeof(baTemp));		
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	
		//CTOS_PrinterFline(d_LINE_DOT * 2);
		vdCTOS_PrinterFline(2);
	}
	/* BDO CLG: Fleet card support - end -- jzg */

	//gcitra-012015 
	//if((srTransRec.byOffline == CN_TRUE) && (srTransRec.byTransType != SALE_TIP)){
 if ((srTransRec.byOffline == CN_TRUE) && (srTransRec.byTransType == SALE_OFFLINE)){ //aaronnino for BDOCLG ver 9.0 fix on issue #00068 No "offline entered" on offline sale with tip adjust receipt 3 of 3
	  //CTOS_PrinterFline(d_LINE_DOT * 1);
	  vdCTOS_PrinterFline(1);
		vdPrintCenter("* Completion/Checkout Entered *");
	}
	//gcitra-012015
	
	
		#if 0 	// v10.0 change start - move up
	memset(szStr, ' ', d_LINE_SIZE);
	memset(szTemp, ' ', d_LINE_SIZE);
	if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
		/* EMV: Revised EMV details printing - start -- jzg */
		(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
		(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
		(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
		(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
		(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
		/* EMV: Revised EMV details printing - end -- jzg */
	{
		CTOS_PrinterFline(d_LINE_DOT * 1);
	
		/* EMV: Get Application Label - start -- jzg */
		memset(szStr, ' ', d_LINE_SIZE);
		sprintf(szStr, "APP.: %s", srTransRec.stEMVinfo.szChipLabel);
		memset (baTemp, 0x00, sizeof(baTemp));		
		CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		/* EMV: Get Application Label - end -- jzg */
	
		//AC
		//issue-00770
		if (srTransRec.byTransType != SALE_OFFLINE && srTransRec.byOrgTransType!= SALE_OFFLINE){
			wub_hex_2_str(srTransRec.stEMVinfo.T9F26, szTemp, 8);
			sprintf(szStr, "TC: %s", szTemp);
			memset (baTemp, 0x00, sizeof(baTemp));		
			CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);	
		}
		//AID
		memset(szStr, ' ', d_LINE_SIZE);
		EMVtagLen = srTransRec.stEMVinfo.T84_len;
		memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
		memcpy(EMVtagVal, srTransRec.stEMVinfo.T84, EMVtagLen);
		memset(szTemp, ' ', d_LINE_SIZE);
		wub_hex_2_str(EMVtagVal, szTemp, EMVtagLen);
		sprintf(szStr, "AID: %s",szTemp);
		memset (baTemp, 0x00, sizeof(baTemp));		
		CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	}
		#endif 	// v10.0 change end
	
}

//1027
	return d_OK;	
	
}
#endif

USHORT ushCTOS_PrintBody(int page)
{	
    char szStr[d_LINE_SIZE + 3];
    char szTemp[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    char szTemp3[d_LINE_SIZE + 1];
    char szTemp4[d_LINE_SIZE + 1];
    char szTemp5[d_LINE_SIZE + 1];
    char szFormatPAN[strlen(srTransRec.szPAN) + 7];//to account for space as in PAN format and to include additional PAN no. 7 has been added -Meena 08/01/2012
    int inFmtPANSize;
    BYTE baTemp[PAPER_X_SIZE * 64];
    USHORT result;
    int num,i,inResult;
    unsigned char tucPrint [24*4+1];	
    BYTE   EMVtagVal[64];
    USHORT EMVtagLen; 
    short spacestring;
    BYTE   key;
   	BOOL fCTLSEMVCheck = CN_FALSE;
    char szAmountBuff[20], szTemp6[47];
    int inPADSize,x;
    char szSPACE[40];
    char szPOSEntry[21] = {0}; /* BDOCLG-00134: Reformat cardtype line -- jzg */
	char szFxRate[d_LINE_SIZE + 3];
	int inLength;
	float inMarkup=0;
	char szOutAID[d_LINE_SIZE + 1] = {0};

	//version16
	int inMasking;
	//inMasking = strIIT.inMaskIDS; ;
	char szMaskAID[20];
	char chPadChar='0';

	if (strIIT.inIssuerNumber == 2){ 
		inMasking = get_env_int("VisaMaskIDS");
    }else if (strIIT.inIssuerNumber == 21){
        if (srTransRec.szPAN[0] == '4')
			inMasking = get_env_int("VisaMaskIDS");
		else
			inMasking = 1;
    }else{
		inMasking = 1;
    }

	//version16

    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    /* tid mid */
    printTIDMID(FALSE); 
    
    /* batch invoice no. */
	if(strFLG.fLargeInvoice)
   		printBatchInvoiceNOEx();
	else
    	printBatchInvoiceNO();
    /* card no. */
    memset(szTemp5, 0x00, sizeof(szTemp5));
    //BDO: Enable PAN Masking for each receipt - start -- jzg
    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 4 of 21
    if(page == CUSTOMER_COPY_RECEIPT)
        vdCTOS_FormatPAN2(strIIT.szMaskCustomerCopy, srTransRec.szPAN, szTemp5);
    else if(page == MERCHANT_COPY_RECEIPT)
        vdCTOS_FormatPAN2(strIIT.szMaskMerchantCopy, srTransRec.szPAN, szTemp5);
    else if(page == BANK_COPY_RECEIPT)
        vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp5);
    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 4 of 21
    
    vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 1, 0);
    memset(szTemp6, 0x00, sizeof(szTemp6));
    memset(szStr, 0x00, sizeof(szStr));
    
    if (strlen(srTransRec.szPAN) > 16)
        vdRemoveSpace(szStr, szTemp5);		
    else
        strcpy(szStr, szTemp5);
    
	inPrint(szStr);

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

    if(strTCT.fSMMode && strTCT.fPrintIssuerID)
	{
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "ISSUER ID: %02d", strHDT.inIssuerID);
		inPrint(szStr);
	}
		
    if ((strIIT.fGetPolicyNumber == TRUE) && (strlen(srTransRec.szPolicyNumber) > 0))
    {
        memset(szStr, 0x00, d_LINE_SIZE);
        sprintf(szStr, "POLICY NO: %s", srTransRec.szPolicyNumber);
        inPrint(szStr);
    }

	
	if(srTransRec.fBINVer)
	{
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "BIN CHECK: %06ld", atol(srTransRec.szBINVerSTAN));
		inPrint(szStr);
	}

    /* card holder name */
    printCardHolderName();
    
    /*Trans type*/
    memset(szStr, 0x00, sizeof(szStr));
    if (srTransRec.byTransType == PRE_AUTH)
        strcpy(szStr,"CARD VERIFY");
    else if(srTransRec.byTransType == CASH_ADVANCE)
        strcpy(szStr,"CASH ADVANCE");
    else if(srTransRec.byTransType == VOID && srTransRec.byOrgTransType == CASH_ADVANCE)
        strcpy(szStr,"CASH ADVANCE VOID");
	//version16
    else if(srTransRec.byTransType == VOID_PREAUTH)
        strcpy(szStr,"VOID PREAUTH");
	//version16
    else
        szGetTransTitle(srTransRec.byTransType, szStr); 
    
    vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
    if ((srTransRec.byTransType == SALE||srTransRec.byTransType == SALE_OFFLINE) && (srTransRec.byEntryMode == CARD_ENTRY_WAVE))
        vdPrintCenter("CONTACTLESS SALE");
	else if ((srTransRec.byTransType == VOID) && (srTransRec.byEntryMode == CARD_ENTRY_WAVE))
        vdPrintCenter("CONTACTLESS VOID");
    else
    {
		//memset (baTemp, 0x00, sizeof(baTemp));
        //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
        //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		vdPrintCenter(szStr);  
    }
    
    /* date time entry mode */
    switch(srTransRec.byEntryMode)
    {
        case CARD_ENTRY_MSR:
            strcat(szPOSEntry, "S");
        break;

        case CARD_ENTRY_MANUAL:
            strcat(szPOSEntry, "M");
        break;

        case CARD_ENTRY_ICC:
            strcat(szPOSEntry, "C");   
        break;

        case CARD_ENTRY_FALLBACK:		
			if((srTransRec.szServiceCode[0] == '2') || (srTransRec.szServiceCode[0] == '6'))
            	strcat(szPOSEntry, "F");  
			else			
            	strcat(szPOSEntry, "S");
        break;
    }

	
    printDateTimeAndOther(szPOSEntry, 23);	
	
    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

    /* card type approval code */
    memset(szTemp, 0x00, d_LINE_SIZE);
    memset(szTemp1, 0x00, d_LINE_SIZE);
	memset(szTemp3, 0x00, d_LINE_SIZE);
	if (srTransRec.byEntryMode == CARD_ENTRY_WAVE && (srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_2 || srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC || srTransRec.bWaveSID == d_VW_SID_AE_EMV || srTransRec.bWaveSID == d_VW_SID_CUP_EMV || srTransRec.bWaveSID == 0x63 || srTransRec.bWaveSID == 0x65 || srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP  || srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS))
		fCTLSEMVCheck = CN_TRUE;
	
    if (inGetATPBinRouteFlag() == TRUE){
		if( fCTLSEMVCheck || srTransRec.byEntryMode == CARD_ENTRY_ICC || strcmp("SMGUARNTR",srTransRec.szCardLable) == 0 || 
			strcmp("SMADVNTGE",srTransRec.szCardLable) == 0 || strcmp("SHOP CARD",srTransRec.szCardLable) == 0|| 
			strcmp("FLEET",srTransRec.szCardLable) == 0 || strcmp("CASHCARD",srTransRec.szCardLable) == 0 || 
			strcmp("BDOREWARDS",srTransRec.szCardLable) == 0 )
			strcpy(szTemp3,srTransRec.szCardLable);
		else if(srTransRec.inCardType == DEBIT_CARD)
			strcpy(szTemp3,"DEBIT");
		else if (srTransRec.inCardType == CREDIT_CARD){	

			if (srTransRec.fFleetCard == TRUE)	
				strcpy(szTemp3,srTransRec.szCardLable);
			else
				strcpy(szTemp3,"CREDIT");
		}	
    }
	else
		strcpy(szTemp3,srTransRec.szCardLable);
	
	vdDebug_LogPrintf("ushCTOS_PrintBody srTransRec.szCardLable=[%s][%d]", srTransRec.szCardLable, strlen(szTemp3));
	
    if(strTCT.fDutyFreeMode)
    {
       if (strcmp(szTemp3,"CITI VISA")==0)
           sprintf(szTemp,"CARD TYPE: VISA", szTemp3);
       else if (strcmp(szTemp3,"CITI MASTER")==0)
           sprintf(szTemp,"CARD TYPE: MASTERCARD", szTemp3);
       else
	   {
	   		//00197 - Card type value missing on  BDO loaylty redemption sale receipt
     		if (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX){
				
				vdDebug_LogPrintf("ushCTOS_PrintBody XXX");

				if(strlen(szTemp3) <= 0)
					strcpy(szTemp3,"BDO LOYALTY");
     		}	

           	sprintf(szTemp,"CARD TYPE: %s", szTemp3);
       }

		//change request hardcode approval code for BDO loyalty
		if (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX)
			sprintf(szTemp1,"APP CODE: 000002");
		else
    		sprintf(szTemp1,"APP CODE: %s", srTransRec.szAuthCode);
       inPrint(szTemp);
       vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
       //inPrintLeftRight("",szTemp1,23);
       inPrint(szTemp1);
	   vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	}
	else
	{
     	if (strcmp(szTemp3,"CITI VISA")==0)
     	{
     	   	memset(szTemp3,"",sizeof(szTemp3));
			strcpy(szTemp3,"VISA");
         	sprintf(szTemp,"CARD TYPE:%-12.12sAPP CODE: %s", szTemp3,srTransRec.szAuthCode);
     	}else if (strcmp(szTemp3,"CITI MASTER")==0)
     	{
     	   	memset(szTemp3,"",sizeof(szTemp3));
			strcpy(szTemp3,"MASTERCARD");
         	sprintf(szTemp,"CARD TYPE:%-12.12sAPP CODE: %s", szTemp3,srTransRec.szAuthCode);
     	}else{

			vdDebug_LogPrintf("ushCTOS_PrintBody NOT strTCT.fDutyFreeMode [%d][%d][%d]", srTransRec.HDTid, srTransRec.byTransType, strlen(szTemp3));
		
     		if (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX && srTransRec.byTransType == POINTS_INQUIRY)
				sprintf(szTemp,"CARD TYPE:%-12.12s", szTemp3);	
			else{
				//change request hardcode approval code for BDO loyalty
				if (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX){

					//00215 - Missing BDO Loyalty in card type  redemption sale receipt				
					if(strlen(szTemp3) <= 0)
						strcpy(szTemp3,"BDO LOYALTY");					

					sprintf(szTemp,"CARD TYPE:%-12.12sAPP CODE: 000002", szTemp3);
				}
				else	
 		    		sprintf(szTemp,"CARD TYPE:%-12.12sAPP CODE: %s", szTemp3,srTransRec.szAuthCode);
			}
     	}
		vdDebug_LogPrintf("card type line = %s", szTemp);
 		inPrint(szTemp);
	}
	
	if(srTransRec.fDCC)
	{
		if(inFLGGet("fPrintForExRate") == TRUE)
		{
			inLength=strlen(srTransRec.szDCCFXRate)-srTransRec.inDCCFXRateMU;
			memset(szFxRate,0x00,sizeof(szFxRate));
			memcpy(szFxRate,srTransRec.szDCCFXRate,inLength);
			memcpy(&szFxRate[inLength],".",1);
			memcpy(&szFxRate[inLength+1],&srTransRec.szDCCFXRate[inLength],srTransRec.inDCCFXRateMU);
			
			memset(szStr,0x00,d_LINE_SIZE);
			sprintf(szStr, "ExR: %s 1.00 = %s %s", srTransRec.szDCCLocalSymbol, srTransRec.szDCCCurSymbol, szFxRate);	
			inPrint(szStr);
		}
		
		if(inFLGGet("fPrintDCCMarkUp") == TRUE)
		{
			memset(szTemp,0x00,sizeof(szTemp));
			memset(szStr,0x00,sizeof(szStr));
			inMarkup = atof(srTransRec.szDCCMarkupPer);
			sprintf(szTemp,"%.2f",inMarkup);
			sprintf(szStr,"M-UP: %s",szTemp);
			strcat(szStr,"%");
			inPrint(szStr);
		}
	}
	
    /*Reference num*/
	memset(szTemp, 0x00, d_LINE_SIZE);
    memset(szTemp1, 0x00, d_LINE_SIZE);
	
    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	vdDebug_LogPrintf("ushCTOS_PrintBody srTransRec.byEntryMode=[%d]", srTransRec.byEntryMode);

	
	//00129 - Missing RRN in transaction receipt when performing CREDIT SALE or DCC SALE via fallback and manual #1
    if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) || (srTransRec.byEntryMode == CARD_ENTRY_FALLBACK) ||
    /* EMV: Revised EMV details printing - start -- jzg */
    //(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||  
    (srTransRec.bWaveSID == 0x65) ||
    (srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
    (srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
    //(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||
    (srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
    (srTransRec.bWaveSID == 0x63) ||
    (srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
    (srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
    /* EMV: Revised EMV details printing - end -- jzg */
    {	
		//00129 - Missing RRN in transaction receipt when performing CREDIT SALE or DCC SALE via fallback and manual #2
		if(srTransRec.byEntryMode != CARD_ENTRY_FALLBACK)
			sprintf(szTemp,"RRN: %-17.17sAPP:%s", srTransRec.szRRN,srTransRec.stEMVinfo.szChipLabel);
		else
			sprintf(szTemp,"RRN: %-17.17s", srTransRec.szRRN);
			
		//sprintf(szTemp,"RRN: %-17.17sAPP:%s", srTransRec.szRRN,srTransRec.szCardLable);
        //sprintf(szTemp1,"APP: %s", srTransRec.szCardLable);
		//inPrintLeftRight(szTemp,szTemp1,42);
    }
    else	// v10.0 change - depends on srTransRec.byEntryMode
    {
       	//version16
     	//if (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX && srTransRec.byTransType != POINTS_INQUIRY)
     	//fix for RRN not being printed if manual entry
     	if (srTransRec.byTransType != POINTS_INQUIRY)
        	sprintf(szTemp, "RRN: %-17.17s", srTransRec.szRRN);
		//inPrint(szStr);
    }

    inPrint(szTemp);

    /* AID TC */
    memset(szStr, ' ', sizeof(szStr));
    memset(szTemp, ' ', sizeof(szTemp));
    memset(szTemp1, ' ', sizeof(szTemp1));
    memset(szTemp3, ' ', sizeof(szTemp3));
    memset(szTemp4, ' ', sizeof(szTemp4));
    if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
    /* EMV: Revised EMV details printing - start -- jzg */
    //(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||    
    (srTransRec.bWaveSID == 0x65) ||
    (srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
    (srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
    (srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
    (srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
    //(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||
    
    (srTransRec.bWaveSID == 0x63) ||
    (srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
    
    /* EMV: Revised EMV details printing - end -- jzg */
    {
        //AID
        EMVtagLen = srTransRec.stEMVinfo.T84_len;
        memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
        memcpy(EMVtagVal, srTransRec.stEMVinfo.T84, EMVtagLen);
        wub_hex_2_str(EMVtagVal, szTemp, EMVtagLen);


        //version16
   	 	if (inMasking == 0){ 
			memset(szOutAID, 0x00, sizeof(szOutAID));
			//return d_OK;
			//do nothing
    	}else if (inMasking == 1){
			memset(szOutAID, 0x00, sizeof(szOutAID));
			strcpy(szOutAID, szTemp);
    	}else if (inMasking == 2){
    		memset(szMaskAID, 0x00, sizeof(szMaskAID));
			inCTOSS_GetEnvDB("VisaMaskAID",szMaskAID);

    	    if (strlen (szMaskAID) < 15 && strlen (szMaskAID) > 0){
				chPadChar = szMaskAID[0];
            	vdCTOS_Pad_String(szMaskAID, 15, chPadChar, POSITION_RIGHT);
            }

    	    vdDebug_LogPrintf("mask AID %s", szMaskAID);
    		vdCTOS_FormatHeader(szMaskAID, szTemp, szOutAID); // Format AID -- sidumili
    	}
		//version16
		
		vdDebug_LogPrintf("szOutAID=[%s]", szOutAID);
        sprintf(szTemp1, "AID: %s", szOutAID);
        
        //TC
        if ((srTransRec.byTransType != SALE_OFFLINE && srTransRec.byOrgTransType!= SALE_OFFLINE && srTransRec.byPackType != OFFLINE_VOID) ||
			memcmp(srTransRec.szAuthCode,"Y1",2) == 0)
        {
            wub_hex_2_str(srTransRec.stEMVinfo.T9F26, szTemp3, 8);
			//version16
			//if (inMasking == 0)
			//	sprintf(szStr, "TC: %-16.16s",szTemp3);
			//else
				sprintf(szStr, "AID: %-16.16s TC: %-16.16s", szOutAID, szTemp3);
        }
		else{
			//version16
			if (inMasking != 0)
				sprintf(szStr, "AID: %-16.16s", szOutAID);
		}
		
		memset (baTemp, 0x00, sizeof(baTemp));		
        //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
        //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		
    }		  

	if (strTCT.fSMReceipt == 0)//version 11 - do not put space for SM receipts
		vdCTOS_PrinterFline(1); // Change Request. Added new line before printing amount on BDO receipts.
	
    /* Amount */
    memset(szStr, ' ', d_LINE_SIZE);
    memset(szTemp, ' ', d_LINE_SIZE);
    memset(szTemp1, ' ', d_LINE_SIZE);
    memset(szTemp3, ' ', d_LINE_SIZE);

    wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
    wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
    wub_hex_2_str(srTransRec.szTipAmount, szTemp3, AMT_BCD_SIZE);
    
    vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
    
    //1025 - ADD OFFLINE SALE
    if(srTransRec.byTransType == VOID && atol(szTemp3) == 0L)/*void without tip*/
    {	
        vdDebug_LogPrintf("gtest 1");
		if (strTCT.fTipAllowFlag == CN_FALSE)
        {
	        memset(szStr, ' ', d_LINE_SIZE);
	        memset(szAmountBuff,0x00,20);
	        memset(szTemp4, 0x00, sizeof(szTemp4));
	        memset(szTemp6,0x00, sizeof(szTemp6));

	        strcpy(szTemp6,"TOTAL:");
	        
	        if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
	            vdDCCModifyAmount(szTemp1,szTemp4); //vdDCCModifyAmount(&szTemp4);
	        else	   
	            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
	        
	        sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
	        inPrintLeftRight(szTemp6,szAmountBuff,23);
		}
		else
		{
            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));
			
            strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change

			if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(szTemp1,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else	
	            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
            sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
            inPrintLeftRight(szTemp6,szAmountBuff,23);
            /*********************************************************/
            /*TIP*/
            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));

			//version16
			//do not print tip for loyalty
			vdDebug_LogPrintf("bdo loyalty test %d" ,srTransRec.HDTid);
			if (srTransRec.HDTid != BDO_LOYALTY_HDT_INDEX){
            	sprintf(szStr,"TIP:   %s", strCST.szCurSymbol);
            	memset (baTemp, 0x00, sizeof(baTemp));
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
				memset(szStr, 0x00, d_LINE_SIZE);
    			strcpy(szStr,"           ------------");
	        	memset (baTemp, 0x00, sizeof(baTemp));		
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
			}
           
            
            /*********************************************************/

            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));
            strcpy(szTemp6,"TOTAL:");
                        
            inPrintLeftRight(szTemp6,szAmountBuff,23);
        }
    }
    else if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == SALE_OFFLINE))
    {
        vdDebug_LogPrintf("gtest 2");

        //Base amount
        memset(szStr, ' ', d_LINE_SIZE);
        memset(szAmountBuff,0x00,20);
        memset(szTemp4, 0x00, sizeof(szTemp4));
        memset(szTemp6,0x00, sizeof(szTemp6));
        
        
        if (strTCT.fTipAllowFlag == CN_FALSE)
        {
            vdDebug_LogPrintf("gtest 3");

            strcpy(szTemp6,"TOTAL:");

			if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(szTemp1,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else	   
            	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
            	
            sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
            inPrintLeftRight(szTemp6,szAmountBuff,23);
        }
		else
		{
		    vdDebug_LogPrintf("gtest 4");

            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));

            strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change

			if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(szTemp1,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else	
	            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
            sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
            inPrintLeftRight(szTemp6,szAmountBuff,23);
            /*********************************************************/
            /*TIP*/

			if (srTransRec.HDTid != BDO_LOYALTY_HDT_INDEX){

            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));
            if (atol(szTemp3) == 0L)
            {
                
                //sprintf(szStr,"TIP:   %s  ___________", strCST.szCurSymbol);
                sprintf(szStr,"TIP:   %s", strCST.szCurSymbol);
                memset (baTemp, 0x00, sizeof(baTemp));		
                //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
                //CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);
				//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
				memset(szStr, 0x00, d_LINE_SIZE);
        		strcpy(szStr,"           ------------");
		        memset (baTemp, 0x00, sizeof(baTemp));		
				//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
				//vdCTOS_PrinterFline(1);
            }
            else
            {
                strcpy(szTemp6,"TIP:");
                if (atol(szTemp3)> 0)
                {
					if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
		   				vdDCCModifyAmount(szTemp3,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   				else
                    	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
                    sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
                }
                inPrintLeftRight(szTemp6,szAmountBuff,23); 
            }
			}
            /*********************************************************/

            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));
            strcpy(szTemp6,"TOTAL:");
            
            if (atol(szTemp3)> 0)
            {
				if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
			   		vdDCCModifyAmount(szTemp,szTemp4);//vdDCCModifyAmount(&szTemp4);
	   			else
                	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp4);// patrick add code 20141216	
                sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
            }

            inPrintLeftRight(szTemp6,szAmountBuff,23);
        }
    
    }
    else if ((srTransRec.byTransType == SALE_TIP) ||(srTransRec.byOrgTransType == SALE_TIP))
    {
        int inCurSymPos = 0, inTempCurSymLen = 0;
        char szTempCurSym[d_LINE_SIZE + 1];
        char szTempStr[d_LINE_SIZE + 1];
        //get the longest amount (total amount) to calculate currency position
        memset(szTemp4, 0x00, sizeof(szTemp4));

		if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
	   		vdDCCModifyAmount(szTemp,szTemp4);//vdDCCModifyAmount(&szTemp4);
   		else
	        vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp4);
		
        memset(szTempCurSym, 0x00, sizeof(szTempCurSym));
        if (srTransRec.byTransType == VOID)
        {
            if (strlen(szTemp4) >= 13 || (srTransRec.byOrgTransType == SALE_TIP) || srTransRec.fFleetCard == TRUE)
                sprintf(szTempCurSym, "-%s", strCST.szCurSymbol);
            else
                sprintf(szTempCurSym, "-%s", strCST.szCurSymbol);
        }
        else
            sprintf(szTempCurSym, "%s", strCST.szCurSymbol);
        inTempCurSymLen = strlen(szTempCurSym);
        inCurSymPos = 23-strlen(szTemp4)-inTempCurSymLen;
        
        //Base amount
        memset(szStr, 0x00, d_LINE_SIZE);
        memset(szAmountBuff,0x00,20);
        memset(szTemp4, 0x00, sizeof(szTemp4));
        memset(szTemp6,0x00, sizeof(szTemp6));
        strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change

		if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
	   		vdDCCModifyAmount(szTemp1,szTemp4); //vdDCCModifyAmount(&szTemp4);
   		else
	        vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
        
        memset(szTempStr, 0x00, sizeof(szTempStr));
        vdCTOS_Pad_String(szTemp6, inCurSymPos+inTempCurSymLen, ' ', POSITION_RIGHT);
        memcpy(&szTemp6[inCurSymPos], szTempCurSym, inTempCurSymLen);
        strcpy(szAmountBuff, szTemp4);
        inPrintLeftRight(szTemp6,szAmountBuff,23);
        /*********************************************************/
        /*TIP*/
		if (srTransRec.HDTid != BDO_LOYALTY_HDT_INDEX){

        memset(szStr, 0x00, d_LINE_SIZE);
        //memset(szAmountBuff,0x00,20); // haven't reset, needed for tip
        //memset(szTemp4, 0x00, sizeof(szTemp4));	// haven't reset, needed for tip
        memset(szTemp6,0x00, sizeof(szTemp6));
        if (atol(szTemp3) == 0L)
        {
            //sprintf(szStr,"TIP:   %s  ___________", strCST.szCurSymbol);
            sprintf(szStr,"TIP:   %s", strCST.szCurSymbol);
            memset (baTemp, 0x00, sizeof(baTemp));		
            //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
            //CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);
			//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
			
			memset(szStr, 0x00, d_LINE_SIZE);
    		strcpy(szStr,"           ------------");
	        memset (baTemp, 0x00, sizeof(baTemp));		
			//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
			//vdCTOS_PrinterFline(1);
        }
        else
        {
            strcpy(szTemp6,"TIP:");
            if (atol(szTemp3)> 0)
            {
				if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
		   			vdDCCModifyAmount(szTemp3,szTemp4);//vdDCCModifyAmount(&szTemp4);
		   		else
    	            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
    	            
                memset(szTempStr, 0x00, sizeof(szTempStr));
                vdCTOS_Pad_String(szTemp6, inCurSymPos+inTempCurSymLen, ' ', POSITION_RIGHT);
                memcpy(&szTemp6[inCurSymPos], szTempCurSym, inTempCurSymLen);
                strcpy(szAmountBuff, szTemp4);
            }
            inPrintLeftRight(szTemp6,szAmountBuff,23);
        }
		}
        /*********************************************************/
				
        memset(szStr, 0x00, d_LINE_SIZE);
        //strcpy(szStr,"           ____________");
        strcpy(szStr,"           ------------");
        memset (baTemp, 0x00, sizeof(baTemp));		
        //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 0, szStr, &stgFONT_ATTRIB);
        //CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);
		//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
        //vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 1, 0);
        //CTOS_PrinterBufferHLine(10, 1, 20, 1);//test
        //CTOS_PrinterBufferPixel(10, 1, 1);

		//vdCTOS_PrinterFline(1);
        memset(szStr, 0x00, d_LINE_SIZE);
        memset(szAmountBuff,0x00,20);
        memset(szTemp4, 0x00, sizeof(szTemp4));
        memset(szTemp6,0x00, sizeof(szTemp6));
        strcpy(szTemp6,"TOTAL:");
        
        if (atol(szTemp3)> 0)
        {
			if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(szTemp,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else
            	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp4);// patrick add code 20141216	
            	
            if (srTransRec.byTransType == VOID)
                sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
            else
                sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
        }
        inPrintLeftRight(szTemp6,szAmountBuff,23);
    }
    else
    {
        if ((strTCT.fTipAllowFlag == CN_TRUE) && (srTransRec.byTransType != PRE_AUTH) && (srTransRec.byTransType != CASH_ADVANCE))
        {

		    vdDebug_LogPrintf("gtest 6");

            //Base amount
            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));
			if (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX && srTransRec.byTransType == POINTS_INQUIRY)
				strcpy(szTemp6,"BALANCE:");
			else
            	strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change

			if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(szTemp1,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else
	            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
            
            if (srTransRec.byTransType == VOID)
            {
                if (strlen(szTemp4) >= 13 || srTransRec.fFleetCard == TRUE)
                    sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
                else
                    sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
            }
            else
                sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
            inPrintLeftRight(szTemp6,szAmountBuff,23);

            /*TIP*/
			if (srTransRec.HDTid != BDO_LOYALTY_HDT_INDEX){

            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));
            if (atol(szTemp3) == 0L)
            {
	            //sprintf(szStr,"TIP:   %s  ___________", strCST.szCurSymbol);
	            sprintf(szStr,"TIP:   %s", strCST.szCurSymbol);
	            memset (baTemp, 0x00, sizeof(baTemp));		
	            //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	            //CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);
				//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
				memset(szStr, 0x00, d_LINE_SIZE);
	    		strcpy(szStr,"           ------------");
		        memset (baTemp, 0x00, sizeof(baTemp));		
				//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
				//vdCTOS_PrinterFline(1);
            }
            else
            {
                strcpy(szTemp6,"TIP:");
                if (atol(szTemp3)> 0)
                {
					if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
				   		vdDCCModifyAmount(szTemp3,szTemp4);//vdDCCModifyAmount(&szTemp4);
			   		else
    	                vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);	
    	                
                    if (srTransRec.byTransType == VOID)
                    {
                        sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
                    }
                    else
                        sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
                }
                inPrintLeftRight(szTemp6,szAmountBuff,23);
            }
			}
        }
        
        memset(szStr, ' ', d_LINE_SIZE);
        memset(szAmountBuff,0x00,20);
        memset(szTemp4, 0x00, sizeof(szTemp4));
        memset(szTemp6,0x00, sizeof(szTemp6));
        strcpy(szTemp6,"TOTAL:");
        
        if ((atol(szTemp3)> 0) || (srTransRec.byTransType == PRE_AUTH) || (srTransRec.byTransType == CASH_ADVANCE))
        {
			if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(szTemp1,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else
            	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
            	
            if (srTransRec.byTransType == VOID)
            {
                if (strlen(szTemp4) >= 13 || srTransRec.fFleetCard == TRUE)
                    sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
                else
                    sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
            }
            else
                sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
        }
        //fix for void receipt - if TIP is off
        else if ((strTCT.fTipAllowFlag == CN_FALSE) &&	(srTransRec.byTransType != PRE_AUTH) && (srTransRec.byTransType != CASH_ADVANCE))
        {
			if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(szTemp1,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else
            	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
            	
            if (srTransRec.byTransType == VOID)
            {
                if (strlen(szTemp4) >= 13 || srTransRec.fFleetCard == TRUE)
                    sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
                else
                    sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
            }
            else
                sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
        }
        //fix for void receipt - if TIP is off
        if (srTransRec.byTransType != POINTS_INQUIRY)
        	inPrintLeftRight(szTemp6,szAmountBuff,23); 
    }
    
    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    
    /* BDO CLG: Fleet card support - start -- jzg */
    if((srTransRec.fFleetCard == TRUE) && 
    (strTCT.fFleetGetLiters == TRUE) &&
    (strTCT.fGetDescriptorCode == TRUE)) /* BDOCLG-00347: should be controlled also be parameterized -- jzg */
    {
        memset(szStr, ' ', d_LINE_SIZE);
        memset (baTemp, 0x00, sizeof(baTemp));
        memset(szStr, ' ', d_LINE_SIZE);
        sprintf(szStr, "NO. OF LITERS :   %d", srTransRec.inFleetNumofLiters);
        memset (baTemp, 0x00, sizeof(baTemp));		
        //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
        //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
		
        memset(szStr, ' ', d_LINE_SIZE);
        memset (baTemp, 0x00, sizeof(baTemp));
        memset(szStr, ' ', d_LINE_SIZE);
        sprintf(szStr, "%s", srTransRec.szFleetProductDesc);
        memset (baTemp, 0x00, sizeof(baTemp));		
        //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
       // CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
    }

	if (strTCT.fSMReceipt == 0)//version 11 - do not put space for SM receipts
		inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);//Added blank line between "TOTAL:" and CVM (NO SIGNATURE REQUIRED, PIN VERIFICATION SUCCESSFUL and etc.)
	
	return d_OK;		
}

USHORT ushCTOS_PrintAgreement()
{
	if (srTransRec.HDTid == SMAC_HDT_INDEX)
	{
		vdPrintCenter("I AGREE THAT THE AMOUNT ABOVE SHALL BE ");
		vdPrintCenter("DEBITED FROM MY LOYALTY ACCOUNT ");
	}
	else
	{
		if(srTransRec.HDTid == SMSHOPCARD_HDT_INDEX)
		{
			vdPrintCenter("I AGREE THAT THE AMOUNT ABOVE SHALL BE");
			vdPrintCenter("DEBITED FROM MY SM SHOPPING CARD");
		}
		else if (inCheckIfSMCardTransRec() == TRUE)			
		{
			vdPrintCenter("I PROMISE TO PAY THE TOTAL AMOUNT ABOVE ");
			vdPrintCenter("AND OTHER CHARGES PURSUANT TO THE AGREE-");
			vdPrintCenter("MENT/S GOVERNING USE OF THIS CARD, AND ");
			vdPrintCenter("AUTHORIZE THE ISSUER OF THIS CARD TO PAY ");
			vdPrintCenter("THE TOTAL AMOUNT ABOVE UPON PRESENTATION.");
		}
		else
		{
			//vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, NORMAL_SIZE, 0, 0);

			vdPrintCenter("I AGREE TO PAY THE ABOVE TOTAL AMOUNT");
			vdPrintCenter("ACCORDING TO THE CARD ISSUER AGREEMENT");
			
			//vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		}
	}
}

USHORT ushCTOS_PrintFooter(int page)
{		
	BYTE EMVtagVal[64] = {0};
	USHORT EMVtagLen = 0; 
    BYTE baTemp[PAPER_X_SIZE * 64];
    char szStr[d_LINE_SIZE + 3];
	int fNSRflag = 0;

	//04192023 - Signature line is printed for BDO Loyalty txn
	//int fPage;



    vdDebug_LogPrintf("ushCTOS_PrintFooter");

	//if(srTransRec.fDCC && (srTransRec.byTransType == SALE||srTransRec.byTransType == SALE_OFFLINE||srTransRec.byTransType == SALE_ADJUST||
		//(srTransRec.byTransType == VOID && srTransRec.byOrgTransType == SALE)))
    if(srTransRec.fDCC)		
        vdPrintDCCFooter();

	//version16
	if (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX && srTransRec.byTransType == POINTS_INQUIRY){

		
		vdDebug_LogPrintf("ushCTOS_PrintFooter2");

		if(page == BANK_COPY_RECEIPT)
        	vdPrintCenter("--- BANK COPY ---");
    	else if(page == CUSTOMER_COPY_RECEIPT)
        	vdPrintCenter("--- CUSTOMER COPY ---");
    	else if(page = MERCHANT_COPY_RECEIPT)
        	vdPrintCenter("--- MERCHANT COPY ---");
 
		    //sidumili: Issue#000135 [Print Footer Logo]
    	if (srTransRec.fFooterLogo)
    	{
         	vdCTOSS_PrinterBMPPic(0, 0, "/home/ap/pub/footer.bmp");
    	}

		vdLineFeed(srTransRec.fFooterLogo);

		return d_OK;
	}


	fNSRflag = inNSRFlag();

	vdDebug_LogPrintf("fNSRflag = %d", fNSRflag);

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
	EMVtagLen = 0;
	
    DebugAddINT("ushCTOS_PrintFooter,mode",srTransRec.byEntryMode);  
    
    vdDebug_LogPrintf("CVM [%02X %02X %02X]",
    srTransRec.stEMVinfo.T9F34[0], srTransRec.stEMVinfo.T9F34[1], srTransRec.stEMVinfo.T9F34[2]);
    vdDebug_LogPrintf("srTransRec.byEntryMode = [%d], strTCT.inCustomerCopy[%d], srTransRec.HDTid[%d], page[%d]", 
		srTransRec.byEntryMode, strTCT.inCustomerCopy, srTransRec.HDTid, page);

//04192023 - Signature line is printed for BDO Loyalty txn
#if 0
	fPage = page;
	vdDebug_LogPrintf("ushCTOS_PrintFooter fPage [%d]", fPage);

	if(srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX)
		page = CUSTOMER_COPY_RECEIPT;
#endif

    if((page != CUSTOMER_COPY_RECEIPT) && (srTransRec.byTransType != VOID))
    {
        //version 11 - should still check 9f34 even if NSR flag is OFF
		//if(strIIT.fNSR == 1 && srTransRec.fDCC != TRUE)
		if(srTransRec.fDCC != TRUE)
        {
            EMVtagLen = 3;
            memcpy(EMVtagVal, srTransRec.stEMVinfo.T9F34, EMVtagLen);

			if(srTransRec.byEntryMode == CARD_ENTRY_ICC && (((EMVtagVal[0] != 0x03) && (EMVtagVal[0] != 0x05) &&
			(EMVtagVal[0] != 0x1E) && (EMVtagVal[0] != 0x5E)) || (EMVtagVal[0] == 0x3F)))
			{
				//vdCTOS_PrinterFline(1);
				if(EMVtagVal[0] & 0x01 || EMVtagVal[0] & 0x02 || EMVtagVal[0] & 0x04) /*offline plain text, online encrypted and offline encrypted pin respectively*/
					vdPrintCenter("PIN VERIFICATION SUCCESSFUL");
				else
				{
				    vdDebug_LogPrintf("no signature 1");
				    
					if (strTCT.fSMReceipt)
						vdPrintCenter("*****NO SIGNATURE REQUIRED*****");	
					else{
						vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
						vdPrintCenter("NO SIGNATURE REQUIRED");		
						vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
					}
				}
			}
			else if (srTransRec.byEntryMode == CARD_ENTRY_WAVE)
            {
            	if(srTransRec.byTransType == SALE_TIP)
            	{
			        if(ushCTOS_ePadPrintSignature() != d_OK && inPrintPNG() != d_OK)
                    vdCTOS_PrinterFline(2);	
					vdDebug_LogPrintf("sign 1");
                    memset(szStr, 0x00, sizeof(szStr));
                    strcpy(szStr, "SIGN:_____________________________________");
                    memset (baTemp, 0x00, sizeof(baTemp));
                    //inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
                    //inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
					inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
					inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);
                    
				}
				else
				{
				
	                if(srTransRec.bWaveSCVMAnalysis != d_CVM_REQUIRED_SIGNATURE)
	                {
	                    if (srTransRec.bWaveSID == d_VW_SID_AE_EMV && srTransRec.bWaveSCVMAnalysis == d_CVM_REQUIRED_NONE)
	                    {
	                        if((page == BANK_COPY_RECEIPT) || (page == MERCHANT_COPY_RECEIPT))
	                        {
	                             if(ushCTOS_ePadPrintSignature() != d_OK && inPrintPNG() != d_OK)
	                                vdCTOS_PrinterFline(2);	
								 	vdDebug_LogPrintf("sign 2");
	                                memset(szStr, 0x00, sizeof(szStr));
	                                strcpy(szStr, "SIGN:_____________________________________");
	                                memset (baTemp, 0x00, sizeof(baTemp));
	                                //inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	                                //inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
									inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
									inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);
	                        }
	                        else
	                            vdCTOS_PrinterFline(1);    
	                    }
	                    else
	                    {
	                        //vdCTOS_PrinterFline(1);
	                        vdDebug_LogPrintf("no signature 2");
							if (strTCT.fSMReceipt)
								vdPrintCenter("*****NO SIGNATURE REQUIRED*****");	
							else{
	                        	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	                        	vdPrintCenter("NO SIGNATURE REQUIRED");
								vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
							}
	                    }
	                }
                	else
	                {
	                    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 8 of 21
	                    if((page == BANK_COPY_RECEIPT) || (page == MERCHANT_COPY_RECEIPT))
	                    {
							   if(fNSRflag == 1)
							   {
							      vdDebug_LogPrintf("no signature 3");
	                              vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		                          vdPrintCenter("NO SIGNATURE REQUIRED");
								  vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
							   }
							   else
							   {
		                           if(ushCTOS_ePadPrintSignature() != d_OK)
		                              vdCTOS_PrinterFline(2);	

								   vdDebug_LogPrintf("sign 3");
		                           memset(szStr, 0x00, sizeof(szStr));
		                           strcpy(szStr, "SIGN:_____________________________________");
		                           memset (baTemp, 0x00, sizeof(baTemp));
		                           //inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		                           //inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1); 
								   inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
								   inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);
							   }
	                    }
	                    else
	                        //CTOS_PrinterFline(d_LINE_DOT);
						              vdCTOS_PrinterFline(1);
	                    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 8 of 21
	                }
				}
            }
            else
            {
                if(fNSRflag == 1)
                {	
                    vdDebug_LogPrintf("no signature 4");
                    //vdCTOS_PrinterFline(1);
					if (strTCT.fSMReceipt)
						vdPrintCenter("*****NO SIGNATURE REQUIRED*****");	
					else{
                    	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
                    	vdPrintCenter("NO SIGNATURE REQUIRED");
						vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
					}
                }
                else
                {
                       if(ushCTOS_ePadPrintSignature() != d_OK && inPrintPNG() != d_OK)
                           vdCTOS_PrinterFline(2);		

						vdDebug_LogPrintf("sign 4");
						memset(szStr, 0x00, sizeof(szStr));
                        strcpy(szStr, "SIGN:_____________________________________");
                        memset (baTemp, 0x00, sizeof(baTemp));
                        //inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
                        //inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
                        
						inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
						inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);
                }
            }
        }
		else
		{
            if(srTransRec.byEntryMode == CARD_ENTRY_ICC)
            {
                EMVtagLen = 3;
                memcpy(EMVtagVal, srTransRec.stEMVinfo.T9F34, EMVtagLen);
                
                //EMV: Fix for noCVM during above floor limit scenario - start -- jzg
                vdDebug_LogPrintf("EMVtagVal [%02X %02X %02X]", EMVtagVal[0], EMVtagVal[1], EMVtagVal[2]);
                // patrick add code 20141208
                if (((EMVtagVal[0] != 0x03) && (EMVtagVal[0] != 0x05) &&
                (EMVtagVal[0] != 0x1E) &&
                (EMVtagVal[0] != 0x5E)) || (EMVtagVal[0] == 0x3F))
                //EMV: Fix for noCVM during above floor limit scenario - end -- jzg
                {
                    //vdCTOS_PrinterFline(1);
                    if(EMVtagVal[0] & 0x01 || EMVtagVal[0] & 0x02 || EMVtagVal[0] & 0x04) /*plain text or encrypted pin*/
                        vdPrintCenter("PIN VERIFICATION SUCCESSFUL");
					else
					{
					    vdDebug_LogPrintf("no signature 5");
						if (strTCT.fSMReceipt)
							vdPrintCenter("*****NO SIGNATURE REQUIRED*****");	
						else{
							vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
                        	vdPrintCenter("NO SIGNATURE REQUIRED");     
							vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
						}
					}
                }
                else
                {
                    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 7 of 21
                    if((page == BANK_COPY_RECEIPT) || (page == MERCHANT_COPY_RECEIPT)) 
                    {
						//version16
					    //if(fNSRflag == 1)
					    if (inCTOSS_CheckCVMAmount() == d_NO)
						{
							vdDebug_LogPrintf("no signature 3");
	                        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		                    vdPrintCenter("NO SIGNATURE REQUIRED");
							vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
						}else{ 
                       		if(ushCTOS_ePadPrintSignature() != d_OK && inPrintPNG() != d_OK)
                           		vdCTOS_PrinterFline(2);	

						   	vdDebug_LogPrintf("sign 5");
                           	memset(szStr, 0x00, sizeof(szStr));
                           	strcpy(szStr, "SIGN:_____________________________________");
                           	memset (baTemp, 0x00, sizeof(baTemp));
                           	//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
                           	//inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
                           	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
                           	inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);
						}
                    }
                    else
                        //CTOS_PrinterFline(d_LINE_DOT);
					              vdCTOS_PrinterFline(1);   
                    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 7 of 21
                }
            }
            else if (srTransRec.byEntryMode == CARD_ENTRY_WAVE)
            {
                if(srTransRec.bWaveSCVMAnalysis != d_CVM_REQUIRED_SIGNATURE)
                {
                    if (srTransRec.bWaveSID == d_VW_SID_AE_EMV && srTransRec.bWaveSCVMAnalysis == d_CVM_REQUIRED_NONE)
                    {
                        if((page == BANK_COPY_RECEIPT) || (page == MERCHANT_COPY_RECEIPT))
                        {
                             if(ushCTOS_ePadPrintSignature() != d_OK && inPrintPNG() != d_OK)
                                vdCTOS_PrinterFline(2);	
							    vdDebug_LogPrintf("sign 6");
                                memset(szStr, 0x00, sizeof(szStr));
                                strcpy(szStr, "SIGN:_____________________________________");
                                memset (baTemp, 0x00, sizeof(baTemp));
                                //inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
                                //inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
								inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
								inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);
                        }
                        else
                            vdCTOS_PrinterFline(1);    
                    }
                    else
                    {
                        //vdCTOS_PrinterFline(1);
                        vdDebug_LogPrintf("no signature 6");
						if (strTCT.fSMReceipt)
							vdPrintCenter("*****NO SIGNATURE REQUIRED*****");	
						else{
                        	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
                        	vdPrintCenter("NO SIGNATURE REQUIRED");
							vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
						}
                    }
                }
                else
                {
                    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 8 of 21
                    if((page == BANK_COPY_RECEIPT) || (page == MERCHANT_COPY_RECEIPT))
                    {
                           if(ushCTOS_ePadPrintSignature() != d_OK && inPrintPNG() != d_OK)
                              vdCTOS_PrinterFline(2);	

						   vdDebug_LogPrintf("sign 7");
                           memset(szStr, 0x00, sizeof(szStr));
                           strcpy(szStr, "SIGN:_____________________________________");
                           memset (baTemp, 0x00, sizeof(baTemp));
                           //inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
                           //inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1); 
						   inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
						   inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);
                    }
                    else
                        //CTOS_PrinterFline(d_LINE_DOT);
					              vdCTOS_PrinterFline(1);
                    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 8 of 21
                }
            }		
        	//CTLS: Revised signature line printing - end -- jzg
        	else
        	{
                //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 9 of 21
                if(((page == BANK_COPY_RECEIPT) || (page == MERCHANT_COPY_RECEIPT)) && (srTransRec.byTransType != VOID))
                {
                       if(ushCTOS_ePadPrintSignature() != d_OK && inPrintPNG() != d_OK)
                           vdCTOS_PrinterFline(2);    

						vdDebug_LogPrintf("sign 8");
                       memset(szStr, 0x00, sizeof(szStr));
                       strcpy(szStr, "SIGN:_____________________________________");
                       memset (baTemp, 0x00, sizeof(baTemp));
                       //inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
                       //inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
                       
					   inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
					   inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);
                }
                else 
									  vdCTOS_PrinterFline(1);
								    //CTOS_PrinterFline(d_LINE_DOT);
                //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 9 of 21
        	}
		}
    }
	
    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    
    //if (page != CUSTOMER_COPY_RECEIPT && (!(srTransRec.byTransType == VOID && srTransRec.byOrgTransType == SALE_TIP)) &&
    //(!(srTransRec.byTransType == VOID && srTransRec.fFleetCard == TRUE)))
    //{
		//if(srTransRec.fDCC != TRUE)
            //ushCTOS_PrintAgreement();
    //}

    if(page != CUSTOMER_COPY_RECEIPT)
    {
        if(srTransRec.byTransType != VOID && /*srTransRec.byTransType != SALE_TIP &&*/ srTransRec.fDCC != TRUE && srTransRec.fFleetCard != TRUE)//SM GIFTCARD should not print Agreement Statement
        {

			vdDebug_LogPrintf("ushCTOS_PrintFooter (page != CUSTOMER_COPY_RECEIPT)");
		
            ushCTOS_PrintAgreement();
        }
    }

    vdPrintFooterText();

//original code 04192023
#if 1
	if(page == CUSTOMER_COPY_RECEIPT)
	{
		if(srTransRec.fDCC)
			vdCTOS_PrinterFline(1);
	}
	
    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 8 of 13
    if(page == BANK_COPY_RECEIPT)
        vdPrintCenter("--- BANK COPY ---");
    else if(page == CUSTOMER_COPY_RECEIPT)
        vdPrintCenter("--- CUSTOMER COPY ---");
    else if(page = MERCHANT_COPY_RECEIPT)
        vdPrintCenter("--- MERCHANT COPY ---");
    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 8 of 13
    /***************************************************/
#else
	//04192023 - Signature line is printed for BDO Loyalty txn

	if(srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX)
	{
		if(fPage == CUSTOMER_COPY_RECEIPT){
			if(srTransRec.fDCC)
			vdCTOS_PrinterFline(1);
		}
		
	    if(fPage == BANK_COPY_RECEIPT)
	        vdPrintCenter("--- BANK COPY ---");
	    else if(fPage == CUSTOMER_COPY_RECEIPT)
	        vdPrintCenter("--- CUSTOMER COPY ---");
	    else if(fPage = MERCHANT_COPY_RECEIPT)
	        vdPrintCenter("--- MERCHANT COPY ---");			
	}
	else
	{
		if(page == CUSTOMER_COPY_RECEIPT)
		{
			if(srTransRec.fDCC)
				vdCTOS_PrinterFline(1);
		}
		
	    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 8 of 13
	    if(page == BANK_COPY_RECEIPT)
	        vdPrintCenter("--- BANK COPY ---");
	    else if(page == CUSTOMER_COPY_RECEIPT)
	        vdPrintCenter("--- CUSTOMER COPY ---");
	    else if(page = MERCHANT_COPY_RECEIPT)
	        vdPrintCenter("--- MERCHANT COPY ---");	
	}

#endif



    //sidumili: Issue#000135 [Print Footer Logo]
    if (srTransRec.fFooterLogo)
    {
        //CTOS_PrinterFline(d_LINE_DOT * 2); 
        //vdCTOSS_PrintFooterLogoBMPPic(0, 0, "footer.bmp");
        //vdCTOSS_PrinterBMPPicEx(0,0,"/home/ap/pub/footer.bmp");  
        vdCTOSS_PrinterBMPPic(0, 0, "/home/ap/pub/footer.bmp");
    }
    /***************************************************/

	vdLineFeed(srTransRec.fFooterLogo);
	
    return d_OK;	
}

USHORT ushCTOS_printAll(int page)
{	
	int inResult;

		//for MP200 no need print
		if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
			return (d_OK);

        if(strTCT.byERMMode)
           fERMTransaction=TRUE;
		else
		   fERMTransaction=FALSE;
		//sidumili: check printer status
		if( printCheckPaper()==-1)
    	return -1;
		
    //vdSetPrintThreadStatus(1);
    
    if(strTCT.fDisplayAPPROVED == FALSE)//Sound BEEP before printing if APPROVED message is not displayed
		CTOS_Beep();
	
	vdPrintReportDisplayBMP();

    if(VS_FALSE == fRePrintFlag)
    {
#if 0
		if(srTransRec.byTransType == SMAC_BALANCE && strTCT.byLastTransType != SMAC_BALANCE)//Only save 2ndLastInvoiceNo for non SMAC_BALANCE transactions.
			memcpy(strTCT.sz2ndLastInvoiceNo,strTCT.szLastInvoiceNo,INVOICE_BCD_SIZE);      //Save 2nd last for retreival after reprint last of SMAC Balance since it will be deleted from batch after reprint.
#endif
		
//	    memcpy(strTCT.szLastInvoiceNo,srTransRec.szInvoiceNo,INVOICE_BCD_SIZE);
//		strTCT.byLastTransType = srTransRec.byTransType;
    }
	
//	if((inResult = inTCTSave(1)) != ST_SUCCESS)
//  {
//		vdDisplayErrorMsg(1, 8, "Update TCT fail");
//  }



	
    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	vdCTOSS_PrinterStart(100);
    CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel); 

	//gcitra
	if (srTransRec.byTransType == CASH_LOYALTY)
  		ushCTOS_PrintCashLoyaltyBody();	
	else{
	//gcitra
	//smac

		if (srTransRec.HDTid == SMAC_HDT_INDEX){
			vdDebug_LogPrintf("testlang 1 barcode %s", srTransRec.szBarcodeText);
			vdDebug_LogPrintf("print smac");
			vdDebug_LogPrintf("ushCTOS_printAll KIKO1 srTransPara->szPAN:%s", srTransRec.szPAN);

			ushCTOS_PrintHeader(page);
			ushCTOS_PrintSMACBody(page);
			ushCTOS_PrintSMFooter(page);
		}
		/*BDO: For SMGuarantor -- sidumili*/
		else if (srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMPARTNER_HDT_INDEX || srTransRec.HDTid == SMSHOPCARD_HDT_INDEX 
			|| srTransRec.HDTid == SMGIFTCARD_HDT_INDEX || srTransRec.HDTid == SMECARD_HDT_INDEX || srTransRec.HDTid == SM_CREDIT_CARD || srTransRec.HDTid == SMSHOPCRD)
		{
			vdDebug_LogPrintf("print sm");
			ushCTOS_PrintHeader(page);
			ushCTOS_PrintSMGuarantorBody(page);
			ushCTOS_PrintSMFooter(page);
		}	
		/*BDO: For SMGuarantor -- sidumili*/
	//smac

#if 0 //removed for version 11
		else if (strTCT.fSMReceipt)	// SMAC application
		{
			ushCTOS_PrintSMHeader(page);
			ushCTOS_PrintSMBody(page);
			ushCTOS_PrintSMFooter(page);
		}
#endif
		else{
			vdDebug_LogPrintf("print none sm");
			ushCTOS_PrintHeader(page);
  			ushCTOS_PrintBody(page);	
			ushCTOS_PrintFooter(page);
		}
	}
    vdSetPrintThreadStatus(0);
	vdCTOSS_PrinterEnd();

	CTOS_LCDTClearDisplay();
	
    return d_OK;
 
}

int inCTOS_rePrintReceipt(void)
{
	int   inResult;
	BYTE  szInvNoAsc[6+1];
	BYTE  szInvNoBcd[3];	
	BOOL  needSecond = TRUE;	
	//1027
	BOOL  needThird = TRUE;	
	BYTE  key;

	/*BDO: Parameterized receipt printing - start*/
	BOOL BankCopy, CustCopy, MercCopy;
	BOOL fFirstReceiptPrinted = VS_FALSE;
    /*BDO: Parameterized receipt printing - end*/

    BOOL fFirstReceipt=TRUE; 
    int inReceiptCtr=0;
    BYTE szPrintOption[3+1];
    BYTE chPrintOption=0x00;

   vduiClearBelow(2);  

	//for MP200 no need print
	if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
    	return (d_OK);

	//vdCTOSS_PrinterStart(100);
	//CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
	if(printCheckPaper()==-1)
		return d_NO;

  inResult = inCTOS_GetTxnPassword();
    if(d_OK != inResult)
        return inResult;

	inResult = inCTOS_GeneralGetInvoice();
	if(d_OK != inResult)
	{
		return inResult;
	}

	if (inMultiAP_CheckMainAPStatus() == d_OK)
	{
		inResult = inCTOS_MultiAPBatchSearch(d_IPC_CMD_REPRINT_ANY);
		if(d_OK != inResult)
			return inResult;
	}
	else
	{
		if (inMultiAP_CheckSubAPStatus() == d_OK)
		{
			inResult = inCTOS_MultiAPGetVoid();
			if(d_OK != inResult)
				return inResult;
		}		
		inResult = inCTOS_BatchSearch();
		if(d_OK != inResult)
			return inResult;
	}

	if(srTransRec.byTransType == SMAC_BALANCE || srTransRec.byTransType == BALANCE_INQUIRY)
	{
		//vdDisplayErrorMsg(1, 8, "NO RECORD FOUND");
		vdDisplayErrorMsgResp2("","TRANSACTION","NOT FOUND");
		return d_NOT_RECORD;
	}

	//1026
	//inCSTRead(srTransRec.HDTid); // sidumili: commented
	//1026

	/*BDO: Parameterized receipt printing - start*/
	inHDTRead(srTransRec.HDTid);

	if (srTransRec.byTransType == VOID){
		BankCopy = strHDT.fPrintVoidBankReceipt;
		CustCopy = strHDT.fPrintVoidCustReceipt;
		MercCopy = strHDT.fPrintVoidMercReceipt;
	}else{
		BankCopy = strHDT.fPrintBankReceipt;
		CustCopy = strHDT.fPrintCustReceipt;
		MercCopy = strHDT.fPrintMercReceipt;
	}
	/*BDO: Parameterized receipt printing - end*/


	/*Issue# 000299 -- sidumili*/
	inCSTRead(srTransRec.inSavedCurrencyIdx);
	/*Issue# 000299 -- sidumili*/

	//BDO: Reload IIT to properly load PAN masking during reprint - start -- jzg
	vdDebug_LogPrintf("JEFF::IITid [%d]", srTransRec.IITid);
	inIITRead(srTransRec.IITid);
	//BDO: Reload IIT to properly load PAN masking during reprint - end -- jzg

	//save TID and MID retrived from batch
	memcpy(TempszTID, srTransRec.szTID, strlen( srTransRec.szTID));
	memcpy(TempszMID, srTransRec.szMID, strlen( srTransRec.szMID));

    vdCTOS_PrintReceiptCopies(BankCopy, CustCopy, MercCopy, FALSE);

	fECRBuildSendOK = TRUE;	
	if (fECRBuildSendOK){
		strcpy(srTransRec.szRespCode,"00");
	    inResult = inMultiAP_ECRSendSuccessResponse();		
	}
	
	//vdCTOSS_PrinterEnd();
	return d_OK;
}

void vdCTOS_PrintSummaryReport()
{
	ACCUM_REC srAccumRec;
	unsigned char chkey;
	short shHostIndex;
	int inResult,inRet;
	int inTranCardType;
	int inReportType;
	int inIITNum , i;
	char szStr[d_LINE_SIZE + 1];
    BYTE baTemp[PAPER_X_SIZE * 64];

	
	int inPADSize,x;
	char szSPACE[40];
	char szBuff[46];
	char szBuff2[46];


	vdDebug_LogPrintf("vdCTOS_PrintSummaryReport byTerminalType[%d]", strTCT.byTerminalType);

	//for MP200 no need print
	if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
    	return (d_OK);

	vdDebug_LogPrintf("vdCTOS_PrintSummaryReport");
	
	if( printCheckPaper()==-1)
		return;

	vdDebug_LogPrintf("vdCTOS_PrintSummaryReport1");

	inResult = inCTOS_TEMPCheckAndSelectMutipleMID();

	vdDebug_LogPrintf("vdCTOS_PrintSummaryReport1 inResult [%d]", inResult);
	
	DebugAddINT("summary MITid",srTransRec.MITid);
	if(d_OK != inResult)
		return;

		
	//by host and merchant
	//shHostIndex = inCTOS_SelectHostSetting();	
	shHostIndex = inCTOS_SelectHostSettingWithIndicator(1);
	vdDebug_LogPrintf("vdCTOS_PrintSummaryReport1 shHostIndex [%d]", shHostIndex);
	
	if (shHostIndex == -1)
		return;
	strHDT.inHostIndex = shHostIndex;

	vdDebug_LogPrintf("vdCTOS_PrintSummaryReport1 strHDT.inHostIndex [%d]", strHDT.inHostIndex);
	
	DebugAddINT("summary host Index",shHostIndex);
	inCSTRead(strHDT.inCurrencyIdx);

	if (inMultiAP_CheckMainAPStatus() == d_OK)
	{
		inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_SUMMARY_REPORT);
		if(d_OK != inRet)
			return ;
	}
	else
	{
		if (inMultiAP_CheckSubAPStatus() == d_OK)
		{
			inRet = inCTOS_MultiAPGetData();
			if(d_OK != inRet)
				return ;

			inRet = inCTOS_MultiAPReloadHost();
			if(d_OK != inRet)
				return ;
		}
	}

	vdDebug_LogPrintf("vdCTOS_PrintSummaryReport1 AAA");

	//inResult = inCTOS_CheckAndSelectMutipleMID();
	//DebugAddINT("summary MITid",srTransRec.MITid);
	//if(d_OK != inResult)
	//	return;
	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

	inResult = inCTOS_ChkBatchEmpty();
	if(d_OK != inResult)
	{
		return;
	}
	vdDebug_LogPrintf("vdCTOS_PrintSummaryReport1 BBB");


#if 1
    vdCTOS_PrintMerchantSummaryReport(); /*albert - to have a common receipt on Summary Report*/
#else
	inResult = inCTOS_ChkBatchEmpty();
	if(d_OK != inResult)
	{
		return;
	}

    memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
    {
        vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
        return;    
    }

	vdSetPrintThreadStatus(1); /*BDO:Display printing image during report -- sidumili*/
	
//1105
    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
    //vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);   
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
//1105
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
    
	ushCTOS_PrintHeader(0);	

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

    //vdPrintTitleCenter("SUMMARY REPORT");
	CTOS_PrinterFline(d_LINE_DOT * 1);

    //printHostLabel();
    
	printTIDMID();
    
	printDateTime();
    
	printBatchNO();

    CTOS_PrinterFline(d_LINE_DOT * 1);
	vdPrintCenter("*** TRANSACTION TOTALS BY ISSUER ***");
	CTOS_PrinterFline(d_LINE_DOT * 1);
	
	for(inTranCardType = 0; inTranCardType < 1 ;inTranCardType ++)
	{
		inReportType = PRINT_CARD_TOTAL;
		
		if(inReportType == PRINT_CARD_TOTAL)
		{
			//for(i= 0; i < 20; i ++ )
			for(i= 0; i < 26; i ++ )//smac
			{
				
				if((srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount == 0)
//issue:00269 - Print Issue totals even if Cash advance is the only transaction	
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount == 0))
					continue;
				
				vdDebug_LogPrintf("Count[%d]", i); 
				inIITRead(i);
				memset(szStr, ' ', d_LINE_SIZE);
				memset (baTemp, 0x00, sizeof(baTemp));
				//strcpy(szStr,strIIT.szIssuerLabel);

		        //sprintf(szBuff,"HOST%s%s",szSPACE,srTransRec.szHostLabel);
				sprintf(szStr,"ISSUER: %s",strIIT.szIssuerLabel);

                sprintf(szBuff,"HOST       %s",srTransRec.szHostLabel); /* BDO: Adjusted spacing for receipt -- jzg */
				
				inPrintLeftRight2(szStr,szBuff,42);
				
				vdCTOS_PrintAccumeByHostAndCard (inReportType, 
					/* BDO-00043: Add void count to sale and sale grand total - start -- end */					
					(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount) +
						srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount, 	
					/* BDO-00043: Add void count to sale and sale grand total - end -- end */					

					(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
					
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 
//issue-00296-add void cash advance					
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
					(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 
					
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),
					
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount)

												);	
			}
			//SMAC
			
			if (srTransRec.HDTid == 26)
				continue;

			//SMAC
			//after print issuer total, then print host toal
			{
				CTOS_PrinterFline(d_LINE_DOT * 1);
				memset(szStr, ' ', d_LINE_SIZE);
				memset (baTemp, 0x00, sizeof(baTemp));
				strcpy(szStr,"GRAND TOTALS");
				CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
				CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
				vdCTOS_PrintAccumeByHostAndCard (inReportType, 
					/* BDO-00043: Add void count to sale and sale grand total - start -- end */					
					(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount) +
						srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, 	
					/* BDO-00043: Add void count to sale and sale grand total - end -- end */					

					(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
					
					srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
//issue-00296-add void cash advance 									
					srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
					(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
					
					srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
					
					srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
					
					srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount)

													);		
			}
		}
		else
		{
		
			memset(szStr, ' ', d_LINE_SIZE);
			memset (baTemp, 0x00, sizeof(baTemp));
			strcpy(szStr,srTransRec.szHostLabel);
			CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			vdCTOS_PrintAccumeByHostAndCard (inReportType, 
				/* BDO-00043: Add void count to sale and sale grand total - start -- end */ 				
				(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount) +
					srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, 	
				/* BDO-00043: Add void count to sale and sale grand total - end -- end */ 				

				(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 

			    //issue-00296-add void cash advance 									
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
				(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
								
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount)

												);		
		}
	}
    
	//print space one line
	CTOS_PrinterFline(d_LINE_DOT * 2);		
	CTOS_PrinterFline(d_LINE_DOT * 2);
	CTOS_PrinterFline(d_LINE_DOT * 2);

	vdSetPrintThreadStatus(0); /*BDO:Display printing image during report -- sidumili*/
#endif	
	return;	
}

void vdCTOS_PrintDetailReport(BOOL fAddtoSettleReport, BOOL fLastSettleReport)
{
	unsigned char chkey;
	short shHostIndex;
	int inResult,i,inCount,inRet;
	int inTranCardType;
	int inReportType;
	int inBatchNumOfRecord;
	int *pinTransDataid;

//0720
	ACCUM_REC srAccumRec;
	BYTE baTemp[PAPER_X_SIZE * 64];
	char szStr[d_LINE_SIZE + 1];
//0720

	//for MP200 no need print
	if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
    	return (d_OK);
	
	if( printCheckPaper()==-1)
		return;

	//start-do not select Merchant if Detail report is during settlement
		if(fAddtoSettleReport != TRUE){
			inResult = inCTOS_TEMPCheckAndSelectMutipleMID();
			DebugAddINT("summary MITid",srTransRec.MITid);
			if(d_OK != inResult)
				return;
		}
	//end


	/* BDO: Include detailed report to settlement receipt - start -- jzg */
	if(fAddtoSettleReport != TRUE)
	{
		//shHostIndex = inCTOS_SelectHostSetting();
		shHostIndex = inCTOS_SelectHostSettingWithIndicator(1);
		if (shHostIndex == -1)
			return;
		
		strHDT.inHostIndex = shHostIndex;
	}
	/* BDO: Include detailed report to settlement receipt - end -- jzg */
	
	DebugAddINT("summary host Index",shHostIndex);

	if (inMultiAP_CheckMainAPStatus() == d_OK)
	{
	inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_DETAIL_REPORT);
		if(d_OK != inRet)
			return ;
	}
	else
	{
		if (inMultiAP_CheckSubAPStatus() == d_OK)
		{
			inRet = inCTOS_MultiAPGetData();
			if(d_OK != inRet)
				return ;

			inRet = inCTOS_MultiAPReloadHost();
			if(d_OK != inRet)
				return ;
		}
	}

//start-do not select Merchant if Detail report is during settlement
	//if(fAddtoSettleReport != TRUE){
	//	inResult = inCTOS_CheckAndSelectMutipleMID();
	//	DebugAddINT("summary MITid",srTransRec.MITid);
	//	if(d_OK != inResult)
	//		return;
	//}

//end

//issue-00307
    //if (srTransRec.byTransType == MANUAL_SETTLE)
		//vdDispTitleString("CLEAR BATCH");
		

	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

	vdDebug_LogPrintf("TEST DETAIL %d %d", srTransRec.HDTid,srTransRec.MITid);

#if 1
    vdDebug_LogPrintf("vdCTOS_PrintDetailReport: %d", fLastSettleReport);
    /*albert - start - 20161202 - Reprint of Detail Report for Last Settlement Report*/
    if(fLastSettleReport == TRUE) 
        vdCTOS_PrintSettleMerchantDetailReport(); /*albert - to have a common receipt on Detail Report*/
	else
	{
		inResult = inCTOS_ChkBatchEmpty();
		if(d_OK != inResult)
			return;
		vdCTOS_PrintMerchantDetailReport(); /*albert - to have a common receipt on Detail Report*/
	}
	/*albert - end - 20161202 - Reprint of Detail Report for Last Settlement Report*/
#else
	inBatchNumOfRecord = inBatchNumRecord();
	
	DebugAddINT("batch record",inBatchNumOfRecord);
	if(inBatchNumOfRecord <= 0)
	{
		vdDisplayErrorMsg(1, 8, "BATCH EMPTY");
		return;
	}

	vdSetPrintThreadStatus(1); /*BDO:Display printing image during report -- sidumili*/
	
    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
    vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);
    
	ushCTOS_printBatchRecordHeader();

	
	pinTransDataid = (int*)malloc(inBatchNumOfRecord  * sizeof(int));
	inCount = 0;		
	inBatchByMerchandHost(inBatchNumOfRecord, srTransRec.HDTid, srTransRec.MITid, srTransRec.szBatchNo, pinTransDataid);
	for(i=0; i<inBatchNumOfRecord; i++)
	{
		inResult = inDatabase_BatchReadByTransId(&srTransRec, pinTransDataid[inCount]);
        inCount ++;
		ushCTOS_printBatchRecordFooter();	
	}

//0720
	memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
	if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
	{
			vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
			return; 	 
	}


	CTOS_PrinterFline(d_LINE_DOT * 1);
	CTOS_PrinterFline(d_LINE_DOT * 1);

  memset(baTemp, 0x00, sizeof(baTemp));
	sprintf(szStr,"CARD TYPE        COUNT         AMT");
	CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

	for(inTranCardType = 0; inTranCardType < 1 ;inTranCardType ++)
	{
			inReportType = DETAIL_REPORT_TOTAL;
	
			for(i= 0; i <30; i ++ )
			{
				vdDebug_LogPrintf("--Count[%d]", i);
				if((srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount == 0)
//issue-00270 - show card type in Detail Report Totals per card even if cash advance is the only transaction
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount == 0))

					continue;
			
				vdDebug_LogPrintf("Count[%d]", i); 
				inIITRead(i);
				memset(szStr, ' ', d_LINE_SIZE);
				memset (baTemp, 0x00, sizeof(baTemp));

				/* BDO: USD setup - Load BDO host index to get the correct currency index - start -- jzg */
				inCSTRead(strHDT.inCurrencyIdx);
			    //deduct void cash advance count 
				vdCTOS_PrintAccumeByHostAndCard (inReportType, 
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 	
				(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 
//issue-00296-add void cash advance 				
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
				(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 
				
				//srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount, 
				//(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount), 
				
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount));	
			}

			
			printDividingLine(DIVIDING_LINE);
			
			inReportType = DETAIL_REPORT_GRANDTOTAL;
			
			vdCTOS_PrintAccumeByHostAndCard (inReportType, 
				
			//deduct void cash advance count 
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 	
				(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 

//issue-00296-add void cash advance 									
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
				(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 

				//srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount,
				//(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount), 
				
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount));		
}


//0720

			/* BDO: Include detailed report to settlement receipt - start -- jzg */
			if(fAddtoSettleReport == FALSE)
	    	CTOS_PrinterFline(d_LINE_DOT * 10);
			else
	    	CTOS_PrinterFline(d_LINE_DOT * 5);
			/* BDO: Include detailed report to settlement receipt - end -- jzg */

			vdSetPrintThreadStatus(0); /*BDO:Display printing image during report -- sidumili*/
	#endif
	
	return;	
}



void vdCTOS_PrintDetailTotals()
{
	//unsigned char chkey;
	//short shHostIndex;
	int inResult,i,inCount,inRet;
	int inTranCardType;
	int inReportType;
	//int inBatchNumOfRecord;
	//int *pinTransDataid;

//0720
	ACCUM_REC srAccumRec;
	BYTE baTemp[PAPER_X_SIZE * 64];
	char szStr[d_LINE_SIZE + 1];
//0720


vdDebug_LogPrintf("vdCTOS_PrintDetailTotals"); 

//0720
	memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
	if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
	{
			vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
			return; 	 
	}


	//CTOS_PrinterFline(d_LINE_DOT * 1);
	//CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(2);

  memset(baTemp, 0x00, sizeof(baTemp));
	sprintf(szStr,"CARD TYPE        COUNT         AMT");
	
	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

	for(inTranCardType = 0; inTranCardType < 1 ;inTranCardType ++)
	{	
			if(srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMGIFTCARD_HDT_INDEX)
				inTranCardType = 1;
							
			inReportType = DETAIL_REPORT_TOTAL;
			//00148 - No card type prints in Detail report  and manual settlement  with detail receipt for BDO Loyalty #1
			//for(i= 0; i <30; i ++ )
			for(i= 0; i <37; i ++ )
			{
				vdDebug_LogPrintf("--Count[%d]", i);
				if((srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount == 0)
//issue-00270 - show card type in Detail Report Totals per card even if cash advance is the only transaction
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount == 0))	
					continue;
			
				vdDebug_LogPrintf("Count[%d]", i); 
				inIITRead(i);
				memset(szStr, ' ', d_LINE_SIZE);
				memset (baTemp, 0x00, sizeof(baTemp));


				//00148 - No card type prints in Detail report	and manual settlement  with detail receipt for BDO Loyalty #2
				#if 1
				strcpy(szStr,strIIT.szIssuerLabel);
				//sprintf(szStr,"ISSUER: %s",strIIT.szIssuerLabel);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
				#endif


			
				vdCTOS_PrintAccumeByHostAndCard (inReportType, 
                //deduct void cash advance count to totals
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount - - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 	

				(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 

//issue-00296-add void cash advance 				
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
				(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 
				
				//srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount, 
				//(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount), 
				
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount));	
			}

			
			printDividingLine(DIVIDING_LINE);
			
			inReportType = DETAIL_REPORT_GRANDTOTAL;
			
			vdCTOS_PrintAccumeByHostAndCard (inReportType, 
				//deduct void cash advance count 
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 	
				(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 

//issue-00296-add void cash advance 									
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
				(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
				
				//srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, 
				//(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount), 
				
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
				
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount));		
}


//0720


    	//CTOS_PrinterFline(d_LINE_DOT * 5);
	vdCTOS_PrinterFline(5);

	
	return;	
}



int inCTOS_rePrintLastReceipt(void)
{
	int   inResult;
	BYTE  szInvNoAsc[6+1];
	BYTE  szInvNoBcd[3];	
    BOOL   needSecond = TRUE;	
    BYTE   key;
	//1027
	BOOL   needThird = TRUE;	

	/*BDO: Parameterized receipt printing - start*/
	BOOL BankCopy, CustCopy, MercCopy;
	BOOL fFirstReceiptPrinted = VS_FALSE;
	/*BDO: Parameterized receipt printing - end*/

    BOOL fFirstReceipt=TRUE; 
	int inReceiptCtr=0;
	BYTE szPrintOption[3+1];
	BYTE chPrintOption=0x00;
	
	//for MP200 no need print
	if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
    	return (d_OK);

	//vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
	if( printCheckPaper()==-1)
		return d_NO;

	inTCTReadLastInvoiceNo(1);
	
	memcpy(srTransRec.szInvoiceNo,strTCT.szLastInvoiceNo,INVOICE_BCD_SIZE);
	DebugAddHEX("last invoice", strTCT.szLastInvoiceNo,3 );

	if (inMultiAP_CheckMainAPStatus() == d_OK)
	{
		inResult = inCTOS_MultiAPBatchSearch(d_IPC_CMD_REPRINT_LAST);
		if(d_OK != inResult)
			return inResult;
	}
	else
	{
		if (inMultiAP_CheckSubAPStatus() == d_OK)
		{
			inResult = inCTOS_MultiAPGetVoid();
			if(d_OK != inResult)
				return inResult;
		}		
		inResult = inCTOS_BatchSearch();
		if(d_OK != inResult)
			return inResult;
	}

	/*BDO: Parameterized receipt printing - start*/
	inHDTRead(srTransRec.HDTid);

	if (srTransRec.byTransType == VOID){
		BankCopy = strHDT.fPrintVoidBankReceipt;
		CustCopy = strHDT.fPrintVoidCustReceipt;
		MercCopy = strHDT.fPrintVoidMercReceipt;
	}else{
		BankCopy = strHDT.fPrintBankReceipt;
		CustCopy = strHDT.fPrintCustReceipt;
		MercCopy = strHDT.fPrintMercReceipt;
	}
	/*BDO: Parameterized receipt printing - end*/


	//1026
	//inCSTRead(srTransRec.HDTid); // sidumili: commented
	//1026

	/*Issue# 000299 -- sidumili*/
	inCSTRead(srTransRec.inSavedCurrencyIdx);
	/*Issue# 000299 -- sidumili*/

	//BDO: Reload IIT to properly load PAN masking during reprint - start -- jzg
	vdDebug_LogPrintf("JEFF::IITid [%d]", srTransRec.IITid);
	inIITRead(srTransRec.IITid);
	//BDO: Reload IIT to properly load PAN masking during reprint - end -- jzg

	
	//save TID and MID retrived from batch
	memcpy(TempszTID, srTransRec.szTID, strlen( srTransRec.szTID));
	memcpy(TempszMID, srTransRec.szMID, strlen( srTransRec.szMID));
	
	if(srTransRec.byTransType == SMAC_BALANCE || srTransRec.byTransType == BALANCE_INQUIRY)
	{
		BankCopy = MercCopy = FALSE;
		CustCopy = TRUE;
		vdCTOS_PrintReceiptCopies(BankCopy, CustCopy, MercCopy, FALSE);
#if 0
		memcpy(strTCT.szLastInvoiceNo,strTCT.sz2ndLastInvoiceNo,INVOICE_BCD_SIZE);//Retrieve txn before Balance Inquiry to prevent NO RECORD FOUND after deletion of SMAC BALANCE txn from Batch.
		if((inResult = inTCTSave(1)) != ST_SUCCESS)
	    {
			vdDisplayErrorMsg(1, 7, "Update TCT fail");
			vdDisplayErrorMsg(1, 8, "sz2ndLastInvoiceNo");
	    }
		
		//inResult = inDatabase_BatchDeleteTransType(SMAC_BALANCE);//Delete ALL SMAC Balance transactions from Batch after successful reprint
		///*inMyFile_SMACFooterDelete();//Delete SMAC Footer*/ inDatabase_SMACFooterDeletebyTraceNum(&srTransRec);//Delete SMACFooter from table
#endif
	}
	else
	    vdCTOS_PrintReceiptCopies(BankCopy, CustCopy, MercCopy, FALSE);

	fECRBuildSendOK = TRUE;	
	if (fECRBuildSendOK){	
		strcpy(srTransRec.szRespCode,"00");
	    inResult = inMultiAP_ECRSendSuccessResponse();		
	}
	
	//vdCTOSS_PrinterEnd();
	return d_OK;
}

/*BDO: Parameterized receipt printing - start*/
USHORT ushCTOS_printReceipt(void)
{
	USHORT inRet;
    USHORT result;
    BYTE   key;
    BOOL   needSecond = TRUE;
		//1027
		BOOL   needThird = TRUE;	

    BOOL BankCopy, CustCopy, MercCopy;
		BOOL fFirstReceiptPrinted = VS_FALSE;
	int fNSRflag = 0;
    BOOL fFirstReceipt=TRUE; 
    int inReceiptCtr=0;
    BYTE szPrintOption[3+1];
    BYTE chPrintOption=0x00;
		
     
		if (srTransRec.byTransType == VOID){
			BankCopy = strHDT.fPrintVoidBankReceipt;
			CustCopy = strHDT.fPrintVoidCustReceipt;
			MercCopy = strHDT.fPrintVoidMercReceipt;
		}else{
			BankCopy = strHDT.fPrintBankReceipt;
			CustCopy = strHDT.fPrintCustReceipt;
			MercCopy = strHDT.fPrintMercReceipt;
		}

	//for MP200 no need print
	if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
    	return (d_OK);
    
	if( ((srTransRec.byTransType == BALANCE_INQUIRY || srTransRec.byTransType == SMAC_BALANCE) && strTCT.fEnablePrintBalanceInq == 1)
		|| ((srTransRec.byTransType == BALANCE_INQUIRY || srTransRec.byTransType == SMAC_BALANCE) && srTransRec.fSMACFooter == TRUE) )
		if( printCheckPaper()==-1)
    		return -1;

#if 0	
#if 0
	vdDisplayAnimateBmp(0,0, "Printer1(320240).bmp", "Printer2(320240).bmp", "Printer3(320240).bmp", NULL, NULL);
#else
	if (strlen(srTransRec.szRespCode) > 0){
		CTOS_LCDTClearDisplay();
		//vdDispTransTitle(srTransRec.byTransType);
		
		if(strTCT.fDisplayAPPROVED == TRUE && srTransRec.byTransType != SMAC_BALANCE && srTransRec.byTransType != BALANCE_INQUIRY) // Terminal will display the SMAC balance instead of the "APPROVED" message. 
		{
			vdDispTransTitle(srTransRec.byTransType);
			vdDisplayErrorMsgResp2(" ", " ","APPROVED");
				
			//vduiDisplayStringCenter(8,"TRANSACTION APPROVED"); /*BDO : Request -- sidumili*/
			//WaitKey(1);
		}
		else
			CTOS_Beep();
	}
#endif
#endif	


	

    //gcitra
	if (srTransRec.byTransType == CASH_LOYALTY){
		result = ushCTOS_printAll(CUSTOMER_COPY_RECEIPT);
		CTOS_KBDBufFlush();//cleare key buffer
	    	return (d_OK);
	}
    //gcitra
	fNSRflag = inNSRFlag();//inCTOSS_GetBatchFieldData(&srTransFlexiData, AMEX_NSR_FLAG, &fNSRflag, 1);
	
	vdDebug_LogPrintf("*** BEGIN PRINT RECEIPT ***");
	vdDebug_LogPrintf("fNSRflag=[%d],fNSRCustCopy=[%d]",fNSRflag,strTCT.fNSRCustCopy);
	if (fNSRflag == 1 && 1 != strTCT.fNSRCustCopy)
	{
		CustCopy = FALSE;//return (d_OK);
	}

    if(srTransRec.byTransType == SMAC_BALANCE || srTransRec.byTransType == BALANCE_INQUIRY) 
    {
		BankCopy=MercCopy=CustCopy=FALSE;
        if(strTCT.fEnablePrintBalanceInq == 1 || srTransRec.fSMACFooter == TRUE)
		    CustCopy=TRUE;
    }

	if(srTransRec.byTransType == KIT_SALE) 
    {
		BankCopy=CustCopy=FALSE;
		MercCopy=TRUE;        
    }
	else if(srTransRec.byTransType == PTS_AWARDING)
		BankCopy=MercCopy=CustCopy=FALSE;
	

	if(srTransRec.fDCC && (srTransRec.byTransType == SALE || srTransRec.byTransType == SALE_OFFLINE) && strTCT.inDCCMode == AUTO_OPTOUT_MODE)
	{
		inRet = usPrintReceiptDCCCopies(BankCopy, CustCopy, MercCopy, TRUE);

		if(inRet == VS_TXNFINISH)
			return inRet;
	}
	else
		vdCTOS_PrintReceiptCopies(BankCopy, CustCopy, MercCopy, TRUE);

	return (d_OK);
}
/*BDO: Parameterized receipt printing - end*/

USHORT ushCTOS_printErrorReceipt(void)
{
    USHORT result;
    BYTE   key;
    BOOL   needSecond = TRUE;
	
	char szStr[d_LINE_SIZE + 1];
   char szTemp[d_LINE_SIZE + 1];
   char szTemp1[d_LINE_SIZE + 1];
   char szTemp3[d_LINE_SIZE + 1];
   char szTemp4[d_LINE_SIZE + 1];
   char szTemp5[d_LINE_SIZE + 1];
   char szFormatPAN[strlen(srTransRec.szPAN) + 7];//to account for space as in PAN format and to include additional PAN no. 7 has been added -Meena 08/01/2012
   int inFmtPANSize;
   BYTE baTemp[PAPER_X_SIZE * 64];
   CTOS_FONT_ATTRIB stFONT_ATTRIB;
   int num,i,inResult;
   unsigned char tucPrint [24*4+1];    
   BYTE   EMVtagVal[64];
   USHORT EMVtagLen; 
   short spacestring;

	//for MP200 no need print
		if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
			return (d_OK);

    
    if( printCheckPaper()==-1)
    	return -1;

	memcpy(strTCT.szLastInvoiceNo,srTransRec.szInvoiceNo,INVOICE_BCD_SIZE);
	
	if((inResult = inTCTSave(1)) != ST_SUCCESS)
    {
		vdDisplayErrorMsg(1, 8, "Update TCT fail");
    }
	
	DebugAddHEX("LastInvoiceNum", strTCT.szLastInvoiceNo,3);

	inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
    vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);

	vdCTOSS_PrinterStart(100);
    CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  
	DebugAddSTR("ushCTOS_printAll","print...",20);
		

	ushCTOS_PrintHeader(d_FIRST_PAGE);

	memset(szTemp1, ' ', d_LINE_SIZE);
	sprintf(szTemp1,"%s",srTransRec.szHostLabel);
	vdPrintCenter(szTemp1);
	
	printDateTime();

    printTIDMID(FALSE); 
	
	printBatchInvoiceNO();
	
	szGetTransTitle(srTransRec.byTransType, szStr);     
		vdPrintTitleCenter(szStr);    
    if(srTransRec.byTransType == SETTLE)
    {
        DebugAddSTR("settle","print...",20);
    }
    else
    {
        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
    	memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
    	EMVtagLen = 0;
    	memset(szStr, ' ', d_LINE_SIZE);
    	vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);

    	sprintf(szStr, "%s", srTransRec.szCardLable);
    	vdMyEZLib_LogPrintf("Card label: %s",srTransRec.szCardLable);
    	
    	memset (baTemp, 0x00, sizeof(baTemp));
    	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

    	cardMasking(srTransRec.szPAN, PRINT_CARD_MASKING_1);
    	strcpy(szTemp4, srTransRec.szPAN);
    	memset (baTemp, 0x00, sizeof(baTemp));
    	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szTemp4, &stgFONT_ATTRIB);
    	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

        vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);
        
    	//Exp date and Entry mode
    	memset(szStr, ' ', d_LINE_SIZE);
    	memset(szTemp, 0, sizeof(szTemp));
    	memset(szTemp1, 0, sizeof(szTemp1));
    	memset(szTemp4, 0, sizeof(szTemp4));
    	memset(szTemp5, 0, sizeof(szTemp5));
    	wub_hex_2_str(srTransRec.szExpireDate, szTemp,EXPIRY_DATE_BCD_SIZE);
    	DebugAddSTR("EXP",szTemp,12);  
    	
    	for (i =0; i<4;i++)
    		szTemp[i] = '*';
    	memcpy(szTemp4,&szTemp[0],2);
    	memcpy(szTemp5,&szTemp[2],2);

    	if(srTransRec.byEntryMode==CARD_ENTRY_ICC)
    		memcpy(szTemp1,"Chip",4);
    	else if(srTransRec.byEntryMode==CARD_ENTRY_MANUAL)
    		memcpy(szTemp1,"Manual",6);
    	else if(srTransRec.byEntryMode==CARD_ENTRY_MSR)
    		memcpy(szTemp1,"Swipe",5);
    	else if(srTransRec.byEntryMode==CARD_ENTRY_FALLBACK)
    		memcpy(szTemp1,"Fallback",8);
    	
    	memset (baTemp, 0x00, sizeof(baTemp));
    	sprintf(szTemp,"%s%s/%s          %s%s","EXP: ",szTemp4,szTemp5,"ENT:",szTemp1);
    	
    	DebugAddSTR("ENT:",baTemp,12);  
    	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szTemp, &stgFONT_ATTRIB);
    	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

    		
     	memset (baTemp, 0x00, sizeof(baTemp));
    	stFONT_ATTRIB.FontSize = 0x1010;
        stFONT_ATTRIB.X_Zoom = DOUBLE_SIZE;       // The width magnifies X_Zoom diameters
        stFONT_ATTRIB.Y_Zoom = DOUBLE_SIZE;       // The height magnifies Y_Zoom diameters

        stFONT_ATTRIB.X_Space = 0;      // The width of the space between the font with next font

    }

	memset(szStr, ' ', d_LINE_SIZE);
	memset(szTemp, ' ', d_LINE_SIZE);
	memset(szTemp1, ' ', d_LINE_SIZE);
	sprintf(szStr, "%s", "TRANS NOT SUC.");
	
	memset (baTemp, 0x00, sizeof(baTemp));
	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stFONT_ATTRIB);
	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

	memset(szStr, ' ', d_LINE_SIZE);
	memset(szTemp, ' ', d_LINE_SIZE);
	memset(szTemp1, ' ', d_LINE_SIZE);
	
	sprintf(szStr, "%s", "PLS TRY AGAIN");
	
	memset (baTemp, 0x00, sizeof(baTemp));
	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stFONT_ATTRIB);
	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

	//CTOS_PrinterFline(d_LINE_DOT * 6); 
	vdCTOS_PrinterFline(6);
	
	vdCTOSS_PrinterEnd();
	//inSetTextMode();
    return (d_OK);
}


int inCTOS_REPRINT_ANY()
{
    char szErrMsg[30+1];
    int   inResult,inRet;
	
	fRePrintFlag = TRUE;
	memset(TempszTID, 0x00, sizeof(TempszTID));	
	memset(TempszMID, 0x00, sizeof(TempszMID));
	
    vdCTOS_SetTransType(REPRINT_ANY);

	if ((strTCT.fECR) &&  (fECRTxnFlg == 1))//glad0129 - only check if ECR triggered
    {
    	CTOS_LCDTClearDisplay();
        vdDebug_LogPrintf("vdCTOS_TxnsBeginInit check Database exist");
    	if (file_exist (DB_MULTIAP))
    	{
    	    vdDebug_LogPrintf("vdCTOS_TxnsBeginInit Read ECR Data");
    		inRet = inCTOS_MultiAPGetData();
            vdDebug_LogPrintf("vdCTOS_TxnsBeginInit Read ECR Data ret[%d]", inRet);

			//set as ECRtriggered trans
			
			srTransRec.fECRTriggerTran = TRUE;
			srTransRec.fECRTrxFlg = TRUE; /*Flag for multiAP database and flag for multi app -- sidumili*/		
						
    		if(d_OK != inRet)
    			return ;
    	}
    }
	
    CTOS_LCDTSelectFontSize(d_FONT_16x30);
	inResult = inCTOS_rePrintReceipt();

	if (!fECRBuildSendOK)
	{	
		inMultiAP_ECRSendSuccessResponse();	
	}
	
	fECRBuildSendOK = FALSE;
	
    memset(szErrMsg,0x00,sizeof(szErrMsg));
    if (inGetErrorMessage(szErrMsg) > 0)
    {
        vdDisplayErrorMsg(1, 8, szErrMsg);
        vdSetErrorMessage("");
    }
    
    memset( &srTransRec, 0x00, sizeof(TRANS_DATA_TABLE));
    CTOS_KBDBufFlush();
	fRePrintFlag = FALSE;
	return inResult;
}

int inCTOS_REPRINT_LAST()
{
    char szErrMsg[30+1];
	int   inResult;


//test 
	if ((strTCT.fECR) &&  (fECRTxnFlg == 1))
    {
        CTOS_LCDTClearDisplay();
    }
    
    CTOS_LCDTSelectFontSize(d_FONT_16x30);
	fRePrintFlag = TRUE;
	
	memset(TempszTID, 0x00, sizeof(TempszTID));	
	memset(TempszMID, 0x00, sizeof(TempszMID));
	
	inResult = inCTOS_rePrintLastReceipt();	

	
	if (!fECRBuildSendOK)
	{	
		inMultiAP_ECRSendSuccessResponse();	
	}
	
	fECRBuildSendOK = FALSE;

    memset(szErrMsg,0x00,sizeof(szErrMsg));
    if (inGetErrorMessage(szErrMsg) > 0)
    {
        vdDisplayErrorMsg(1, 8, szErrMsg);
        vdSetErrorMessage("");
    }
    
    memset( &srTransRec, 0x00, sizeof(TRANS_DATA_TABLE));
    CTOS_KBDBufFlush();
	fRePrintFlag = FALSE;
	
	return inResult;
}

int inCTOS_PRINTF_SUMMARY()
{
    char szErrMsg[30+1];

	//GetReportTime();

	vdDebug_LogPrintf("inCTOS_PRINTF_SUMMARY");

	vdCTOS_PrintSummaryReport();	

    memset(szErrMsg,0x00,sizeof(szErrMsg));
    if (inGetErrorMessage(szErrMsg) > 0)
    {
        vdDisplayErrorMsg(1, 8, szErrMsg);
        vdSetErrorMessage("");
    }
    
    memset( &srTransRec, 0x00, sizeof(TRANS_DATA_TABLE));
    CTOS_KBDBufFlush();

	
	vdDebug_LogPrintf("inCTOS_PRINTF_SUMMARY END");

	return d_OK;
	
}

int inCTOS_PRINTF_DETAIL()
{
    char szErrMsg[30+1];

		//GetReportTime();

		vdCTOS_PrintDetailReport(FALSE, FALSE);	

    memset(szErrMsg,0x00,sizeof(szErrMsg));
    if (inGetErrorMessage(szErrMsg) > 0)
    {
        vdDisplayErrorMsg(1, 8, szErrMsg);
        vdSetErrorMessage("");
    }
    
    memset( &srTransRec, 0x00, sizeof(TRANS_DATA_TABLE));
    CTOS_KBDBufFlush();
    
	return d_OK;
	
}

int inCTOS_REPRINTF_LAST_SETTLEMENT()
{
    char szErrMsg[30+1];

    
	  ushCTOS_ReprintLastSettleReport();

	  
	  fRePrintFlag=FALSE;
    
    memset(szErrMsg,0x00,sizeof(szErrMsg));
    if (inGetErrorMessage(szErrMsg) > 0)
    {
        vdDisplayErrorMsg(1, 8, szErrMsg);
        vdSetErrorMessage("");
    }
    memset( &srTransRec, 0x00, sizeof(TRANS_DATA_TABLE));
    CTOS_KBDBufFlush();
    
	return d_OK;
}

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
	double ulTipTotalAmount) 
	//1105
{
	char szStr[d_LINE_SIZE + 3] = {0},
		szTemp[d_LINE_SIZE + 3] = {0}, 
		szTemp1[d_LINE_SIZE + 3] = {0}, 
		szTemp2[d_LINE_SIZE + 3] = {0};
	USHORT usTotalCount = 0;
	double ulTotalAmount = 0;
	BYTE baTemp[PAPER_X_SIZE * 64] = {0};

	char szBuff[47] = {0};
	int inPADSize = 0, x = 0;
	char szSPACE[40] = {0};

	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  
	memset (baTemp, 0x00, sizeof(baTemp));		


	//0720
		if((inReportType == DETAIL_REPORT_TOTAL) || (inReportType == DETAIL_REPORT_GRANDTOTAL)){
	    
			usTotalCount = usSaleCount + usOffSaleCount + usRefundCount + usCashAdvCount + usVoidSaleCount;
			memset(baTemp, 0x00, sizeof(baTemp));
			//add cash advance in totals amount
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount+ulCashAdvTotalAmount) - ulRefundTotalAmount;
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));
			
			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	
				
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);

			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%d",usTotalCount);
			memset(szStr, 0x20, sizeof(szStr));
				
			if (inReportType == DETAIL_REPORT_TOTAL)
				memcpy(&szStr[0],strIIT.szIssuerLabel, strlen(strIIT.szIssuerLabel));
			else
				memcpy(&szStr[0],"TOTAL", 5);
				
			memcpy(&szStr[18],szTemp1, strlen(szTemp1));
			memcpy(&szStr[42-strlen(szTemp)],szTemp, strlen(szTemp));

	    	memset(baTemp, 0x00, sizeof(baTemp));
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	
	    return;
		}
	//0720


//smac
  if (inCheckIfSMCardTransRec() == TRUE)//SM CARDS SUMMARY REPORT
  	{
	  memset(szStr, 0x00, sizeof(szStr));
	  memset(szBuff, 0x00, sizeof(szBuff));
	  memset(szTemp1, 0x00, sizeof(szTemp1)); 
	  memset(szTemp2, 0x00, sizeof(szTemp2));

	  if ((srTransRec.HDTid == SMAC_HDT_INDEX)){
		  sprintf(szTemp1,"%.0f", ulOffSaleTotalAmount);		  
		  vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	  
		  sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
		  sprintf(szStr,"PTS AWARDED   %04d",usOffSaleCount);
		  inPrintLeftRight2(szStr,szBuff,42);

		  sprintf(szTemp1,"%.0f", ulSaleTotalAmount);		  
		  vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	  
		  sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
		  sprintf(szStr,"REDEMPTION    %04d",usSaleCount);
		  
		  inPrintLeftRight2(szStr,szBuff,42);
	  }

	  if (srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMPARTNER_HDT_INDEX || srTransRec.HDTid == SMSHOPCARD_HDT_INDEX || 
	  	srTransRec.HDTid == SMGIFTCARD_HDT_INDEX || srTransRec.HDTid == SMECARD_HDT_INDEX || srTransRec.HDTid == SM_CREDIT_CARD || srTransRec.HDTid == SMSHOPCARD_HDT_INDEX){
	  	  sprintf(szTemp1,"%.0f", ulSaleTotalAmount);		  
		  vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	  
		  sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
		  sprintf(szStr,"SALE          %04d",usSaleCount);
		  
		  inPrintLeftRight2(szStr,szBuff,42);
	  }

	//void
	  memset(szStr, 0x00, sizeof(szStr));
	  memset(szBuff, 0x00, sizeof(szBuff));
	  memset(szTemp1, 0x00, sizeof(szTemp1));	
	  memset(szTemp2, 0x00, sizeof(szTemp2));

	  sprintf(szTemp1,"%.0f", ulVoidSaleTotalAmount);

	  if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
      else
	  	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	  sprintf(szBuff,"-%s%s",strCST.szCurSymbol,szTemp2);
	  sprintf(szStr,"VOID          %04d",usVoidSaleCount);
	  inPrintLeftRight2(szStr,szBuff,42);


	usTotalCount = usSaleCount + usOffSaleCount + usRefundCount + usCashAdvCount + usVoidSaleCount;
	memset(szStr, 0x00, d_LINE_SIZE);
	memset(szTemp, 0x00, d_LINE_SIZE);
	if (inReportType == PRINT_HOST_TOTAL)
	{
		if(ulRefundTotalAmount > (ulSaleTotalAmount+ulOffSaleTotalAmount))
		{
			ulTotalAmount = ulRefundTotalAmount - (ulSaleTotalAmount+ulOffSaleTotalAmount);

			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);	
			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"-%s%s",strCST.szCurSymbol,szTemp2);
			//sprintf(szStr,"  TOTALS");		
			sprintf(szStr,"TOT.          %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}
		else
		{
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount) - ulRefundTotalAmount;

			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);
			
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);
			//sprintf(szStr,"  TOTALS");			
			sprintf(szStr,"TOT.          %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}
	}
	else if(inReportType == PRINT_CARD_TOTAL)
	{
		if(ulRefundTotalAmount > (ulSaleTotalAmount+ulOffSaleTotalAmount))
		{
			ulTotalAmount = ulRefundTotalAmount - (ulSaleTotalAmount+ulOffSaleTotalAmount);
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));
			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"-%s%s",strCST.szCurSymbol,szTemp2);
			//sprintf(szStr,"  TOTALS");		
			sprintf(szStr,"TOT.          %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}
		else
		{
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount) - ulRefundTotalAmount;
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);
			//sprintf(szStr,"  TOTALS");	
			sprintf(szStr,"TOT.          %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}	 
	}



	//CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);



    return;
  }  
//smac
//BDO CARDS SUMMARY REPORT
	//sale 
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulSaleTotalAmount+ulOffSaleTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"SALE     %04d",usSaleCount+usOffSaleCount);
	inPrintLeftRight2(szStr,szBuff,42);

	//Base amount
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", (ulSaleTotalAmount+ulOffSaleTotalAmount) - ulTipTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"BASE");		
	inPrintLeftRight2(szStr,szBuff,42);

	//tip
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulTipTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	strcpy(szStr,"TIP");
	inPrintLeftRight2(szStr,szBuff,42);

	//void
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulVoidSaleTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"-%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"VOID     %04d",usVoidSaleCount);
	inPrintLeftRight2(szStr,szBuff,42);

//remove- version16
#if 0
	//refund
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulRefundTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"REF.     %04d",usRefundCount);
	inPrintLeftRight2(szStr,szBuff,42);
#endif

#if 0		
	//offline sale
	memset(szStr, ' ', d_LINE_SIZE);
	sprintf(szStr,"OFFLINE  %3d  %s  %10lu.%02lu", usOffSaleCount, strCST.szCurSymbol,ulOffSaleTotalAmount/100, ulOffSaleTotalAmount%100);
	memset (baTemp, 0x00, sizeof(baTemp));
	CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);		
#endif


	//Cash Advance
    if (strTCT.fDefaultCashAdvance == 1){

	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulCashAdvTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"CADV     %04d",usCashAdvCount);
	inPrintLeftRight2(szStr,szBuff,42);
    }
	usTotalCount = usSaleCount + usOffSaleCount + usRefundCount+usCashAdvCount;
	memset(szStr, 0x00, d_LINE_SIZE);
	memset(szTemp, 0x00, d_LINE_SIZE);
	
	if (inReportType == PRINT_HOST_TOTAL)
	{
		if(ulRefundTotalAmount > (ulSaleTotalAmount+ulOffSaleTotalAmount))
		{
			ulTotalAmount = ulRefundTotalAmount - (ulSaleTotalAmount+ulOffSaleTotalAmount);

			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"-%s%s",strCST.szCurSymbol,szTemp2);
			sprintf(szStr,"TOT.     %04d", usTotalCount);	
			inPrintLeftRight2(szStr,szTemp,42);
		}
		else
		{
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount+ulCashAdvTotalAmount) - ulRefundTotalAmount;

			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);
			sprintf(szStr,"TOT.     %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}
	}
	else if(inReportType == PRINT_CARD_TOTAL)
	{
		if(ulRefundTotalAmount > (ulSaleTotalAmount+ulOffSaleTotalAmount))
		{
			ulTotalAmount = ulRefundTotalAmount - (ulSaleTotalAmount+ulOffSaleTotalAmount);
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));
			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"-%s%s",strCST.szCurSymbol,szTemp2);
			sprintf(szStr,"TOT.     %04d", usTotalCount);	
			inPrintLeftRight2(szStr,szTemp,42);
		}
		else
		{
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount+ulCashAdvTotalAmount) - ulRefundTotalAmount;
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);
			sprintf(szStr,"TOT.     %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}	 
	}



	//CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);
}

int inCTOS_SelectFont(int inFontMode,int inFontSize ,int inFontStyle,char * szFontName)
{
	if(inFontMode == d_FONT_TTF_MODE)
	{
		CTOS_PrinterFontSelectMode(d_FONT_TTF_MODE);	//set the printer with TTF Mode
		CTOS_PrinterTTFSelect("times.ttf", inFontStyle);
	}
	else
	{
	
		CTOS_PrinterFontSelectMode(d_FONT_FNT_MODE);	//set the printer with default Mode
		CTOS_LanguagePrinterFontSize(inFontSize, 0, TRUE);		
	}
	return d_OK;
	
}

int inCTOS_PrintSettleReport(BOOL fManualSettlement)
{
	ACCUM_REC srAccumRec;
	unsigned char chkey;
	short shHostIndex;
	int inResult;
	int inTranCardType;
	int inReportType;
	int i;		
	char szStr[d_LINE_SIZE + 1];
	BYTE baTemp[PAPER_X_SIZE * 64];	

	int inTempTransType;
    BYTE        szTempDate[DATE_BCD_SIZE+1];     
    BYTE        szTempTime[TIME_BCD_SIZE+1];     


   srTransRec.fManualSettlement=fManualSettlement; 
	inCSTRead(strHDT.inCurrencyIdx);
	//for MP200 no need print
	if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
    	return (d_OK);
	
	if( printCheckPaper()==-1)
		return;
	
	inResult = inCTOS_ChkBatchEmpty();
	if(d_OK != inResult)
	{
        //add return the correct value
		//return;
		return inResult;
	}

    if (fManualSettle != TRUE)
		inCTLOS_Updatepowrfail(PFR_BATCH_SETTLEMENT_PRINT);//1204

	//save Orig Trans type before detail report
	inTempTransType = srTransRec.byTransType;

	memset(szTempTime, 0x00, sizeof(szTempTime));
	wub_hex_2_str(srTransRec.szTime, szTempTime, 3);

	if(strlen(szTempTime) <= 0)
		SetReportTime();
	
	//save date and time for retrieval later-after printing of details report
    memset(szTempDate, 0x00, sizeof(szTempDate));
    memset(szTempTime, 0x00, sizeof(szTempTime));
	memcpy(szTempDate, srTransRec.szDate, DATE_BCD_SIZE);
	memcpy(szTempTime, srTransRec.szTime, TIME_BCD_SIZE);


    /* BDO: Include detailed report to settlement receipt - start -- jzg */
    if(srTransRec.byTransType == MANUAL_SETTLE || fAUTOManualSettle == TRUE)
        vdCTOS_PrintDetailReport(TRUE, FALSE);    
    else if(strTCT.fPrintSettleDetailReport == TRUE)
        vdCTOS_PrintDetailReport(TRUE, FALSE);



	//Reload back Original Trans Type
	srTransRec.byTransType = inTempTransType;

	memcpy(srTransRec.szDate, szTempDate, DATE_BCD_SIZE);
	memcpy(srTransRec.szTime, szTempTime,  TIME_BCD_SIZE);

	/* BDO: Include detailed report to settlement receipt - end -- jzg */
  //aaronnino for BDOCLG ver 9.0 fix on issue #00102 Manual settle prints settlement closed instead of summary report 4 of 4
	//if(fManualSettle == TRUE)
	//{
	//	 vdCTOS_SetTransType(MANUAL_SETTLE);
		 //fManualSettle = FALSE;
	//}
	//aaronnino for BDOCLG ver 9.0 fix on issue #00102 Manual settle prints settlement closed instead of summary report 4 of 4
	memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
    {
        vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
		vdSetErrorMessage("Read Accum Error");
        return ST_ERROR;    
    }
    
    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);



	/* BDO: Include detailed report to settlement receipt - start -- jzg */
	//if(strTCT.fPrintSettleDetailReport == FALSE)
	//{

	
	vdPrintReportDisplayBMP(); //fix for issue 322. Printing animation is not displayed if fPrintSettleDetailReport=0

	
	//SetReportTime();
	ushCTOS_PrintHeader(0);	
	//CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	printTIDMID(TRUE);
	
	//memset(srTransRec.szTime, 0x00, sizeof(srTransRec.szTime));
	printDateTime();
	printBatchNO();
	//}
	/* BDO: Include detailed report to settlement receipt - end -- jzg */


	vdDebug_LogPrintf("GLAD TEST = [%d][%d]", srTransRec.byTransType, srTransRec.HDTid);


    //vdDispTitleString("TEST CLEAR BATCH 4");
	//CTOS_Delay(2000);

	/* BDO: if settlement title should be "SETTLEMENT CLOSED", if manual posting "SUMMARY REPORT" */
		vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		//if (srTransRec.byTransType == SETTLE) //aaronnino for BDOCLG ver 9.0 fix on issue #00082 Upon settlement with detail report, "SUMMARY REPORT" is printing in receipt instead of "SETTLEMENT CLOSED" 
		//if(fManualSettle == TRUE)
		
	  	if ((srTransRec.byTransType == SETTLE) && (fAUTOManualSettle==FALSE)&& (fManualSettlement==FALSE))	
	  	{
			vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
			vdPrintCenter("SETTLEMENT CLOSED");
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 0, 0);
			vdPrintCenter("    *** TRANSACTION TOTALS BY ISSUER ***");
	  	}
		else
			vdPrintCenter("SUMMARY REPORT");
		
		
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);



    //CTOS_PrinterFline(d_LINE_DOT * 1);
	  vdCTOS_PrinterFline(1);
	for(inTranCardType = 0; inTranCardType < 1 ;inTranCardType ++)
	{
		if(srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMGIFTCARD_HDT_INDEX)
			inTranCardType = 1;
		
		inReportType = PRINT_CARD_TOTAL;
		
		if(inReportType == PRINT_CARD_TOTAL)
		{
			//00147 - No issuer name prints in summary report, settlement report and manual settlement report for BDO Loyalty
			//for(i= 0; i <30; i ++ )
			for(i= 0; i <37; i ++ )				
			{
				vdDebug_LogPrintf("--Count[%d]", i);
				if((srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount == 0)
				//issue:00269 - Print Issue totals even if Cash advance is the only transaction 
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount == 0)
				/*&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usKitSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRenewalCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usPtsAwardCount == 0)*/)
				{				
					
					vdDebug_LogPrintf("continue"); 
					continue;
				}
				
				vdDebug_LogPrintf("Count[%d]", i); 
				inIITRead(i);
				memset(szStr, ' ', d_LINE_SIZE);
				memset (baTemp, 0x00, sizeof(baTemp));
				//strcpy(szStr,strIIT.szIssuerLabel);
				sprintf(szStr,"ISSUER: %s",strIIT.szIssuerLabel);
				//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
				//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

				
				if (inCheckIfSMCardTransRec() == TRUE){
				#if 0
					vdCTOS_PrintAccumeByHostAndCard (inReportType,
					/*issue-00043*/
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount,   
					(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) ,									
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 
					//issue-00296-add void cash advance 				
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
					(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 								
					//srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount), 
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount));	
				#else
					vdCTOS_PrintSMAccumeByHostAndCard(inReportType, 
					//deduct void cash advance on Detail total
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount,	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount,
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount, 
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
	            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount,
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount,
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount,
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usKitSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulKitSaleTotalAmount,
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRenewalCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRenewalTotalAmount,
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usPtsAwardCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulPtsAwardTotalAmount
					);
				#endif

				}else{
					if(inCheckIfDCCHost() == TRUE)
	 					vdCTOS_DCCPrintAccumeByHostAndCard (inReportType, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i]);
					else
						vdCTOS_PrintAccumeByHostAndCard (inReportType,
						/*issue-00043*/
						srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount  + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount,   
						(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),									
						srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 
						//issue-00296-add void cash advance 				
						srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
						(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 								
						//srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount), 
						srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
						srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),
						srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount));	
				}
			}
			//after print issuer total, then print host toal
			{
					if (inCheckIfSMCardTransRec() == TRUE){

					}else{

						memset(szStr, ' ', d_LINE_SIZE);
						memset (baTemp, 0x00, sizeof(baTemp));
						//strcpy(szStr,"TOTAL:");
						strcpy(szStr,"GRAND TOTALS");
						inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
						
						if(inCheckIfDCCHost() == TRUE)
							vdCTOS_DCCPrintAccumeByHostAndCard (PRINT_HOST_TOTAL, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal);
						else
						{
                            vdCTOS_PrintAccumeByHostAndCard (inReportType, 			
                            /*issue-00043*/
                            (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount) +
                            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, 	
                            (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),													
                            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
                            //issue-00296-add void cash advance 									
                            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
                            (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 													
                            //srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount), 
                            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
                            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
                            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount));	
						}
					}
			}
		}
		else
		{
		
			memset(szStr, ' ', d_LINE_SIZE);
			memset (baTemp, 0x00, sizeof(baTemp));
			strcpy(szStr,srTransRec.szHostLabel);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

			
			if (inCheckIfSMCardTransRec() == TRUE){
				#if 0
				vdCTOS_PrintAccumeByHostAndCard (inReportType, 
				/*issue-00043*/
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount,   
				(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount),										
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
				//issue-00296-add void cash advance 									
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
				(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 											
				//srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount), 
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount));	
				#else
				vdCTOS_PrintSMAccumeByHostAndCard(inReportType, 
				//deduct void cash advance on Detail total
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, 	
	        	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount),
	        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
	        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
	        	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
	        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
	        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
	        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount),
	        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usKitSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulKitSaleTotalAmount),
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRenewalCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRenewalTotalAmount),
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usPtsAwardCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulPtsAwardTotalAmount)
				);
				#endif
			}else{
				vdCTOS_PrintAccumeByHostAndCard (inReportType, 
				/*issue-00043*/
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount  + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount,   
				(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),										
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
				//issue-00296-add void cash advance 									
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
				(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 											
				//srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount), 
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount));	
			}
		}
	}
    
	//print space one line
	//CTOS_PrinterFline(d_LINE_DOT * 2);		
	//CTOS_PrinterFline(d_LINE_DOT * 2);
	//CTOS_PrinterFline(d_LINE_DOT * 2);
	vdCTOS_PrinterFline(6);
	
	if(strTCT.byERMMode != 0)
		inCTOSS_ERM_Form_Receipt(1);

	vdCTOSS_PrinterEnd();
	memset(&strIIT,0x00, sizeof(STRUCT_IIT));//memset as to not carry over IIT values on next host if Settle all is performed.
	return d_OK;

}

USHORT ushCTOS_printBatchRecordHeader(void)
{
	USHORT result;
	BYTE baTemp[PAPER_X_SIZE * 64];


	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

    ushCTOS_PrintHeader(0);	
     
	printTIDMID(TRUE);
    
	printDateTime();
    
	printBatchNO();

	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
    vdPrintCenter("DETAIL REPORT");

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    
    //if(strTCT.fSMMode == TRUE)//Removed condition for SM and BDO to have same Detail Report format
    //{
    vdCTOS_PrinterFline(1);
    memset (baTemp, 0x00, sizeof(baTemp));
    inCCTOS_PrinterBufferOutput("CARD NAME              CARD NUMBER",&stgFONT_ATTRIB,1);
    memset (baTemp, 0x00, sizeof(baTemp));
            
    if(inCheckIfSMCardTransRec() == TRUE)
		inCCTOS_PrinterBufferOutput("TRANSACTION            TRACE NUMBER",&stgFONT_ATTRIB,1);	
	else
	    inCCTOS_PrinterBufferOutput("EXP DATE               TRACE NUMBER",&stgFONT_ATTRIB,1);
    memset (baTemp, 0x00, sizeof(baTemp));
    /*}
	else
	{
        vdCTOS_PrinterFline(1);
        memset (baTemp, 0x00, sizeof(baTemp));
        inCCTOS_PrinterBufferOutput("CARD NAME              TRACE NUMBER",&stgFONT_ATTRIB,1);
        memset (baTemp, 0x00, sizeof(baTemp));
	}
	*/
	
	if(inCheckIfSMCardTransRec() == TRUE)
		inCCTOS_PrinterBufferOutput("APPROVAL CODE          AMOUNT",&stgFONT_ATTRIB,1);
	else
	{
		if(inCheckIfDCCHost() == TRUE)
			inCCTOS_PrinterBufferOutput("TRANSACTION            DCC AMOUNT",&stgFONT_ATTRIB,1);
		else
			inCCTOS_PrinterBufferOutput("TRANSACTION            AMOUNT",&stgFONT_ATTRIB,1);
		
		memset (baTemp, 0x00, sizeof(baTemp));

		if(inCheckIfDCCHost() == TRUE)
			inCCTOS_PrinterBufferOutput("APPROVAL CODE          PHP AMOUNT",&stgFONT_ATTRIB,1);
		else
			inCCTOS_PrinterBufferOutput("APPROVAL CODE",&stgFONT_ATTRIB,1);
	}
	
	printDividingLine(DIVIDING_LINE);
	return d_OK;
}

USHORT ushCTOS_printBatchRecordFooter(void)
{
	BYTE baTemp[PAPER_X_SIZE * 64] = {0};
	char szStr[d_LINE_SIZE + 1] = {0};
	char szPrintBuf[d_LINE_SIZE + 1] = {0};
	char szTempBuf1[d_LINE_SIZE + 1] = {0};
	char szTempBuf2[d_LINE_SIZE + 1] = {0};
	char szTempBuf3[d_LINE_SIZE + 1] = {0};
	char szTempBuf4[d_LINE_SIZE + 1] = {0};
	char szTemp[d_LINE_SIZE + 3] = {0};
	int i = 0;

	DebugAddSTR("ushCTOS_printBatchRecordFooter", srTransRec.szPAN, 10);

    //test
    memset(szStr, 0x00, sizeof(szStr));
    wub_hex_2_str(srTransRec.szInvoiceNo, szStr, INVOICE_BCD_SIZE);
	vdDebug_LogPrintf("TRANS TYPE %d %s %d", srTransRec.byTransType, szStr, srTransRec.fOnlineSALE );

	
	//test
	/*sidumili: Issue#: 000098 [do not print CARD VERIFY/PRE-AUTH on detail report]*/
	if (srTransRec.byTransType == PRE_AUTH || srTransRec.byTransType == SMAC_BALANCE || srTransRec.byTransType == BALANCE_INQUIRY
		|| srTransRec.byTransType == KIT_SALE || srTransRec.byTransType == RENEWAL || srTransRec.byTransType == PTS_AWARDING)
	{ 
		return;
	}

	memset(szTempBuf1,0,sizeof(szTempBuf1));
	memset(szTempBuf2,0,sizeof(szTempBuf2));
	memset(szTempBuf4, 0, sizeof(szTempBuf4));
	//strcpy(szTempBuf1,srTransRec.szPAN);    
	inIITRead(srTransRec.IITid);
	strcpy(szTempBuf4,strIIT.szIssuerLabel);
#if 0	
	if (strlen(szTempBuf1) > 16)	
		cardMasking(szTempBuf1, PRINT_CARD_MASKING_4);
	else
		cardMasking(szTempBuf1, PRINT_CARD_MASKING_3);
#else
	vdCTOS_FormatPAN2(strHDT.szDetailReportMask, srTransRec.szPAN, szTempBuf1);
	if (strlen(srTransRec.szPAN) > 16)
		vdRemoveSpace(szTempBuf2, szTempBuf1);		
	else
		strcpy(szTempBuf2, szTempBuf1);
#endif

	memset (szPrintBuf, 0x00, sizeof(szPrintBuf));
	strcpy(szPrintBuf, szTempBuf4);
	memset(&szPrintBuf[strlen(szPrintBuf)], 0x20, 23-strlen(szTempBuf4));
	strcat(szPrintBuf, szTempBuf2);
	memset (baTemp, 0x00, sizeof(baTemp));
	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1,szPrintBuf , &stgFONT_ATTRIB);
	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	//if(strTCT.fSMMode == TRUE)
	    inCCTOS_PrinterBufferOutput(szPrintBuf,&stgFONT_ATTRIB,1);

	if(inCheckIfSMCardTransRec() == FALSE)
	{
		//Exp date and inv num
		memset(szTempBuf1, 0, sizeof(szTempBuf1));
		memset(szTempBuf2, 0, sizeof(szTempBuf2));
		memset(szTempBuf3, 0, sizeof(szTempBuf3));

		wub_hex_2_str(srTransRec.szExpireDate, szTempBuf1,EXPIRY_DATE_BCD_SIZE);
		DebugAddSTR("detail--EXP",szTempBuf1,12);  

		for (i =0; i<4;i++)
			szTempBuf1[i] = '*';
		
		memcpy(szTempBuf2,&szTempBuf1[0],2);
		memcpy(szTempBuf3,&szTempBuf1[2],2);

		memset(szStr, 0,sizeof(szStr));
		wub_hex_2_str(srTransRec.szInvoiceNo, szStr, INVOICE_BCD_SIZE);

		memset (szPrintBuf, 0x00, sizeof(szPrintBuf));
		strcpy(szPrintBuf, szTempBuf2);
		strcat(szPrintBuf, szTempBuf3);
		memset(&szPrintBuf[strlen(szPrintBuf)], 0x20, 23-strlen(szTempBuf2)-strlen(szTempBuf3));
		strcat(szPrintBuf, szStr);
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1,szPrintBuf , &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		
	    //if(strTCT.fSMMode == TRUE)
	        inCCTOS_PrinterBufferOutput(szPrintBuf,&stgFONT_ATTRIB,1);
		/*else

		{
			memset(szTempBuf1, 0,sizeof(szTempBuf1));
			sprintf(szTempBuf1, "%-23.23s%s",szTempBuf4, szStr);
			//inPrintLeftRight(szTempBuf4, szStr, 42);
			inPrint(szTempBuf1);
		}*/

		memset(szStr, 0,sizeof(szStr));
		memset(szTempBuf1, 0,sizeof(szTempBuf1));
		memset(szTempBuf2, 0,sizeof(szTempBuf2));
		szGetTransTitle(srTransRec.byTransType, szStr);

		//test
	    if (srTransRec.byTransType == VOID){


			if((memcmp(srTransRec.szAuthCode,"Y1",2) == 0) || (srTransRec.fOnlineSALE == TRUE))
				strcpy(szStr, "VOID");					
	    }

		//test
		wub_hex_2_str(srTransRec.szTotalAmount, szTempBuf1, AMT_BCD_SIZE);

	//SMAC 
	    //change SALE to REDEMPTION 
	    //change OFFLINE to PTS AWARDED



#if 0
	    if (srTransRec.HDTid == SMAC_HDT_INDEX){
			
			memset(szStr, 0,sizeof(szStr));
	    	if (srTransRec.byTransType == SALE)
				strcpy(szStr,"Redeem Pts");
		
	    	else if (srTransRec.byTransType == SALE_OFFLINE)
				strcpy(szStr,"Award Pts");


			if((srTransRec.byTransType == VOID) ||
				(srTransRec.byTransType == OFFLINE_VOID)){

				if (srTransRec.byOrgTransType== SALE)
						strcpy(szStr,"VOID Redeem Pts");
				else if (srTransRec.byOrgTransType == SALE_OFFLINE)
					strcpy(szStr,"VOID Award Pts");

			}
	    
	    }
#endif
	//SMAC

		memset(szTemp, 0x00, sizeof(szTemp)); 
		sprintf(szTemp,"%s", szTempBuf1);		

		memset(szTempBuf1, 0, sizeof(szTempBuf1));
		memset(szTempBuf2, 0, sizeof(szTempBuf2));

		if(srTransRec.HDTid >= 6 && srTransRec.HDTid <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
			vdDCCModifyAmount(szTemp,szTempBuf1);
		else
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp, szTempBuf1);// patrick add code 20141216
			
	    sprintf(szTempBuf2,"%s%s",strCST.szCurSymbol, szTempBuf1);
	    
		/* BDO: Add negative sign to amount on detail report - start -- jzg */
		if((srTransRec.byTransType == VOID) ||
			(srTransRec.byTransType == OFFLINE_VOID))
		{
			memset(szTempBuf3, 0, sizeof(szTempBuf3));
			sprintf(szTempBuf3, "-%s", szTempBuf2);
			memset(szTempBuf2, 0, sizeof(szTempBuf2));
			strcpy(szTempBuf2, szTempBuf3);
		}
		/* BDO: Add negative sign to amount on detail report - end -- jzg */
		
		memset (szPrintBuf, 0x00, sizeof(szPrintBuf));
		strcpy(szPrintBuf, szStr);
		memset(&szPrintBuf[strlen(szPrintBuf)], 0x20, 23-strlen(szStr));
		strcat(szPrintBuf, szTempBuf2);
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1,szPrintBuf , &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inPrint(szPrintBuf);

		if(inCheckIfDCCHost() == TRUE)
		{
			memset (szPrintBuf, 0x00, sizeof(szPrintBuf));
			memset (baTemp, 0x00, sizeof(baTemp));
			memset (szTempBuf1, 0x00, sizeof(szTempBuf1));
			memset (szTempBuf2, 0x00, sizeof(szTempBuf2));
			memset (szTempBuf3, 0x00, sizeof(szTempBuf3));
			memset (szTempBuf4, 0x00, sizeof(szTempBuf4));
			memset (szStr, 0x00, sizeof(szStr));

			strcpy(szTempBuf2, srTransRec.szAuthCode);
			strcpy(szPrintBuf, szTempBuf2);
			
			wub_hex_2_str(srTransRec.szDCCLocalAmount,szTempBuf3,AMT_BCD_SIZE);
			wub_hex_2_str(srTransRec.szDCCLocalTipAmount,szTempBuf4,AMT_BCD_SIZE);
			sprintf(baTemp, "%012.0f", atof(szTempBuf3) + atof(szTempBuf4));			
			vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", baTemp, szTempBuf1);	
			sprintf(szStr,"%s%s",srTransRec.szDCCLocalSymbol,szTempBuf1);
			
			memset(&szPrintBuf[strlen(szPrintBuf)], 0x20, 23-strlen(szTempBuf2));
			strcat(szPrintBuf, szStr);
			
			inCCTOS_PrinterBufferOutput(szPrintBuf,&stgFONT_ATTRIB,1);
			vdCTOS_PrinterFline(1);
	
		}
		else
		{
			memset (szPrintBuf, 0x00, sizeof(szPrintBuf));
			strcpy(szPrintBuf, srTransRec.szAuthCode);
			memset (baTemp, 0x00, sizeof(baTemp));
			
			inCCTOS_PrinterBufferOutput(szPrintBuf,&stgFONT_ATTRIB,1);
			vdCTOS_PrinterFline(1);
		}
	}
	else
	{
		memset(szStr, 0,sizeof(szStr));
		memset(szPrintBuf, 0,sizeof(szPrintBuf));
		
		szGetTransTitle(srTransRec.byTransType, szPrintBuf);
				
	    if (srTransRec.byTransType == VOID)
		{
			if((memcmp(srTransRec.szAuthCode,"Y1",2) == 0) || (srTransRec.fOnlineSALE == TRUE))
				strcpy(szPrintBuf, "VOID");					
	    }

		memset(&szPrintBuf[strlen(szPrintBuf)], 0x20, 23-strlen(szPrintBuf));

		wub_hex_2_str(srTransRec.szInvoiceNo, szStr, INVOICE_BCD_SIZE);
		strcat(szPrintBuf,szStr);
		
		inPrint(szPrintBuf);

		memset (szPrintBuf, 0x00, sizeof(szPrintBuf));
		strcpy(szPrintBuf, srTransRec.szAuthCode);
				
		memset(szTemp, 0x00, sizeof(szTemp)); 
		wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);

		memset(szTempBuf1, 0, sizeof(szTempBuf1));
		memset(szTempBuf2, 0, sizeof(szTempBuf2));

		if(srTransRec.HDTid >= 6 && srTransRec.HDTid <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
			vdDCCModifyAmount(szTemp,szTempBuf1);
		else
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp, szTempBuf1);// patrick add code 20141216
			
	    sprintf(szTempBuf2,"%s%s",strCST.szCurSymbol, szTempBuf1);
	    
		/* BDO: Add negative sign to amount on detail report - start -- jzg */
		if((srTransRec.byTransType == VOID) ||
			(srTransRec.byTransType == OFFLINE_VOID))
		{
			memset(szTempBuf3, 0, sizeof(szTempBuf3));
			sprintf(szTempBuf3, "-%s", szTempBuf2);
			memset(szTempBuf2, 0, sizeof(szTempBuf2));
			strcpy(szTempBuf2, szTempBuf3);
		}
		/* BDO: Add negative sign to amount on detail report - end -- jzg */
		
		memset(&szPrintBuf[strlen(szPrintBuf)], 0x20, 23-strlen(szPrintBuf));
		strcat(szPrintBuf, szTempBuf2);
		inPrint(szPrintBuf);
		vdCTOS_PrinterFline(1);
	}
}

USHORT ushCTOS_GetFontInfor(void)
{
	USHORT usASCIIFontID;
	USHORT usFontSize;
	USHORT usFontStyle;

	CTOS_LanguagePrinterGetFontInfo( &usASCIIFontID, &usFontSize, &usFontStyle );   
	vdDebug_LogPrintf("usASCIIFontID[%d]usFontSize[%d]usFontStyle[%d]",usFontSize,usFontStyle );
}

USHORT ushCTOS_ReprintLastSettleReport(void)
{
	ACCUM_REC srAccumRec;
	unsigned char chkey;
	short shHostIndex;
	int inResult,inRet;
	int inTranCardType;
	int inReportType;
	int inIITNum , i;
	char szStr[d_LINE_SIZE + 1];
	BYTE baTemp[PAPER_X_SIZE * 64];

	fRePrintFlag=TRUE;
	memset(TempszTID, 0x00, sizeof(TempszTID));	
	memset(TempszMID, 0x00, sizeof(TempszMID));

	//for MP200 no need print
	if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
    	return (d_OK);
	
	if( printCheckPaper()==-1)
		return;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;
		
	//by host and merchant
	//shHostIndex = inCTOS_SelectHostSetting();
	shHostIndex=inCTOS_SelectHostSettingWithIndicator(3);
	if (shHostIndex == -1)
		return;
	strHDT.inHostIndex = shHostIndex;
	DebugAddINT("summary host Index",shHostIndex);
	inCSTRead(strHDT.inCurrencyIdx);

	if (inMultiAP_CheckMainAPStatus() == d_OK)
	{
		inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_REPRINT_LAST_SETT);
		if(d_OK != inRet)
			return inRet;
	}
	else
	{
		if (inMultiAP_CheckSubAPStatus() == d_OK)
		{
			inRet = inCTOS_MultiAPGetData();
			if(d_OK != inRet)
				return inRet;

			inRet = inCTOS_MultiAPReloadHost();
			if(d_OK != inRet)
				return inRet;
		}
	}

	//remove prompt fro selection-Merchant selection is done by inCTOS_TEMPCheckAndSelectMutipleMID
	//	  inRet = inCTOS_CheckAndSelectMutipleMID();
	//	  if(d_OK != inRet)
	//		  return inRet;
	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

	memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
	inResult = inCTOS_ReadBKAccumTotal(&srAccumRec,strHDT.inHostIndex,srTransRec.MITid);
	if(inResult == ST_ERROR)
	{
	    //vdSetErrorMessage("NO RECORD FOUND");
	    vdDisplayErrorMsgResp2("","TRANSACTION","NOT FOUND");
		vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
		return ST_ERROR;	
	}		 
	else if(inResult == RC_FILE_READ_OUT_NO_DATA)
	{
	    //vdSetErrorMessage("NO RECORD FOUND");
	    vdDisplayErrorMsgResp2("","TRANSACTION","NOT FOUND");
		return;
	}	 

	
	//save TID and MID retrived from batch		
	memcpy(TempszTID, srTransRec.szTID, strlen( srTransRec.szTID));
	memcpy(TempszMID, srTransRec.szMID, strlen( srTransRec.szMID));

    /*albert - start - 20161202 - Reprint of Detail Report for Last Settlement Report*/    
    if(strTCT.fPrintSettleDetailReport == TRUE || srAccumRec.fManualSettlement == TRUE)
        vdCTOS_PrintDetailReport(TRUE, TRUE);
	/*albert - end - 20161202 - Reprint of Detail Report for Last Settlement Report*/
	
    strcpy(srTransRec.szTID, srAccumRec.szTID);
    strcpy(srTransRec.szMID, srAccumRec.szMID);
    memcpy(srTransRec.szYear, srAccumRec.szYear, DATE_BCD_SIZE);
    memcpy(srTransRec.szDate, srAccumRec.szDate, DATE_BCD_SIZE);
    memcpy(srTransRec.szTime, srAccumRec.szTime, TIME_BCD_SIZE);
    //memcpy(srTransRec.szBatchNo, srAccumRec.szBatchNo, BATCH_NO_BCD_SIZE);

	vdSetPrintThreadStatus(1); /*BDO: Display printing image during report -- sidumili*/
	
    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
    
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	ushCTOS_PrintHeader(0);	
    
    //vdPrintTitleCenter("LAST SETTLE");
    
	//CTOS_PrinterFline(d_LINE_DOT * 1);
	//vdCTOS_PrinterFline(1);

	//vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

	//vdPrintCenter("DUPLICATE");

	//vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    
	printTIDMID(TRUE);
    
	//printDateTime();
    printLastSettleDateTime();
    
	memcpy(srTransRec.szBatchNo, srAccumRec.szBatchNo, BATCH_NO_BCD_SIZE);
	printBatchNO();

	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	
/* BDO PHASE2: [Print Settlement Closed for last settle receipt] -- sidumili*/	
#if 0
	if (srTransRec.byTransType == SETTLE)
		vdPrintCenter("SETTLEMENT CLOSED");
	else
		vdPrintCenter("SUMMARY REPORT");
#else
    if(srAccumRec.fManualSettlement == TRUE)
        vdPrintCenter("SUMMARY REPORT");
    else
    {
		vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		vdPrintCenter("SETTLEMENT CLOSED");		
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 0, 0);
		vdPrintCenter("    *** TRANSACTION TOTALS BY ISSUER ***");
    }
#endif
/* BDO PHASE2: [Print Settlement Closed for last settle receipt] -- sidumili*/	
	
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);


    //CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);
	for(inTranCardType = 0; inTranCardType < 1 ;inTranCardType ++)
	{
		if(srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMGIFTCARD_HDT_INDEX)
			inTranCardType = 1;
		
		inReportType = PRINT_CARD_TOTAL;
		
		if(inReportType == PRINT_CARD_TOTAL)
		{
			//00147 - No issuer name prints in summary report, settlement report and manual settlement report for BDO Loyalty
			//for(i= 0; i <30; i ++ )
			for(i= 0; i <37; i ++ )
			{
				vdDebug_LogPrintf("--Count[%d]", i);
				if((srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount == 0))
					continue;
				
				vdDebug_LogPrintf("Count[%d]", i); 
				inIITRead(i);
				memset(szStr, ' ', d_LINE_SIZE);
				memset (baTemp, 0x00, sizeof(baTemp));
				//strcpy(szStr,strIIT.szIssuerLabel);
				sprintf(szStr,"ISSUER: %s",strIIT.szIssuerLabel);
				//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
				//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

				if (inCheckIfSMCardTransRec() == TRUE){
					vdCTOS_PrintAccumeByHostAndCard (inReportType,
					/*issue-00043*/
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount,   
					(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) ,									
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 
					//issue-00296-add void cash advance 				
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
					(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 								
					//srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount), 
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount));	


				}else{
				
					if(inCheckIfDCCHost() == TRUE)
		 				vdCTOS_DCCPrintAccumeByHostAndCard (inReportType, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i]);
					else
						vdCTOS_PrintAccumeByHostAndCard (inReportType, 
						/*issue-00043*/
													srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount  + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount,   
													(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
													
													srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 

													//issue-00296-add void cash advance 				
													srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
													(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 
													
													//srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount), 

													srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),

													srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),

													srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount)

													);	
				}
			}
			//after print issuer total, then print host toal
			{
				if (inCheckIfSMCardTransRec() == TRUE){

				}
				else
				{
					memset(szStr, ' ', d_LINE_SIZE);
					memset (baTemp, 0x00, sizeof(baTemp));
					strcpy(szStr,"GRAND TOTALS");
					inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
					
					if(inCheckIfDCCHost() == TRUE)
						vdCTOS_DCCPrintAccumeByHostAndCard (PRINT_HOST_TOTAL, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal);
					else
					{
                        vdCTOS_PrintAccumeByHostAndCard (inReportType, 
                        /*issue-00043*/
                        (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount) +
                        srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, 	
                        (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
                        
                        srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
                        //issue-00296-add void cash advance 									
                        srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
                        (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
                        
                        //srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount), 
                        
                        srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
                        
                        srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
                        
                        srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount)
                        
                        );	
					}
				}
			}
		}
		else
		{
		
			memset(szStr, ' ', d_LINE_SIZE);
			memset (baTemp, 0x00, sizeof(baTemp));
			strcpy(szStr,srTransRec.szHostLabel);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			vdCTOS_PrintAccumeByHostAndCard (inReportType, 
				/*issue-00043*/				
												srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount	+ srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount,   
												(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
												
												srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
												//issue-00296-add void cash advance 									
												srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
												(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
												
												//srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, 
												//(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount), 

												srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),

												srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),

			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount)

												);		
		}
	}
	
	//print space one line
	///CTOS_PrinterFline(d_LINE_DOT * 2);		
	//CTOS_PrinterFline(d_LINE_DOT * 2);
	//CTOS_PrinterFline(d_LINE_DOT * 2);
	vdCTOS_PrinterFline(6);
	vdCTOSS_PrinterEnd();

	if(srAccumRec.fManualSettlement == TRUE)
         vdCTOS_PrintManualPosting();

	vdSetPrintThreadStatus(0); /*BDO: Display printing image during report -- sidumili*/

	
	
	return d_OK;	
}

void vdCTOSS_PrinterBMPPic(unsigned int usX,unsigned int y, const char *path)
{
	char szBmpfile[50+1]={0};
	
	memset(szBmpfile, 0x00, sizeof(szBmpfile));
	//sprintf(szBmpfile,"%s%s", LOCAL_PATH, path);
	sprintf(szBmpfile,"%s", path);
	
	//CTOS_PrinterBMPPic(usX, szBmpfile);
	//vdCTOSS_PrinterBMPPicEx(0, 0, szBmpfile);

    if(strTCT.byERMMode)
        CTOS_PrinterBMPPic(usX, szBmpfile);
    else		
        vdCTOSS_PrinterBMPPicEx(0, 0, szBmpfile);
	return ;
}


//gcitra
extern char szField63[999];

USHORT ushCTOS_PrintCashLoyaltyBody(void)
{	
    char szStr[d_LINE_SIZE + 1];
    char szTemp[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    char szTemp3[d_LINE_SIZE + 1];
    char szTemp4[d_LINE_SIZE + 1];
    char szTemp5[d_LINE_SIZE + 1];
    char szFormatPAN[strlen(srTransRec.szPAN) + 7];//to account for space as in PAN format and to include additional PAN no. 7 has been added -Meena 08/01/2012
    int inFmtPANSize;
    BYTE baTemp[PAPER_X_SIZE * 64];
    USHORT result;
    int num,i,inResult;
    unsigned char tucPrint [24*4+1];	
    BYTE   EMVtagVal[64];
    USHORT EMVtagLen; 
    short spacestring;
    BYTE   key;


    	char szTranType[d_LINE_SIZE + 1];


	char temp[30];
	char szRewardText[1000+1];
	char szRewardSize[4+1];
	int inRewardSize;
	char szPrintBuff[21+1];
	int inOffset;
	int inSizeofField63;
	
	char szCI[2+1];
	
	long lnInvNum;
	char temp2[21+1];


	ushCTOS_PrintHeader(d_FIRST_PAGE);

    	memset(szTemp1, ' ', d_LINE_SIZE);
    	sprintf(szTemp1,"%s",srTransRec.szHostLabel);
    	vdPrintCenter(szTemp1);
		
	printDateTime();

       printTIDMID(FALSE); 
		
	//printBatchInvoiceNO();
	memset(szTemp1,0x00,sizeof(szTemp1));
	wub_hex_2_str(srTransRec.szBatchNo,szTemp1,3);
    	sprintf(szStr, "INV#: %s", szTemp1);
    	memset (baTemp, 0x00, sizeof(baTemp));		

    	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
   	//result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);


	//Reference num
	memset(szStr, ' ', d_LINE_SIZE);
	memset (baTemp, 0x00, sizeof(baTemp));					
	memset(szStr, ' ', d_LINE_SIZE);
	sprintf(szStr, "RREF NUM  : %s", srTransRec.szRRN);
	memset (baTemp, 0x00, sizeof(baTemp));		
	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);


	sprintf(&szRewardSize[0], "%x ", szField63[0]);
	sprintf(&szRewardSize[1], "%02x ", szField63[1]);

	inSizeofField63=atoi(szRewardSize) +2;
	inRewardSize = atoi(szRewardSize) -2;

	inOffset = 0;

	memset(szRewardText, 0x00, sizeof(szRewardText));

	memcpy(szRewardText, (char*) &szField63[4], inRewardSize);

	memset(szCI, 0x00, sizeof(szCI));

	strncpy(szCI, (char*) &szField63[2], 2);

       memset(szTranType,0x00, sizeof(szTranType));
	if ((strcmp(szCI, "PZ") == 0) || (strcmp(szCI, "CI") == 0))
		strcpy(szTranType, "CUSTOMER REWARD");
	else if ((strcmp(szCI, "RN") == 0) || (strcmp(szCI, "CR") == 0))
		strcpy(szTranType, "CASHIER REWARD");
			
	//CTOS_PrinterFline(d_LINE_DOT * 1); 
	vdCTOS_PrinterFline(1);
  	vdPrintTitleCenter(szTranType);    

       vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
        
	//CTOS_PrinterFline(d_LINE_DOT * 1); 
	vdCTOS_PrinterFline(1);

	while(1){
		memset(szPrintBuff, 0x00, sizeof(szPrintBuff));

		for(i=0 ; (i < 21) && (inOffset < inRewardSize); i++){
			szPrintBuff[i] = szRewardText[inOffset];
			inOffset++;
		}
	

		memset (baTemp, 0x00, sizeof(baTemp));
		vdPrintCenter(szPrintBuff);

		if (inOffset >= inRewardSize)
			break;
	}

	//CTOS_PrinterFline(d_LINE_DOT * 1); 
	vdCTOS_PrinterFline(1);
	vdPrintCenter("THANK YOU");

        vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);

	//CTOS_PrinterFline(d_LINE_DOT * 6);
	vdCTOS_PrinterFline(6);

/*second reward*/


	if ((szField63[inRewardSize+4] != (char) 0) || (szField63[inRewardSize+5] != (char) 0)) {


   		CTOS_LCDTClearDisplay();  
		CTOS_LCDTPrintXY(1,4,"Press any key to");
		CTOS_LCDTPrintXY(1,5,"Print");
		sprintf(temp2,"%s",szTranType);
		CTOS_LCDTPrintXY(1,6, temp2);


		WaitKey(60);

      		memset(szTranType, 0x00, sizeof(szTranType));
		if ((strcmp(szCI, "PZ") == 0) || (strcmp(szCI, "CI") == 0))
			strcpy(szTranType, "CUSTOMER REWARD");
		else if ((strcmp(szCI, "RN") == 0) || (strcmp(szCI, "CR") == 0))
			strcpy(szTranType, "CASHIER REWARD");

		ushCTOS_PrintHeader(d_FIRST_PAGE);

    		memset(szTemp1, ' ', d_LINE_SIZE);
    		sprintf(szTemp1,"%s",srTransRec.szHostLabel);
    		vdPrintCenter(szTemp1);
		
		printDateTime();

       	printTIDMID(FALSE); 
		
		//printBatchInvoiceNO();
		memset(szTemp1,0x00,sizeof(szTemp1));
		wub_hex_2_str(srTransRec.szBatchNo,szTemp1,3);
    		sprintf(szStr, "INV#: %s", szTemp1);
    		memset (baTemp, 0x00, sizeof(baTemp));		

    		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
   		//result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);


		//Reference num
		memset(szStr, ' ', d_LINE_SIZE);
		memset (baTemp, 0x00, sizeof(baTemp));					
		memset(szStr, ' ', d_LINE_SIZE);
		sprintf(szStr, "RREF NUM  : %s", srTransRec.szRRN);
		memset (baTemp, 0x00, sizeof(baTemp));		
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);


		sprintf(&szRewardSize[0], "%x ", szField63[0]);
		sprintf(&szRewardSize[1], "%02x ", szField63[1]);

		inSizeofField63=atoi(szRewardSize) +2;
		inRewardSize = atoi(szRewardSize) -2;

		inOffset = 0;

		memset(szRewardText, 0x00, sizeof(szRewardText));

		memcpy(szRewardText, (char*) &szField63[4], inRewardSize);

		memset(szCI, 0x00, sizeof(szCI));

		strncpy(szCI, (char*) &szField63[2], 2);

			
		//CTOS_PrinterFline(d_LINE_DOT * 1); 
		vdCTOS_PrinterFline(1);
  		vdPrintTitleCenter(szTranType);    

       	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
        
		//CTOS_PrinterFline(d_LINE_DOT * 1); 
		vdCTOS_PrinterFline(1);


		memset(szRewardSize, 0x00, sizeof(szRewardSize));

		sprintf(&szRewardSize[0], "%x ",szField63[inRewardSize+4]);
		sprintf(&szRewardSize[1], "%02x ", szField63[inRewardSize+5]);

		inOffset = inRewardSize+8;

		inRewardSize = atoi(szRewardSize) - 2;


		memset(szRewardText, 0x00, sizeof(szRewardText));


		memcpy(szRewardText, (char*) &szField63[inOffset], inRewardSize);


       vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
        
	//CTOS_PrinterFline(d_LINE_DOT * 1); 
	vdCTOS_PrinterFline(1);


	inOffset = 0;

	while(1){
		memset(szPrintBuff, 0x00, sizeof(szPrintBuff));

		for(i=0 ; (i < 21) && (inOffset < inRewardSize); i++){
			szPrintBuff[i] = szRewardText[inOffset];
			inOffset++;
		}
	

		memset (baTemp, 0x00, sizeof(baTemp));
		vdPrintCenter(szPrintBuff);

		if (inOffset >= inRewardSize)
			break;
	}

	//CTOS_PrinterFline(d_LINE_DOT * 1); 
	vdCTOS_PrinterFline(1);
	vdPrintCenter("THANK YOU");

	vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);

	//CTOS_PrinterFline(d_LINE_DOT * 6); 
	vdCTOS_PrinterFline(6);


		}
		
	return d_OK;	
	
}

//int inPrintISOPacket(BOOL fSendPacket, unsigned char *pucMessage, int inLen)
int inPrintISOPacket(unsigned char *pucTitle,unsigned char *pucMessage, int inLen)
{
    char ucLineBuffer[d_LINE_SIZE+4];
    unsigned char *pucBuff;
    int inBuffPtr = 0;
    BYTE baTemp[PAPER_X_SIZE * 64];
    char szStr[d_LINE_SIZE + 4];
	

    if (inLen <= 0)
        return(ST_SUCCESS);

	vdCTOSS_PrinterStart(100);
    CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
	
	CTOS_PrinterSetWorkTime(50000,1000);
    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_16x16,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 0, 0);
    
    memset(szStr, 0x00, sizeof(szStr));
	memset(baTemp, 0x00, sizeof(baTemp));
    sprintf(szStr,"[%s] [%d] \n", pucTitle, inLen);
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

		
    //CTOS_PrinterFline(d_LINE_DOT); 
	  vdCTOS_PrinterFline(1);
    
    
    pucBuff = pucMessage + inLen;
    while (pucBuff > pucMessage)
    {
    	memset(ucLineBuffer,0x00, sizeof(ucLineBuffer));
	    for (inBuffPtr = 0; (inBuffPtr < 44) && (pucBuff > pucMessage); inBuffPtr += 3)
	    {
		    sprintf(&ucLineBuffer[inBuffPtr], "%02X ", *pucMessage);
		    pucMessage++;
	    }
	    ucLineBuffer[44] = '\n';
	    memset (baTemp, 0x00, sizeof(baTemp));		
	    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, ucLineBuffer, &stgFONT_ATTRIB);
	    //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(ucLineBuffer,&stgFONT_ATTRIB,1);
    
    } 
   // CTOS_PrinterFline(d_LINE_DOT * 2); 
	    vdCTOS_PrinterFline(2);
    
    vdCTOSS_PrinterEnd();
    return (ST_SUCCESS);
}


/*albert - start - August2014 - manual settlement*/
void vdCTOS_PrintManualPosting(void)
{
	vdCTOSS_PrinterStart(100);

     vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
     vdPrintCenter("FOR MANUAL POSTING");
     vdPrintCenter("PLEASE SUBMIT TO BDO");
     vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, NORMAL_SIZE, 0, 0);
    // CTOS_PrinterFline(d_LINE_DOT * 2);
	 vdCTOS_PrinterFline(2);
	 
	 //print space one line
	 //CTOS_PrinterFline(d_LINE_DOT * 2); 	 
	 //CTOS_PrinterFline(d_LINE_DOT * 2);
	 //CTOS_PrinterFline(d_LINE_DOT * 2);
	 vdCTOS_PrinterFline(6);
	 vdCTOSS_PrinterEnd();

}
/*albert - end - August2014 - manual settlement*/


//sidumili: [HOST INFO REPORT]
void vdCTOS_HostInfo(void){
	int shHostIndex = 1, inNumOfMerchant=0;
	int inResult,inRet;
	unsigned char szCRC[8+1];
	char ucLineBuffer[d_LINE_SIZE];
	BYTE baTemp[PAPER_X_SIZE * 64];
	int inLoop = 0;
	char szBillerName[1024] = {0};
	char szBillerCode[1024] = {0};
	char szStr[d_LINE_SIZE + 1];
	BYTE szTempBuf[12+1];
	BYTE szBuf[50];

	int inNumOfHost;
	int inNum;
	int inHostEnb;

	BOOL fuseBDOMidForWechat = (BOOL)get_env_int("BDOMIDWECHAT");
	BOOL fuseBDOMidForAlipay = (BOOL)get_env_int("BDOMIDALIPAY");


    fERMTransaction=0;
		
	vdDebug_LogPrintf("-->>vdCTOS_HostInfo[START]");

	vduiLightOn();								

//	if( printCheckPaper()==-1)
//    	return;
		
	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

	if( printCheckPaper()==-1)
    	return;
		
	vdDebug_LogPrintf("[Merchant ID %d", srTransRec.MITid);
	

	inNumOfHost = inHDTNumRecord();
	vdDebug_LogPrintf("inNumOfHost=[%d]-----",inNumOfHost);

	inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	inMMTReadRecord(1, srTransRec.MITid);/*temporary - need to reload MMT record for receipt header*/

	vdSetPrintThreadStatus(1); /*BDO:Display printing image during report -- sidumili*/

	vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  
	ushCTOS_PrintHeader(0);

	//CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);

	//vdPrintTitleCenter("HOST INFO REPORT");
	//CTOS_PrinterFline(d_LINE_DOT * 1);
	//vdCTOS_PrinterFline(1);

	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
    vdPrintCenter("HOST INFO REPORT");
	vdCTOS_PrinterFline(1);
	
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	printDateTime();
	
	inDatabase_TerminalOpenDatabaseEx(DB_TERMINAL);
	
	inHostEnb=1;
	for(inNum =1 ;inNum <= inNumOfHost; inNum++)
	{

		//if(inHDTRead(inNum) == d_OK)
		//if(inHDTReadinSequence(inNum) == d_OK)
		if(inHDTReadinSequenceEx(inNum) == d_OK)
		{	
			//inCPTRead(inNum);
			
			vdDebug_LogPrintf("[HOST %d MID %d", strHDT.inHostIndex, srTransRec.MITid);

			
			//inMMTReadRecord(strHDT.inHostIndex,srTransRec.MITid);
			if(inMMTReadRecordEx(strHDT.inHostIndex,srTransRec.MITid) != d_OK)
				continue;
			
			vdDebug_LogPrintf("[read MMT fail]-Mitid[%d]strHDT.inHostIndex[%d]inResult[%d]", inLoop,strHDT.inHostIndex,inResult);

			vdDebug_LogPrintf("[inNumOfMerchant]-[%d]strHDT.inHostIndex[%d]", inNumOfMerchant,strHDT.inHostIndex);
			
			//inCCTOS_PrinterBufferOutput("__________________________________________",&stgFONT_ATTRIB,1);
			inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "  HOST NAME: %s", (char *)strHDT.szHostLabel);
			inPrint(szStr);

			memset(szStr, 0x00, sizeof(szStr));
			sprintf(szStr, "TERMINAL ID: %s", strMMT[0].szTID); 											 
			inPrint(szStr);


            //version16
			memset(szStr, 0x00, sizeof(szStr));
            if (strHDT.inHostIndex == WECHAT_HOST_INDEX){
				if (fuseBDOMidForWechat == 1){
					inBDOWechatRead(1);
					sprintf(szStr, "MERCHANT ID: %s", strDigitalWallet.szBDOMID); 
				}else
					sprintf(szStr, "MERCHANT ID: %s", strMMT[0].szMID); 
			}else  if (strHDT.inHostIndex == ALIPAY_HOST_INDEX){
				if (fuseBDOMidForAlipay == 1){
					inBDOAlipayRead(1);
					sprintf(szStr, "MERCHANT ID: %s", strDigitalWallet.szBDOMID); 
				}else
					sprintf(szStr, "MERCHANT ID: %s", strMMT[0].szMID); 
			}else{
				
				sprintf(szStr, "MERCHANT ID: %s", strMMT[0].szMID); 											 
			}

			inPrint(szStr);
#if 0			
			memset(szTempBuf, 0x00, sizeof(szTempBuf));
			wub_hex_2_str(strHDT.szTPDU,szTempBuf,5);
			sprintf(szStr, "  TPDU     : %s", szTempBuf);
			inPrint(szStr);
#endif
			memset(szTempBuf, 0x00, sizeof(szTempBuf));
			wub_hex_2_str(strHDT.szNII,szTempBuf,2);
			sprintf(szStr, "        NII: %s", szTempBuf);
			inPrint(szStr);

			if (strTCT.fSingleComms != TRUE)
			{	
				//inCPTRead(strHDT.inHostIndex);
				inCPTReadEx(strHDT.inHostIndex);
				
				memset(szStr, 0x00, d_LINE_SIZE);
				sprintf(szStr, "    PRI NUM: %s", (char *)strCPT.szPriTxnPhoneNumber);
				inPrint(szStr);

				memset(szStr, 0x00, d_LINE_SIZE);
				sprintf(szStr, "    SEC NUM: %s", (char *)strCPT.szSecTxnPhoneNumber);
				inPrint(szStr);
#if 0

				memset(szStr, 0x00, d_LINE_SIZE);
				sprintf(szStr, "  PRI IP   : %s", (char *)strCPT.szPriTxnHostIP);
				inPrint(szStr);

				memset(szStr, 0x00, d_LINE_SIZE);
				sprintf(szStr, "  PRI PORT : %04d", strCPT.inPriTxnHostPortNum);
				inPrint(szStr);

				memset(szStr, 0x00, d_LINE_SIZE);
				sprintf(szStr, "  SEC IP   : %s", (char *)strCPT.szSecTxnHostIP);
				inPrint(szStr);

				memset(szStr, 0x00, d_LINE_SIZE);
				sprintf(szStr, "  SEC PORT : %04d", strCPT.inSecTxnHostPortNum);
				inPrint(szStr);
#endif

			}

			inPrint(" ");

			//inMMTReadNumofRecords(strHDT.inHostIndex,&inNumOfMerchant);
#if 0
			vdDebug_LogPrintf("[HOST %d MID %d", strHDT.inHostIndex, srTransRec.MITid);

			
			inMMTReadRecord(strHDT.inHostIndex,srTransRec.MITid);
			
			vdDebug_LogPrintf("[read MMT fail]-Mitid[%d]strHDT.inHostIndex[%d]inResult[%d]", inLoop,strHDT.inHostIndex,inResult);

			vdDebug_LogPrintf("[inNumOfMerchant]-[%d]strHDT.inHostIndex[%d]", inNumOfMerchant,strHDT.inHostIndex);

			memset(szStr, 0x00, sizeof(szStr));
			#ifdef SINGE_HEADER_FOOTER_TEXT
			inNMTReadRecord(srTransRec.MITid);
			sprintf(szStr, "  MERCHANT : %s", strSingleNMT.szMerchName);
			#else
			sprintf(szStr, "  MERCHANT : %s", strMMT[0].szMerchantName); 
			#endif
			inPrint(szStr);

			memset(szStr, 0x00, sizeof(szStr));
			sprintf(szStr, "  TID      : %s", strMMT[0].szTID); 											 
			inPrint(szStr);

			memset(szStr, 0x00, sizeof(szStr));
			sprintf(szStr, "  MID      : %s", strMMT[0].szMID); 											 
			inPrint(szStr);

			memset(szStr, 0x00, sizeof(szStr));
			memset(szBuf, 0x00, sizeof(szBuf));
			wub_hex_2_str(strMMT[0].szBatchNo, szBuf, 3);
			sprintf(szStr, "  BATCH NO : %s", szBuf); 											 
			inPrint(szStr);
			vdCTOS_PrinterFline(1);
#endif
			if( (inNum%10) == 0)
			{
				vdCTOSS_PrinterEnd();
				vdCTOSS_PrinterStart(100);
				CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel); 
			}
					
		}		

	 }

			
	if (strTCT.fSingleComms == TRUE)
	{	
		//inCPTRead(1);
		inCPTReadEx(1);
		
		inCCTOS_PrinterBufferOutput("__________________________________________",&stgFONT_ATTRIB,fERMTransaction);
		inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);
		
		memset(szStr, 0x00, d_LINE_SIZE);
		//sprintf(szStr, "PRI TEL NUM : %s", (char *)strCPT.szPriTxnPhoneNumber);
		sprintf(szStr, "    PRI NUM: %s", (char *)strCPT.szPriTxnPhoneNumber);
		inPrint(szStr);
	
		memset(szStr, 0x00, d_LINE_SIZE);
		//sprintf(szStr, "SEC TEL NUM : %s", (char *)strCPT.szSecTxnPhoneNumber);
		sprintf(szStr, "    SEC NUM: %s", (char *)strCPT.szSecTxnPhoneNumber);
		inPrint(szStr);
#if 0	
		memset(szStr, 0x00, d_LINE_SIZE);
		//sprintf(szStr, "PRI IP      : %s", (char *)strCPT.szPriTxnHostIP);
		sprintf(szStr, "  PRI IP   : %s", (char *)strCPT.szPriTxnHostIP);
		inPrint(szStr);
	
		memset(szStr, 0x00, d_LINE_SIZE);
		//sprintf(szStr, "PRI IP PORT : %04d", strCPT.inPriTxnHostPortNum);
		sprintf(szStr, "  PRI PORT : %04d", strCPT.inPriTxnHostPortNum);
		inPrint(szStr);
	
		memset(szStr, 0x00, d_LINE_SIZE);
		//sprintf(szStr, "SEC IP      : %s", (char *)strCPT.szSecTxnHostIP);
		sprintf(szStr, "  SEC IP   : %s", (char *)strCPT.szSecTxnHostIP);
		inPrint(szStr);
	
		memset(szStr, 0x00, d_LINE_SIZE);
		//sprintf(szStr, "SEC IP PORT : %04d", strCPT.inSecTxnHostPortNum);
		sprintf(szStr, "  SEC PORT : %04d", strCPT.inSecTxnHostPortNum);
		inPrint(szStr);
#endif

		//inPrint(" ");
		
		//vdCTOS_PrinterFline(1);
	}
	inDatabase_TerminalCloseDatabase();
	//CTOS_PrinterFline(d_LINE_DOT * 5);
	vdCTOS_PrinterFline(6);
	
	vdCTOSS_PrinterEnd();

	vdSetPrintThreadStatus(0); /*BDO:Display printing image during report -- sidumili*/
	
	vdDebug_LogPrintf("-->>vdCTOS_HostInfo[END]");

}
//sidumili: [HOST INFO REPORT]

//sidumili: [HOST INFO REPORT]

int inPrint(unsigned char *strPrint) 
{
	char szStr[42] = {0}; 
	BYTE baTemp[PAPER_X_SIZE * 64] = {0};
    int inSpacing=3;
	
    if(stgFONT_ATTRIB.X_Zoom == DOUBLE_SIZE)
         inSpacing=4;
	
	memset(szStr, 0x00, sizeof(szStr));
	memcpy(szStr, strPrint, strlen(strPrint));

	//memset (baTemp, 0x00, sizeof(baTemp));
	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	//return CTOS_PrinterBufferOutput((BYTE *)baTemp, inSpacing);  

	//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
    inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
	return d_OK;
}

/*albert - start - Aug2014 - compute crc*/
#if 1
void vdCTOS_PrintCRC(void)
{
   int shHostIndex = 1, inNumOfMerchant=0;
   int inResult,inRet;
   unsigned char szCRC[8+1];
   char ucLineBuffer[d_LINE_SIZE];
   BYTE baTemp[PAPER_X_SIZE * 64];
   int i;
   vduiLightOn();  
   char szStr[d_LINE_SIZE + 1];
   BYTE szTemp1[30] = {0};
   int x, inAIDNumRec;
   BYTE   EMVtagVal[64+1];
   USHORT EMVtagLen; 
   char inStr, szTemp[d_LINE_SIZE + 1];
   char szCRCList[5][15]={"CREDITCRC","DEBITCRC","CUPCRC","INSTCRC", "QPAYCRC"};  

   //version16
   BYTE szMAC[30];
   //version16
   
   //shHostIndex = inCTOS_SelectHostSetting();
   //if (shHostIndex == -1)
   //    return;
   
   //inResult = inCTOS_CheckAndSelectMutipleMID();
   //if(d_OK != inResult)
   //	return;

   	if( printCheckPaper()==-1)
    	return;

   /* HC values for 06Aug2019 Release*/
   //put_env_char("CREDITCRC","3a09326e");
   put_env_char("DEBITCRC","20227b73");
   put_env_char("CUPCRC","05397569");
   put_env_char("INSTCRC","02705861");
   put_env_char("QPAYCRC","3252416f");

      
   vdSetPrintThreadStatus(1); /*BDO:Display printing image during report -- sidumili*/
   
   inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
   vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	   
   vdCTOSS_PrinterStart(100);
   CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
   
   fRePrintFlag = FALSE;
   
   ushCTOS_PrintHeader(0);
   //CTOS_PrinterFline(d_LINE_DOT);
	vdCTOS_PrinterFline(1);
   
   
   vdPrintCenter("APPLICATION CRC");

  
   printDateTime();
   //version16
   inMMTReadRecord(1, 1);/*need to reload MMT record for header*/
   printTIDMID(TRUE);

   
   //version16
	//CTOS_PrinterFline(d_LINE_DOT * 2); 
   vdCTOS_PrinterFline(2);
   
   
   vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
   
   for(i=0;i<5;i++)
   {
      inCRCRead(i+1);
      memset(szCRC, 0, sizeof(szCRC));
      //vdComputeCRC(strCRC.ulSize, szCRC);
      //strcpy(CRC, MOLMD5File("APPFILENAME"));//Please take note, it is application file name, not application name.
      //inRet = get_env_char(szCRCList[i],szCRC);

      inRet =inCTOSS_GetEnvDB(szCRCList[i], szCRC);
      vdDebug_LogPrintf("inCTOSS_GetEnvDB[%d] :: szCRCList[%s] :: szCRC[%s]",inRet,szCRCList[i],szCRC);

      memset(ucLineBuffer, 0, sizeof(ucLineBuffer));
	  sprintf(ucLineBuffer, "%16s:  %s", strCRC.szAppname,szCRC);
	  
      ucLineBuffer[32] = '\n';
      memset (baTemp, 0x00, sizeof(baTemp));		
      //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, ucLineBuffer, &stgFONT_ATTRIB);
      //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
      inCCTOS_PrinterBufferOutput(ucLineBuffer,&stgFONT_ATTRIB,1);
   }	
   
   //CTOS_PrinterFline(d_LINE_DOT * 2); 
   vdCTOS_PrinterFline(2);
	 
      /*ROOTFS VERSION*/
      memset(szStr, 0x00, sizeof(szStr));
      memset(szTemp1, 0x00, sizeof(szTemp1));
      vdCTOS_GetROOTFS(szTemp1);
      sprintf(szStr, "ROOTFS : %s", szTemp1);
      inPrint(szStr);
      /*ROOTFS VERSION*/
      
      /* SERIAL NUMBER */
      memset(szStr, 0x00, sizeof(szStr));
      memset(szTemp1, 0x00, sizeof(szTemp1));
      vdCTOS_GetFactorySN(szTemp1);
      //CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szTemp1);


      
      /*Remove non numeric value*/
      for (i=0; i<strlen(szTemp1); i++)
      {
         if (szTemp1[i] < 0x30 || szTemp1[i] > 0x39)
         {
            szTemp1[i] = 0;
            break;
         }
      }

	szTemp1[15] = '\0';
	  
      vdCTOS_Pad_String(szTemp1, 15, IS_ZERO, POSITION_LEFT);

	  vdDebug_LogPrintf("SERIAL NUMBER --- [%s]", szTemp1);
      sprintf(szStr, "SERIAL NUMBER : %s", szTemp1);
      inPrint(szStr);
      /* SERIAL NUMBER */

	  //version16
	  inMMTReadRecord(1,1);
	  memset(szStr, 0x00, sizeof(szStr));
      sprintf(szStr, "TID: 00000000%s",srTransRec.szTID);	
      inPrint(szStr);  

	  memset(szStr, 0x00, sizeof(szStr));
      sprintf(szStr, "MID: %s",srTransRec.szMID);	
      inPrint(szStr);   


	  memset(szMAC, 0x00, sizeof(szMAC));
   	  inEthernet_GetTerminalMac(szMAC);
      sprintf(szStr, "MAC Address: %s",szMAC);	
      inPrint(szStr);   

   	  //version16

	  
      //CTOS_PrinterFline(d_LINE_DOT * 2);  
      	vdCTOS_PrinterFline(2);
      
      /* AID */
      inAIDNumRec = inAIDNumRecord();
      
      for (x = 1; x <= inAIDNumRec; x++ )
      {
         inAIDRead(x);

		 if (strAIDT.fAIDEnable != TRUE)
		 	continue;
		 
         int inEMVType = strAIDT.EMVid;
         inEMVRead(inEMVType);
         
         if (inStr != inEMVType)
         {
            //CTOS_PrinterFline(d_LINE_DOT * 1); 
            vdCTOS_PrinterFline(1);
            inStr = inEMVType;
            memset(ucLineBuffer, 0, sizeof(ucLineBuffer));
            sprintf(ucLineBuffer, "%s AID", strEMVT.szCardScheme);
            ucLineBuffer[32] = '\n';
            memset (baTemp, 0x00, sizeof(baTemp));		
            //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, ucLineBuffer, &stgFONT_ATTRIB);
            //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
						inCCTOS_PrinterBufferOutput(ucLineBuffer,&stgFONT_ATTRIB,1);
         }
         
         memset(szStr, ' ', d_LINE_SIZE);
         EMVtagLen = strAIDT.inAIDLen;
         memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
         memcpy(EMVtagVal, strAIDT.pbAID, EMVtagLen);
         memset(szTemp, ' ', d_LINE_SIZE);
         wub_hex_2_str(EMVtagVal, szTemp, EMVtagLen);
         sprintf(szStr, "%s",szTemp);	
         inPrint(szStr);   
      }
      /*AID*/


      //CTOS_PrinterFline(d_LINE_DOT * 2);  
      //CTOS_PrinterFline(d_LINE_DOT * 2);
      //CTOS_PrinterFline(d_LINE_DOT * 2);
     vdCTOS_PrinterFline(6);
	vdCTOSS_PrinterEnd();
			
   vdSetPrintThreadStatus(0); /*BDO:Display printing image during report -- sidumili*/
}
/*albert - end - Aug2014 - compute crc*/

#endif

void vdCTOS_PrintRS232Report(void)
{
   BYTE szBaudrate[6+1];
	 char szBaudrateRpt[40+1]={0};
	 int fBaudRate;

	 vduiLightOn();  

   if(strTCT.fSMMode != 1)
   {     
			vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");    
	    return;
   } 

   if(printCheckPaper()==-1)
    	return -1;
   
   vdPrintReportDisplayBMP();
   
   inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
   vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	 vdCTOSS_PrinterStart(100);
   CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
   
   fRePrintFlag = FALSE;
   
   ushCTOS_PrintHeader(0);
   //CTOS_PrinterFline(d_LINE_DOT);
   vdCTOS_PrinterFline(1);

	 printDateTime();

	 //CTOS_PrinterFline(d_LINE_DOT * 1); 
   vdCTOS_PrinterFline(1);

	 vdPrintCenter("RS232 REPORT");
   
   //CTOS_PrinterFline(d_LINE_DOT * 1);  
   vdCTOS_PrinterFline(1);

   vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	 
   memset(szBaudrate," ",sizeof(szBaudrate));
   switch (strTCT.fECRBaudRate)
    {
       case 1:
       strcpy (szBaudrate, "9600");
       break;
       case 2:
       strcpy (szBaudrate, "19200");
       break;
       case 3:
       strcpy (szBaudrate, "115200");
       break;
       default:
       strcpy (szBaudrate, "9600");
			 break;
    
    }

   inPrint("DEVICE          :  ECR");
	 sprintf(szBaudrateRpt, "BAUDRATE        :  %s", szBaudrate);
	 inPrint(szBaudrateRpt);
	 inPrint("FORMAT          :  A8N1");
	 inPrint("MODE            :  CHARACTER");
   
   //CTOS_PrinterFline(d_LINE_DOT * 2); 
   //CTOS_PrinterFline(d_LINE_DOT * 2); 
   //CTOS_PrinterFline(d_LINE_DOT * 2); 
	 vdCTOS_PrinterFline(6);
	 vdCTOSS_PrinterEnd();
   
   vdSetPrintThreadStatus(0); /*BDO:Display printing image during report -- sidumili*/
}



int inPrintLeftRight(unsigned char *strLeft, unsigned char *strRight, int inMode) 
{
	char szStr[48+1]; 
    int inLength=0, inSize=0;
    BYTE baTemp[PAPER_X_SIZE * 64];
	int inSpacing=3;
	
    if(stgFONT_ATTRIB.X_Zoom == DOUBLE_SIZE)
         inSpacing=4;

	inLength=inMode;
	
	memset(szStr, 0x20, sizeof(szStr));
	inSize=strlen(strRight);
    memcpy(&szStr[inLength-inSize], strRight, inSize);
	inSize=strlen(strLeft);
    memcpy(szStr, strLeft, strlen(strLeft));
	
    //memset (baTemp, 0x00, sizeof(baTemp));
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);

    //return CTOS_PrinterBufferOutput((BYTE *)baTemp, inSpacing);
	//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
    inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
	return d_OK;
}

int inPrintLeftRight2(unsigned char *strLeft, unsigned char *strRight, int inMode) 
{
	char szStr[48+1]; 
    int inLength=0, inSize=0;
    BYTE baTemp[PAPER_X_SIZE * 64];
	
	//if(inMode == LENGTH_24)
        //inLength=LENGTH_24;
	//else if(inMode == LENGTH_32)
		//inLength=LENGTH_32;
	//else
	    //inLength=LENGTH_41;
	inLength=inMode;
	
	memset(szStr, 0x20, sizeof(szStr));
	inSize=strlen(strRight);
    memcpy(&szStr[inLength-inSize], strRight, inSize);
	inSize=strlen(strLeft);
    memcpy(szStr, strLeft, strlen(strLeft));
	
    //memset (baTemp, 0x00, sizeof(baTemp));
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);

    //return CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	return d_OK;
}


//sidumili: Issue#000135 [Print Footer Logo]
void vdCTOSS_PrintFooterLogoBMPPic(unsigned int usX,unsigned int y, const char *path)
{
char szBmpfile[50+1];
memset(szBmpfile, 0x00, sizeof(szBmpfile));
sprintf(szBmpfile,"%s%s", PUBLIC_PATH, path);
//CTOS_PrinterBMPPic(usX, szBmpfile);
vdCTOSS_PrinterBMPPicEx(0, 0, szBmpfile);

return ;
}
//BDO: Added settlement status to settlement report - start -- jzg
void vdBDO_PrintSettlementReportFooter(void)
{
	int inCtr = 0,
		inResult = d_OK,
		inPadLen = 0;
	BYTE baTemp[PAPER_X_SIZE * 64] = {0};
	char szStr[50] = {0},
		szHostName[50] = {0},
		szNII[10] = {0},
		szStatus[10] = {0};

	int inNUMofRecords=0;

	vdPrintReportDisplayBMP();

	vdCTOSS_PrinterStart(100);
    CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel); 


#if 0	
    if(strTCT.fSMLogo== TRUE)
        vdCTOSS_PrinterBMPPic(0, 0, strTCT.szSMReceiptLogo);
	else 
	    vdCTOSS_PrinterBMPPic(0, 0, strTCT.szBDOReceiptLogo);

	inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_16x16,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

    memset(srTransRec.szDate, 0, sizeof(srTransRec.szDate));
	memset(srTransRec.szTime, 0, sizeof(srTransRec.szTime));
	
	(void)printDateTime();
#endif
	inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_16x16,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	printDateTime();
	
	sprintf(szStr,"HOST                 NII      SETTLED?");
	memset(baTemp, 0x00, sizeof(baTemp));
	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

	inResult = inMMTReadRecord_Footer();

	inNUMofRecords = inMMTNumRecord();

	//for (inCtr = 0; inCtr < inMMTNumRecord(); inCtr++)
	
	for (inCtr = 0; inCtr < inNUMofRecords; inCtr++)
	{

	  if (strMMT_Ft[inCtr].MITid != srTransRec.MITid)
			continue;
		
		vdDebug_LogPrintf("MMT_FT Ctr [%d]", inCtr);
		memset(szHostName, 0, sizeof(szHostName));
		memset(szNII, 0, sizeof(szNII));
		memset(szStatus, 0, sizeof(szStatus));
		
		strcpy(szHostName, strMMT_Ft[inCtr].szHostName);
		wub_hex_2_str(strMMT_Ft[inCtr].szNII, szNII, 2);

		vdDebug_LogPrintf("%d>HostName = [%s]", inCtr, strMMT_Ft[inCtr].szHostName);
		vdDebug_LogPrintf("%d>NII = [%02x%02x]", inCtr, strMMT_Ft[inCtr].szNII[0], strMMT_Ft[inCtr].szNII[1]);
		vdDebug_LogPrintf("%d>Settle Status = [%d]", inCtr, strMMT_Ft[inCtr].inSettleStatus);
		
		switch(strMMT_Ft[inCtr].inSettleStatus)
		{
			case 0:
				strcpy(szStatus, "EMPTY");
				break;
			case 1:
				strcpy(szStatus, "YES");
				break;
			case 2:
				strcpy(szStatus, "NO");
				break;
		}

		inPadLen = strlen(szHostName)+(20-strlen(szHostName));
		vdCTOS_Pad_String(szHostName, inPadLen, ' ', POSITION_RIGHT);
		inPadLen = strlen(szNII)+(8-strlen(szNII));
		vdCTOS_Pad_String(szNII, inPadLen, ' ', POSITION_RIGHT);
		inPadLen = strlen(szStatus)+(8-strlen(szStatus));
		vdCTOS_Pad_String(szStatus, inPadLen, ' ', POSITION_RIGHT);

		sprintf(szStr,"%s %s %s", szHostName, szNII, szStatus);
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	}

	
	//CTOS_PrinterFline(d_LINE_DOT * 6);
	vdCTOS_PrinterFline(6);
	vdCTOSS_PrinterEnd();
	
}

int inPrintDebug(unsigned char *strPrint) 
{
	char szStr[2048] = {0}; 
	BYTE baTemp[PAPER_X_SIZE * 64] = {0};
	
	memset(szStr, 0x00, sizeof(szStr));
	memcpy(szStr, strPrint, strlen(strPrint));

	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
	if( printCheckPaper()==-1)
		return ;
	
	CTOS_LanguagePrinterFontSize(d_FONT_16x16, 0, TRUE);	

	memset (baTemp, 0x00, sizeof(baTemp));
	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	//return CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
}


//0720
int inCopyLeftRight(unsigned char *strLeft, unsigned char *strRight, int inMode, unsigned char *strDest) 
{
	char szStr[48+1]; 
    int inLength=0, inSize=0;
    BYTE baTemp[PAPER_X_SIZE * 64];
	
	//if(inMode == LENGTH_24)
        //inLength=LENGTH_24;
	//else if(inMode == LENGTH_32)
		//inLength=LENGTH_32;
	//else
	    //inLength=LENGTH_41;
	inLength=inMode;
	
	memset(szStr, 0x20, sizeof(szStr));
	inSize=strlen(strRight);
    memcpy(&szStr[inLength-inSize], strRight, inSize);
	inSize=strlen(strLeft);
    memcpy(szStr, strLeft, strlen(strLeft));

		memcpy(strDest, szStr, sizeof(szStr));
	
}


void vdRemoveSpace(char* szDestination, char* szSource)
{
	int inLen;
	int i = 0;
	int j = 0;

	inLen = strlen(szSource);

	while(i < inLen)
	{
		if(szSource[i] != ' ')
		{
			szDestination[j] = szSource[i];
			j++;
		}
		i++;
	}

}

//0720

//smac
USHORT ushCTOS_PrintSMACBody_old(int page)
{	
    char szStr[d_LINE_SIZE + 3];
    char szTemp[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    char szTemp3[d_LINE_SIZE + 1];
    char szTemp4[d_LINE_SIZE + 1];
    char szTemp5[d_LINE_SIZE + 1];
    char szFormatPAN[strlen(srTransRec.szPAN) + 7];//to account for space as in PAN format and to include additional PAN no. 7 has been added -Meena 08/01/2012
    int inFmtPANSize;
    BYTE baTemp[PAPER_X_SIZE * 64];
    USHORT result;
    int num,i,inResult;
    unsigned char tucPrint [24*4+1];	
    BYTE   EMVtagVal[64];
    USHORT EMVtagLen; 
    short spacestring;
    BYTE   key;

	char szAmountBuff[20], szTemp6[47];
	int inPADSize,x;
	char szSPACE[40];
	char szPOSEntry[21] = {0};

	if(d_FIRST_PAGE == page)
	{
    	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    	printTIDMID(FALSE); 

		memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
		EMVtagLen = 0;
		memset(szStr, ' ', d_LINE_SIZE);
		vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);

		sprintf(szStr, "%s", srTransRec.szCardLable);
		vdMyEZLib_LogPrintf("Card label: %s",srTransRec.szCardLable);

		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

    	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		if (srTransRec.byEntryMode == CARD_ENTRY_WAVE){
			
			memset(szStr, 0x00, sizeof(szStr));
			strcpy(szStr, "CONTACTLESS");
			vdPrintCenter(szStr);
		}

		memset(szTemp5, 0x00, sizeof(szTemp5));
		vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp5);
		
		memset(szTemp6, 0x00, sizeof(szTemp6));
		memset(szTemp4, 0x00, sizeof(szTemp4));
		
		if (strlen(srTransRec.szPAN) > 16)
			vdRemoveSpace(szTemp6, szTemp5);		
		else
			strcpy(szTemp6, szTemp5);
				
		strcpy(szTemp4, szTemp6);
			
		//if (srTransRec.byEntryMode == CARD_ENTRY_MANUAL){
		//		strcat(szTemp4," *");
		//}

    	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		memset(szPOSEntry, 0x00, sizeof(szPOSEntry));

		switch(srTransRec.byEntryMode)
		{
			case CARD_ENTRY_MSR:
		   		strcat(szPOSEntry, "SWIPE");
			   	break;
			case CARD_ENTRY_MANUAL:
			   	strcat(szPOSEntry, "MANUAL");
			   	break;
			case CARD_ENTRY_ICC:
		 		strcat(szPOSEntry, "CHIP");   
			   	break;
			case CARD_ENTRY_FALLBACK:
			   	strcat(szPOSEntry, "FALLBACK");	 
			   	break;
		}
		
		//memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szTemp4, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);	
		inPrintLeftRight(szTemp4,szPOSEntry,42);

        //card holder name
        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		printCardHolderName();

		//Trans type
        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		memset(szStr, 0x00, sizeof(szStr));
		//szGetTransTitle(srTransRec.byTransType, szStr); 

		if (srTransRec.byTransType == SALE_OFFLINE)
			strcpy(szStr, "SMAC PTS");
		else if (srTransRec.byTransType == SALE)
			strcpy(szStr, "REDEMPTION");
		else if (srTransRec.byTransType == SMAC_BALANCE)
			strcpy(szStr, "POINTS INQUIRY");
		else if (srTransRec.byTransType == VOID)
			strcpy(szStr, "VOID");
			
			
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		
		/* Issue# 000096: BIN VER Checking - start -- jzg*/
		if (srTransRec.fBINVer)
		{
			//BIN Ver
			vdDebug_LogPrintf("fBINVer = [%d]", fBINVer);
			vdDebug_LogPrintf("BIN Ver STAN = [%s]", szBINVerSTAN);
			
			memset(szStr, 0, d_LINE_SIZE);
			memset(baTemp, 0, sizeof(baTemp)); //BDO: Fix for overlapping BIN Check line on receipt --sidumili
			vdCTOS_Pad_String(srTransRec.szBINVerSTAN, 6, '0', POSITION_LEFT);   //sidumili: modified using stTransRec to get record during reprint/void
			sprintf(szStr, "BIN CHECK: %s", srTransRec.szBINVerSTAN);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		/* Issue# 000096: BIN VER Checking - end -- jzg*/

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);
        
		printBatchInvoiceNO();

		printDateTime();

    
        if ((srTransRec.byTransType == SALE) || (srTransRec.byOrgTransType == SALE) || (srTransRec.byTransType == SMAC_BALANCE)){
			
			if (strTCT.fDutyFreeMode == TRUE){
		   		//Reference num
		   		sprintf(szStr, "REF. NO. %s", srTransRec.szRRN);
		   		memset (baTemp, 0x00, sizeof(baTemp));	   
		   		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		   		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			
		   		vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);  
		   		sprintf(szStr, "APPR. CODE: %s", srTransRec.szAuthCode);
		   		vdCTOS_Pad_String(szStr, 23, ' ', POSITION_LEFT);
		   		memset (baTemp, 0x00, sizeof(baTemp));	   
		   		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		   		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		   		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
			}else{
			 	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
			 if(strlen(srTransRec.szRRN) <= 0)
				 sprintf(szStr, "REF. NO.               APPR. CODE: %s",srTransRec.szAuthCode);
			 else
				sprintf(szStr, "REF. NO. %s  APPR. CODE: %s", srTransRec.szRRN,srTransRec.szAuthCode);
			 	memset (baTemp, 0x00, sizeof(baTemp)); 	 
			 	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			 	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			}

        }

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);

		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		memset(szTemp1, ' ', d_LINE_SIZE);
		memset(szTemp3, ' ', d_LINE_SIZE);
		wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szTipAmount, szTemp3, AMT_BCD_SIZE);

        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		//1025 - ADD OFFLINE SALE

		wub_hex_2_str(srTransRec.szTotalAmount, szTemp1, AMT_BCD_SIZE);


		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
			
		if (srTransRec.byTransType == SMAC_BALANCE)		
			strcpy(szTemp6,"BALANCE:");	
		else
			strcpy(szTemp6,"AMOUNT:");	
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216	
		
		if (srTransRec.byTransType == VOID)
			sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4); /*BDO: Negative sign on amount during void -- sidumili*/
		else
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			
		inPrintLeftRight(szTemp6,szAmountBuff,23);

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);


        if (srTransRec.byTransType == SALE_OFFLINE){

			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	

			memset(szTemp1, 0x00, sizeof(szTemp1));
			wub_hex_2_str(srTransRec.SmacPoints, szTemp1, AMT_BCD_SIZE);

			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"POINTS EARNED");	
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,42);
		
        }

		if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == VOID)){

			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
			memset(szTemp1, 0x00, sizeof(szTemp1));
				
			wub_hex_2_str(srTransRec.SmacBalance, szTemp1, AMT_BCD_SIZE);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"NEW BALANCE:");	
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			sprintf(szAmountBuff,"%s%s pts",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,42);



		}
		
		//CTOS_PrinterFline(d_LINE_DOT * 2);
		vdCTOS_PrinterFline(2);
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
		vdPrintCenter("   ***** BANK COPY *****  ");
		//CTOS_PrinterFline(d_LINE_DOT * 6); 
		vdCTOS_PrinterFline(6);
	    	
	}
	else if(d_SECOND_PAGE == page)
	{
    	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    	printTIDMID(FALSE); 

		memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
		EMVtagLen = 0;
		memset(szStr, ' ', d_LINE_SIZE);
		vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);

		sprintf(szStr, "%s", srTransRec.szCardLable);
		vdMyEZLib_LogPrintf("Card label: %s",srTransRec.szCardLable);

		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

    	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		if (srTransRec.byEntryMode == CARD_ENTRY_WAVE){
			
			memset(szStr, 0x00, sizeof(szStr));
			strcpy(szStr, "CONTACTLESS");
			vdPrintCenter(szStr);
		}

		memset(szTemp5, 0x00, sizeof(szTemp5));
		vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp5);
		
		memset(szTemp6, 0x00, sizeof(szTemp6));
		memset(szTemp4, 0x00, sizeof(szTemp4));
		
		if (strlen(srTransRec.szPAN) > 16)
			vdRemoveSpace(szTemp6, szTemp5);		
		else
			strcpy(szTemp6, szTemp5);
				
		strcpy(szTemp4, szTemp6);
			
		//if (srTransRec.byEntryMode == CARD_ENTRY_MANUAL){
		//		strcat(szTemp4," *");
		//}
			
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		memset(szPOSEntry, 0x00, sizeof(szPOSEntry));
			
		switch(srTransRec.byEntryMode)
		{
			case CARD_ENTRY_MSR:
				strcat(szPOSEntry, "SWIPE");
				break;
			case CARD_ENTRY_MANUAL:
				strcat(szPOSEntry, "MANUAL");
				break;
			case CARD_ENTRY_ICC:
				strcat(szPOSEntry, "CHIP");   
				break;
			case CARD_ENTRY_FALLBACK:
				strcat(szPOSEntry, "FALLBACK");  
				break;
		}
			
		//memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szTemp4, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);	
		inPrintLeftRight(szTemp4,szPOSEntry,42);

        //card holder name
        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		printCardHolderName();

		//Trans type
        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		memset(szStr, 0x00, sizeof(szStr));
		//szGetTransTitle(srTransRec.byTransType, szStr); 

		if (srTransRec.byTransType == SALE_OFFLINE)
			strcpy(szStr, "SMAC PTS");
		else if (srTransRec.byTransType == SALE)
			strcpy(szStr, "REDEMPTION");
		else if (srTransRec.byTransType == SMAC_BALANCE)
			strcpy(szStr, "POINTS INQUIRY");
		else if (srTransRec.byTransType == VOID)
			strcpy(szStr, "VOID");

			
			
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		
		/* Issue# 000096: BIN VER Checking - start -- jzg*/
		if (srTransRec.fBINVer)
		{
			//BIN Ver
			vdDebug_LogPrintf("fBINVer = [%d]", fBINVer);
			vdDebug_LogPrintf("BIN Ver STAN = [%s]", szBINVerSTAN);
			
			memset(szStr, 0, d_LINE_SIZE);
			memset(baTemp, 0, sizeof(baTemp)); //BDO: Fix for overlapping BIN Check line on receipt --sidumili
			vdCTOS_Pad_String(srTransRec.szBINVerSTAN, 6, '0', POSITION_LEFT);   //sidumili: modified using stTransRec to get record during reprint/void
			sprintf(szStr, "BIN CHECK: %s", srTransRec.szBINVerSTAN);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		/* Issue# 000096: BIN VER Checking - end -- jzg*/

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);
        
		printBatchInvoiceNO();

		printDateTime();

    
	if ((srTransRec.byTransType == SALE) || (srTransRec.byOrgTransType == SALE) || (srTransRec.byTransType == SMAC_BALANCE)){
		if (strTCT.fDutyFreeMode == TRUE){
			//Reference num
			sprintf(szStr, "REF. NO. %s", srTransRec.szRRN);
			memset (baTemp, 0x00, sizeof(baTemp));	   
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		
			vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);	
			sprintf(szStr, "APPR. CODE: %s", srTransRec.szAuthCode);
			vdCTOS_Pad_String(szStr, 23, ' ', POSITION_LEFT);
			memset (baTemp, 0x00, sizeof(baTemp));	   
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		}else{
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		 if(strlen(srTransRec.szRRN) <= 0)
			 sprintf(szStr, "REF. NO.				APPR. CODE: %s",srTransRec.szAuthCode);
		 else
			sprintf(szStr, "REF. NO. %s  APPR. CODE: %s", srTransRec.szRRN,srTransRec.szAuthCode);
			memset (baTemp, 0x00, sizeof(baTemp));	 
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
        }

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);

		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		memset(szTemp1, ' ', d_LINE_SIZE);
		memset(szTemp3, ' ', d_LINE_SIZE);
		wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szTipAmount, szTemp3, AMT_BCD_SIZE);

        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		//1025 - ADD OFFLINE SALE

		wub_hex_2_str(srTransRec.szTotalAmount, szTemp1, AMT_BCD_SIZE);

		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
			
		if (srTransRec.byTransType == SMAC_BALANCE)		
			strcpy(szTemp6,"BALANCE:");	
		else
			strcpy(szTemp6,"AMOUNT:");	
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216	

		if (srTransRec.byTransType == VOID)
			sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4); /*BDO: Negative sign on amount during void -- sidumili*/
		else
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
		
		inPrintLeftRight(szTemp6,szAmountBuff,23);

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);


        if (srTransRec.byTransType == SALE_OFFLINE){

			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	

			memset(szTemp1, 0x00, sizeof(szTemp1));
			wub_hex_2_str(srTransRec.SmacPoints, szTemp1, AMT_BCD_SIZE);

			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"POINTS EARNED");	
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,42);
		
        }

		if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == VOID)){

			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
			memset(szTemp1, 0x00, sizeof(szTemp1));
				
			wub_hex_2_str(srTransRec.SmacBalance, szTemp1, AMT_BCD_SIZE);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"NEW BALANCE:");	
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			sprintf(szAmountBuff,"%s%s pts",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,42);



		}


		//CTOS_PrinterFline(d_LINE_DOT * 2);
		vdCTOS_PrinterFline(2);
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
		vdPrintCenter("   ***** CUSTOMER COPY *****  ");
		//CTOS_PrinterFline(d_LINE_DOT * 6);
		vdCTOS_PrinterFline(6);
		
	}

	else if(d_THIRD_PAGE == page)
	{
    	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    	printTIDMID(FALSE); 

		memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
		EMVtagLen = 0;
		memset(szStr, ' ', d_LINE_SIZE);
		vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);

		sprintf(szStr, "%s", srTransRec.szCardLable);
		vdMyEZLib_LogPrintf("Card label: %s",srTransRec.szCardLable);

		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

    	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		if (srTransRec.byEntryMode == CARD_ENTRY_WAVE){
			
			memset(szStr, 0x00, sizeof(szStr));
			strcpy(szStr, "CONTACTLESS");
			vdPrintCenter(szStr);
		}

		memset(szTemp5, 0x00, sizeof(szTemp5));
		vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp5);
		
		memset(szTemp6, 0x00, sizeof(szTemp6));
		memset(szTemp4, 0x00, sizeof(szTemp4));
		
		if (strlen(srTransRec.szPAN) > 16)
			vdRemoveSpace(szTemp6, szTemp5);		
		else
			strcpy(szTemp6, szTemp5);
				
		strcpy(szTemp4, szTemp6);
			
		//if (srTransRec.byEntryMode == CARD_ENTRY_MANUAL){
		//		strcat(szTemp4," *");
		//}
			
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		memset(szPOSEntry, 0x00, sizeof(szPOSEntry));
			
		switch(srTransRec.byEntryMode)
		{
			case CARD_ENTRY_MSR:
				strcat(szPOSEntry, "SWIPE");
				break;
			case CARD_ENTRY_MANUAL:
				strcat(szPOSEntry, "MANUAL");
				break;
			case CARD_ENTRY_ICC:
				strcat(szPOSEntry, "CHIP");   
				break;
			case CARD_ENTRY_FALLBACK:
				strcat(szPOSEntry, "FALLBACK");  
				break;
		}
			
		//memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szTemp4, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);	
		inPrintLeftRight(szTemp4,szPOSEntry,42);
		
        //card holder name
        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		printCardHolderName();

		//Trans type
        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		memset(szStr, 0x00, sizeof(szStr));
		//szGetTransTitle(srTransRec.byTransType, szStr); 

		if (srTransRec.byTransType == SALE_OFFLINE)
			strcpy(szStr, "SMAC PTS");
		else if (srTransRec.byTransType == SALE)
			strcpy(szStr, "REDEMPTION");
		else if (srTransRec.byTransType == SMAC_BALANCE)
			strcpy(szStr, "POINTS INQUIRY");
		else if (srTransRec.byTransType == VOID)
			strcpy(szStr, "VOID");

			
			
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		
		/* Issue# 000096: BIN VER Checking - start -- jzg*/
		if (srTransRec.fBINVer)
		{
			//BIN Ver
			vdDebug_LogPrintf("fBINVer = [%d]", fBINVer);
			vdDebug_LogPrintf("BIN Ver STAN = [%s]", szBINVerSTAN);
			
			memset(szStr, 0, d_LINE_SIZE);
			memset(baTemp, 0, sizeof(baTemp)); //BDO: Fix for overlapping BIN Check line on receipt --sidumili
			vdCTOS_Pad_String(srTransRec.szBINVerSTAN, 6, '0', POSITION_LEFT);   //sidumili: modified using stTransRec to get record during reprint/void
			sprintf(szStr, "BIN CHECK: %s", srTransRec.szBINVerSTAN);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		/* Issue# 000096: BIN VER Checking - end -- jzg*/

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);
        
		printBatchInvoiceNO();

		printDateTime();

    
	if ((srTransRec.byTransType == SALE) || (srTransRec.byOrgTransType == SALE) || (srTransRec.byTransType == SMAC_BALANCE)){
		if (strTCT.fDutyFreeMode == TRUE){
			//Reference num
			sprintf(szStr, "REF. NO. %s", srTransRec.szRRN);
			memset (baTemp, 0x00, sizeof(baTemp));	   
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		
			vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);	
			sprintf(szStr, "APPR. CODE: %s", srTransRec.szAuthCode);
			vdCTOS_Pad_String(szStr, 23, ' ', POSITION_LEFT);
			memset (baTemp, 0x00, sizeof(baTemp));	   
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		}else{
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		 if(strlen(srTransRec.szRRN) <= 0)
			 sprintf(szStr, "REF. NO.				APPR. CODE: %s",srTransRec.szAuthCode);
		 else
			sprintf(szStr, "REF. NO. %s  APPR. CODE: %s", srTransRec.szRRN,srTransRec.szAuthCode);
			memset (baTemp, 0x00, sizeof(baTemp));	 
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
     }

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);
		
		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		memset(szTemp1, ' ', d_LINE_SIZE);
		memset(szTemp3, ' ', d_LINE_SIZE);
		wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szTipAmount, szTemp3, AMT_BCD_SIZE);

        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		//1025 - ADD OFFLINE SALE

		wub_hex_2_str(srTransRec.szTotalAmount, szTemp1, AMT_BCD_SIZE);

		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
			
		if (srTransRec.byTransType == SMAC_BALANCE)		
			strcpy(szTemp6,"BALANCE:");	
		else
			strcpy(szTemp6,"AMOUNT:");	
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		

		if (srTransRec.byTransType == VOID)
			sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4); /*BDO: Negative sign on amount during void -- sidumili*/
		else
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
		
		inPrintLeftRight(szTemp6,szAmountBuff,23);

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);


        if (srTransRec.byTransType == SALE_OFFLINE){

			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	

			memset(szTemp1, 0x00, sizeof(szTemp1));
			wub_hex_2_str(srTransRec.SmacPoints, szTemp1, AMT_BCD_SIZE);

			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"POINTS EARNED");	
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,42);
		
        }

		if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == VOID)){

			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
			memset(szTemp1, 0x00, sizeof(szTemp1));
				
			wub_hex_2_str(srTransRec.SmacBalance, szTemp1, AMT_BCD_SIZE);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"NEW BALANCE:");	
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			sprintf(szAmountBuff,"%s%s pts",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,42);



		}
	
		//CTOS_PrinterFline(d_LINE_DOT * 2);
		vdCTOS_PrinterFline(2);
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		vdPrintCenter("   ***** MERCHANT COPY *****  ");
		//CTOS_PrinterFline(d_LINE_DOT * 6);
		vdCTOS_PrinterFline(6);
	
	}

	return d_OK;	
	
}
//smac


/* BDOCLG-00134: Reformat cardtype line - start -- jzg */
void vdStrCat2(char szStr1[40], char szStr2[21], short shStr2Pos, char *szOutPut)
{
	char szDisp[41] = {0};
	short shXPos = 0;

	if(shStr2Pos < 19)
		shXPos = 19;
	else
		shXPos = shStr2Pos;

	memset(szDisp, ' ', 40);
	memcpy(szDisp, szStr1, strlen(szStr1));
	memcpy(&szDisp[shStr2Pos], szStr2, strlen(szStr2));

	memcpy(szOutPut, szDisp, strlen(szDisp));
}
/* BDOCLG-00134: Reformat cardtype line - start -- jzg */

int inCTOS_PRINT_DETAIL_ALL(void)
{
    int inRet = d_NO;

	//GetReportTime();

    CTOS_LCDTClearDisplay();
		
    vdCTOS_TxnsBeginInit();
    inRet = inCTOS_PrintMerchantDetailAllOperation();
    vdCTOS_TransEndReset();

		CTOS_LCDTClearDisplay();
		
    return inRet;
}

int inCTOS_PrintMerchantDetailAllOperation(void)
{
  	int inRet = d_NO;
  	int inNumOfHost = 0,inNum;
  	char szBcd[INVOICE_BCD_SIZE+1];
  	char szErrMsg[30+1];
  	char szAPName[25];
  	int inAPPID;

    inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
    if(d_OK != inRet)
        return inRet;
    
    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        vdCTOS_PrintMerchantDetailReportAll();
        inCTOS_MultiAPALLAppEventID(d_IPC_CMD_DETAIL_REPORT_ALL);
    }
    else
    {
        if (inMultiAP_CheckSubAPStatus() == d_OK)
        {
            inRet = inCTOS_MultiAPGetData();
            if(d_OK != inRet)
                return inRet;
            
            //inRet = inCTOS_MultiAPReloadTable();
            //if(d_OK != inRet)
                //return inRet;
            
            vdCTOS_PrintMerchantDetailReportAll();
        }    
    }
    
    CTOS_LCDTClearDisplay();
    return ST_SUCCESS;
}


void vdCTOS_PrintMerchantDetailReportAll(void)
{
    unsigned char chkey;
    short shHostIndex;
    int inResult,i,inCount,inRet;
    int inTranCardType;
    int inReportType;
    int inBatchNumOfRecord;
    int *pinTransDataid;
    
    ACCUM_REC srAccumRec;
    BYTE baTemp[PAPER_X_SIZE * 64];
    char szStr[d_LINE_SIZE + 1];

		//int inRet = d_NO;
		int inNumOfHost = 0, inNum = 0;
		char szBcd[INVOICE_BCD_SIZE+1] = {0};
		char szErrMsg[31] = {0};
		char szAPName[25] = {0};
		int inAPPID = 0;
    BOOL fPrintDetail=FALSE;


	char szDisplayMsg[20];

		CTOS_LCDTClearDisplay();
		vdDispTitleString("DETAIL REPORT");
			
    if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
        return;
    
    if( printCheckPaper()==-1)
        return;
	else
		vduiClearBelow(2);

   	memset(szAPName,0x00,sizeof(szAPName));
   	inMultiAP_CurrentAPNamePID(szAPName, &inAPPID);

    inNumOfHost = inHDTNumRecord();
    vdDebug_LogPrintf("inNumOfHost=[%d]-----",inNumOfHost);
    for(inNum =1 ;inNum <= inNumOfHost; inNum++)
    {
        if(inHDTRead(inNum) == d_OK)
        {
            if(strHDT.fHostEnable != TRUE)
						     continue;

			//display-host
			memset(szDisplayMsg, 0x00, sizeof(szDisplayMsg));
			sprintf(szDisplayMsg,"%s",strHDT.szHostLabel); 
			vdCTOS_DispStatusMessage(szDisplayMsg);
			//end
			
            vdDebug_LogPrintf("szAPName=[%s]-[%s]----",szAPName,strHDT.szAPName);
            if (strcmp(szAPName, strHDT.szAPName)!=0)
                continue;
						else
						{
							srTransRec.HDTid=strHDT.inHostIndex;
							
							inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);
							memcpy(srTransRec.szBatchNo, strMMT[0].szBatchNo, 4);
							
							inBatchNumOfRecord = inBatchNumRecord();
							
							DebugAddINT("batch record",inBatchNumOfRecord);
							if(inBatchNumOfRecord <= 0)
							{
									vdDisplayErrorMsg(1, 8, "EMPTY BATCH");
									continue;
							}

							vdCTOS_PrintMerchantDetailReport();
							
							CTOS_LCDTClearDisplay();
							vdDispTitleString("DETAIL REPORT");
						}
        }
    }
    return;	
}

void vdCTOS_PrintMerchantDetailReport(void)
{
    unsigned char chkey;
    short shHostIndex;
    int inResult,i,inCount,inRet;
    int inTranCardType;
    int inReportType;
    int inBatchNumOfRecord;
    int *pinTransDataid;
    
    ACCUM_REC srAccumRec;
    BYTE baTemp[PAPER_X_SIZE * 64];
    char szStr[d_LINE_SIZE + 1];

		//int inRet = d_NO;
		int inNumOfHost = 0, inNum = 0;
		char szBcd[INVOICE_BCD_SIZE+1] = {0};
		char szErrMsg[31] = {0};
		char szAPName[25] = {0};
		int inAPPID = 0;
    BOOL fPrintDetail=FALSE;

    inCSTRead(strHDT.inCurrencyIdx); /*to load Currence and amount format*/

	vdDebug_LogPrintf("vdCTOS_PrintMerchantDetailReport");
	
	vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);

	vdPrintReportDisplayBMP();

    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
    vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);
    
    ushCTOS_printBatchRecordHeader();

    //inBatchNumOfRecord = inBatchNumRecord();
    //change to include even pre-auth, function ushCTOS_printBatchRecordFooter will just exclude the pre-auth trans during printing
    inBatchNumOfRecord = inBatchNumALLRecord();
		
    pinTransDataid = (int*)malloc(inBatchNumOfRecord  * sizeof(int));
    inCount = 0;		
    inBatchByMerchandHost(inBatchNumOfRecord, srTransRec.HDTid, srTransRec.MITid, srTransRec.szBatchNo, pinTransDataid);
    for(i=0; i<inBatchNumOfRecord; i++)
    {
        inResult = inDatabase_BatchReadByTransId(&srTransRec, pinTransDataid[inCount]);
        inCount ++;
        ushCTOS_printBatchRecordFooter();	
    }

    free(pinTransDataid);
	
    memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
    {
        vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
        return; 	 
    }

    //CTOS_PrinterFline(d_LINE_DOT * 1);
    //CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(2);
    
    memset(baTemp, 0x00, sizeof(baTemp));
	if(inCheckIfDCCHost() == TRUE)
    	sprintf(szStr,"CARD TYPE  COUNT  DCC AMT          PHP AMT");
	else
		sprintf(szStr,"CARD TYPE        COUNT                 AMT");
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

    for(inTranCardType = 0; inTranCardType < 1 ;inTranCardType ++)
    {
		if(srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMGIFTCARD_HDT_INDEX)
			inTranCardType = 1;
						
        inReportType = DETAIL_REPORT_TOTAL;
        
        //for(i= 0; i <30; i ++ )
        for(i= 0; i <37; i ++ )
        {
            vdDebug_LogPrintf("--Count[%d]", i);
            if((srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount == 0)
            &&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount == 0)
            &&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount == 0)
            &&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount == 0)
            //issue-00270 - show card type in Detail Report Totals per card even if cash advance is the only transaction
            &&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount == 0)
            &&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount == 0)
            /*&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usKitSaleCount == 0)
            &&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRenewalCount == 0)
            &&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usPtsAwardCount == 0)*/)
                continue;
            
            vdDebug_LogPrintf("Count[%d]", i); 
            inIITRead(i);
            memset(szStr, ' ', d_LINE_SIZE);
            memset (baTemp, 0x00, sizeof(baTemp));

			//00148 - No card type prints in Detail report	and manual settlement  with detail receipt for BDO Loyalty #2
			#if 0
			strcpy(szStr,strIIT.szIssuerLabel);
			//sprintf(szStr,"ISSUER: %s",strIIT.szIssuerLabel);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			#endif

			
            inCSTRead(strHDT.inCurrencyIdx);

			if (inCheckIfSMCardTransRec() == TRUE){
            	#if 0
				vdCTOS_PrintAccumeByHostAndCard (inReportType, 
				//deduct void cash advance on Detail total
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount, 	
            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount),
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount));	
				#endif
				vdCTOS_PrintSMAccumeByHostAndCard(inReportType, 
				//deduct void cash advance on Detail total
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount,	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount,
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount, 
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount,
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount,
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount,
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usKitSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulKitSaleTotalAmount,
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRenewalCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRenewalTotalAmount,
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usPtsAwardCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulPtsAwardTotalAmount
				);

			}else{
				if(inCheckIfDCCHost()== TRUE)
				{
					vdCTOS_PrintDCCandLocalAccumeByHostAndCard(inReportType, 
					//deduct void cash advance on Detail total
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 	
	            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
	            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulLocalTipTotalAmount),
	            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulLocalSaleTotalAmount) /*- (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulLocalOffSaleTotalAmount)*/);
				}
				else
				{
	            	vdCTOS_PrintAccumeByHostAndCard (inReportType, 
					//deduct void cash advance on Detail total
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 	
	            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
	            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),
	            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount));	
				}
			}
        }
			
        printDividingLine(DIVIDING_LINE);
        
        inReportType = DETAIL_REPORT_GRANDTOTAL;

		
		if (inCheckIfSMCardTransRec() == TRUE){
			#if 0
        	vdCTOS_PrintAccumeByHostAndCard (inReportType, 
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, 	
        	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
        	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount));		
			#endif
			
			vdCTOS_PrintSMAccumeByHostAndCard(inReportType, 
			//deduct void cash advance on Detail total
			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, 	
        	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
        	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usKitSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulKitSaleTotalAmount),
			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRenewalCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRenewalTotalAmount),
			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usPtsAwardCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulPtsAwardTotalAmount)
			);
		}else{

			if(inCheckIfDCCHost()== TRUE)
			{
				vdCTOS_PrintDCCandLocalAccumeByHostAndCard(inReportType, 
				//deduct void cash advance on Detail total
            	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 	
            	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
            	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
            	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
            	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
            	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
            	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
            	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalTipTotalAmount),
            	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount) /*- (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulLocalOffSaleTotalAmount)*/);
			}
			else
			{
	        	vdCTOS_PrintAccumeByHostAndCard (inReportType, 
	        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 	
	        	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
	        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
	        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
	        	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
	        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
	        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
	        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount));		
			}
		}
    }
		
		//CTOS_PrinterFline(d_LINE_DOT * 10);
		vdCTOS_PrinterFline(10);

        vdCTOSS_PrinterEnd();
    return;	
}

int inCTOS_PRINT_SUMMARY_ALL(void)
{
    int inRet = d_NO;

	//GetReportTime();
    
    CTOS_LCDTClearDisplay();
		
    vdCTOS_TxnsBeginInit();
    inRet = inCTOS_PrintMerchantSummaryAllOperation();
    vdCTOS_TransEndReset();

		CTOS_LCDTClearDisplay();
		
    return inRet;
}

int inCTOS_PrintMerchantSummaryAllOperation(void)
{
  	int inRet = d_NO;
  	int inNumOfHost = 0,inNum;
  	char szBcd[INVOICE_BCD_SIZE+1];
  	char szErrMsg[30+1];
  	char szAPName[25];
  	int inAPPID;

    inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
    if(d_OK != inRet)
        return inRet;
    
    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        vdCTOS_PrintMerchantSummaryReportAll();
        inCTOS_MultiAPALLAppEventID(d_IPC_CMD_SUMMARY_REPORT_ALL);
    }
    else
    {
        if (inMultiAP_CheckSubAPStatus() == d_OK)
        {
            inRet = inCTOS_MultiAPGetData();
            if(d_OK != inRet)
                return inRet;
            
            //inRet = inCTOS_MultiAPReloadTable();
            //if(d_OK != inRet)
                //return inRet;
            
            vdCTOS_PrintMerchantSummaryReportAll();
        }    
    }
    
    CTOS_LCDTClearDisplay();
    return ST_SUCCESS;
}


void vdCTOS_PrintMerchantSummaryReportAll(void)
{
    unsigned char chkey;
    short shHostIndex;
    int inResult,i,inCount,inRet;
    int inTranCardType;
    int inReportType;
    int inBatchNumOfRecord;
    int *pinTransDataid;
    
    ACCUM_REC srAccumRec;
    BYTE baTemp[PAPER_X_SIZE * 64];
    char szStr[d_LINE_SIZE + 1];

		//int inRet = d_NO;
		int inNumOfHost = 0, inNum = 0;
		char szBcd[INVOICE_BCD_SIZE+1] = {0};
		char szErrMsg[31] = {0};
		char szAPName[25] = {0};
		int inAPPID = 0;
    BOOL fPrintDetail=FALSE;

		char szDisplayMsg[20];

		CTOS_LCDTClearDisplay();
		vdDispTitleString("SUMMARY REPORT");
			
    if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
        return;
    
    if( printCheckPaper()==-1)
        return;
	else
		vduiClearBelow(2);

   	memset(szAPName,0x00,sizeof(szAPName));
   	inMultiAP_CurrentAPNamePID(szAPName, &inAPPID);

    inNumOfHost = inHDTNumRecord();
    vdDebug_LogPrintf("inNumOfHost=[%d]-----",inNumOfHost);
    for(inNum =1 ;inNum <= inNumOfHost; inNum++)
    {
        if(inHDTRead(inNum) == d_OK)
        {
            if(strHDT.fHostEnable != TRUE)
						     continue;

			//display-host
			memset(szDisplayMsg, 0x00, sizeof(szDisplayMsg));
			sprintf(szDisplayMsg,"%s",strHDT.szHostLabel); 
			vdCTOS_DispStatusMessage(szDisplayMsg);
			//end

            vdDebug_LogPrintf("szAPName=[%s]-[%s]----",szAPName,strHDT.szAPName);
            if (strcmp(szAPName, strHDT.szAPName)!=0)
                continue;
						else
						{
							srTransRec.HDTid=strHDT.inHostIndex;
							
							inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);
							memcpy(srTransRec.szBatchNo, strMMT[0].szBatchNo, 4);
							
							inBatchNumOfRecord = inBatchNumRecord();
							
							DebugAddINT("batch record",inBatchNumOfRecord);
							if(inBatchNumOfRecord <= 0)
							{
									vdDisplayErrorMsg(1, 8, "EMPTY BATCH");
									continue;
							}

							vdCTOS_PrintMerchantSummaryReport();
							
							CTOS_LCDTClearDisplay();
							vdDispTitleString("SUMMARY REPORT");
						}
        }
    }
    return;	
}

void vdCTOS_PrintMerchantSummaryReport(void)
{
    unsigned char chkey;
    short shHostIndex;
    int inResult,i,inCount,inRet;
    int inTranCardType;
    int inReportType;
    int inBatchNumOfRecord;
    int *pinTransDataid;
    
    ACCUM_REC srAccumRec;
    BYTE baTemp[PAPER_X_SIZE * 64];
    char szStr[d_LINE_SIZE + 1];
    
    //int inRet = d_NO;
    int inNumOfHost = 0, inNum = 0;
    char szBcd[INVOICE_BCD_SIZE+1] = {0};
    char szErrMsg[31] = {0};
    char szAPName[25] = {0};
    int inAPPID = 0;
    BOOL fPrintDetail=FALSE;

		int inPADSize,x;
		char szSPACE[40];
		char szBuff[46]={0};
		char szBuff2[46];

		int inNumIITRec = 0;


   vdDebug_LogPrintf("vdCTOS_PrintMerchantSummaryReport");

   //test vdDisplayAnimateBmp(0,0, "Print1.bmp", "Print2.bmp", "Print3.bmp", NULL, NULL);

				memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
				if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
				{
						vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
						return; 	 
				}
		
			vdSetPrintThreadStatus(1); /*BDO:Display printing image during report -- sidumili*/
			
		//1105
				inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
				//vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);	 
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		//1105
			vdCTOSS_PrinterStart(100);
			CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
				
			ushCTOS_PrintHeader(0); 
		
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		
				//vdPrintTitleCenter("SUMMARY REPORT");
			//CTOS_PrinterFline(d_LINE_DOT * 1);
				vdCTOS_PrinterFline(1);
		
				//printHostLabel();
				
			printTIDMID(TRUE);
				
			printDateTime();
				
			printBatchNO();
		
			//CTOS_PrinterFline(d_LINE_DOT * 1);
			vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
			vdPrintCenter("SUMMARY REPORT");
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
			vdPrintCenter("*** TRANSACTION TOTALS BY ISSUER ***");
			//CTOS_PrinterFline(d_LINE_DOT * 1);
			vdCTOS_PrinterFline(1);

			vdDebug_LogPrintf("vdCTOS_PrintMerchantSummaryReport HDTid[%d]", srTransRec.HDTid);

			
			for(inTranCardType = 0; inTranCardType < 1 ;inTranCardType ++)
			{

				if(srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMGIFTCARD_HDT_INDEX)
					inTranCardType = 1;

				inReportType = PRINT_CARD_TOTAL;
				
				if(inReportType == PRINT_CARD_TOTAL)
				{
					//for(i= 0; i < 20; i ++ )
					inNumIITRec = inIITNumRecord();
					vdDebug_LogPrintf("vdCTOS_PrintMerchantSummaryReport inNumIITRec[%d]", inNumIITRec);
					
					//for(i= 0; i < 26; i ++ )//smac /*BDO: Ver9.0*/
					//for(i= 0; i < inNumIITRec; i ++ ) // orig code
					for(i= 0; i < 37; i ++ ) //00147 - No issuer name prints in summary report, settlement report and manual settlement report for BDO Loyalty
					{
						
						vdDebug_LogPrintf("Count[%d]usSaleCount[%d]", i, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount); 
						if((srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount == 0)
						&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount == 0)
						&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount == 0)
						&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount == 0)
		//issue:00269 - Print Issue totals even if Cash advance is the only transaction 
						&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount == 0)
						&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount == 0)
						/*&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulKitSaleTotalAmount == 0)
						&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRenewalTotalAmount == 0)
						&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulPtsAwardTotalAmount == 0)*/
						)
						{
						
						vdDebug_LogPrintf("vdCTOS_PrintMerchantSummaryReport continue"); 
							continue;
						}
						
						vdDebug_LogPrintf("CountHERE"); 
						inIITRead(i);
						memset(szStr, ' ', d_LINE_SIZE);
						memset (baTemp, 0x00, sizeof(baTemp));
						//strcpy(szStr,strIIT.szIssuerLabel);
		
								//sprintf(szBuff,"HOST%s%s",szSPACE,srTransRec.szHostLabel);
						sprintf(szStr,"ISSUER: %s",strIIT.szIssuerLabel);
		
						//sprintf(szBuff,"HOST:      %s",srTransRec.szHostLabel); /* BDO: Adjusted spacing for receipt -- jzg */
						
						inPrintLeftRight2(szStr,szBuff,41);
						


 
 							if (inCheckIfSMCardTransRec() == TRUE){
								#if 0
								vdCTOS_PrintAccumeByHostAndCard (inReportType, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount,	
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount,	
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
								(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 		
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount,
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount,	
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount);	
								#else
								vdCTOS_PrintSMAccumeByHostAndCard (inReportType, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount,	
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount,	
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
								(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 		
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount,
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount,	
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount,
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usKitSaleCount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulKitSaleTotalAmount,
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRenewalCount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRenewalTotalAmount,
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usPtsAwardCount, 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulPtsAwardTotalAmount
								);
								#endif

 							}else{
 								
								if(inCheckIfDCCHost() == TRUE)
	 								vdCTOS_DCCPrintAccumeByHostAndCard (inReportType, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i]);
								else
									vdCTOS_PrintAccumeByHostAndCard (inReportType, 
									/* BDO-00043: Add void count to sale and sale grand total - start -- end */ 				
									(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount) + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount,	
									/* BDO-00043: Add void count to sale and sale grand total - end -- end */ 				
									(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),	
									srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 
									//issue-00296-add void cash advance 				
									srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
									(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 		
									srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
									srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),	
									srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount));	
						
 							}
					}
					//SMAC
					
					if (inCheckIfSMCardTransRec() == TRUE)
						continue;
		
					//SMAC
					//after print issuer total, then print host toal
					{
						//CTOS_PrinterFline(d_LINE_DOT * 1);
						vdCTOS_PrinterFline(1);
						memset(szStr, ' ', d_LINE_SIZE);
						memset (baTemp, 0x00, sizeof(baTemp));
						strcpy(szStr,"GRAND TOTALS");
						//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
						//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
						inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

						if(inCheckIfDCCHost() == TRUE)
							vdCTOS_DCCPrintAccumeByHostAndCard (PRINT_HOST_TOTAL, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal);
						else
						    vdCTOS_PrintAccumeByHostAndCard (inReportType, 
							/* BDO-00043: Add void count to sale and sale grand total - start -- end */ 				
							(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount) +
								srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, 	
							/* BDO-00043: Add void count to sale and sale grand total - end -- end */ 				
		
							(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
							
							srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
		//issue-00296-add void cash advance 									
							srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
							(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
							
							srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
							
							srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
							
							srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount)
		
															);		
					}
				}
				else
				{


				
					memset(szStr, ' ', d_LINE_SIZE);
					memset (baTemp, 0x00, sizeof(baTemp));
					strcpy(szStr,srTransRec.szHostLabel);
					//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
					//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
					inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
					vdCTOS_PrintAccumeByHostAndCard (inReportType, 
						/* BDO-00043: Add void count to sale and sale grand total - start -- end */ 				
						(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount) +
							srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, 	
						/* BDO-00043: Add void count to sale and sale grand total - end -- end */ 				
		
						(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
						
						srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
		
							//issue-00296-add void cash advance 									
						srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
						(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
										
						srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
						
						srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
						
						srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount)
		
														);		
				}
			}
				
			//print space one line
			//CTOS_PrinterFline(d_LINE_DOT * 2);		
			//CTOS_PrinterFline(d_LINE_DOT * 2);
			//CTOS_PrinterFline(d_LINE_DOT * 2);
			vdCTOS_PrinterFline(6);

			vdCTOSS_PrinterEnd();
			vdSetPrintThreadStatus(0); /*BDO:Display printing image during report -- sidumili*/
			
			return; 
}

void SetReportTime(void)
{

  	BYTE szCurrTime[7] = {0};
  	CTOS_RTC rtcClock;
  	CTOS_RTC SetRTC;


	CTOS_RTCGet(&SetRTC);

    sprintf(szCurrTime,"%02d%02d%02d", SetRTC.bHour, SetRTC.bMinute, SetRTC.bSecond);

	wub_str_2_hex(szCurrTime,srTransRec.szTime,6);

	     
}

USHORT ushCTOS_PrintSMGuarantorBody_old(int page)
{	
    char szStr[d_LINE_SIZE + 3];
    char szTemp[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    char szTemp3[d_LINE_SIZE + 1];
    char szTemp4[d_LINE_SIZE + 1];
    char szTemp5[d_LINE_SIZE + 1];
    char szFormatPAN[strlen(srTransRec.szPAN) + 7];//to account for space as in PAN format and to include additional PAN no. 7 has been added -Meena 08/01/2012
    int inFmtPANSize;
    BYTE baTemp[PAPER_X_SIZE * 64];
    USHORT result;
    int num,i,inResult;
    unsigned char tucPrint [24*4+1];	
    BYTE   EMVtagVal[64];
    USHORT EMVtagLen; 
    short spacestring;
    BYTE   key;

	char szAmountBuff[20], szTemp6[47];
	int inPADSize,x;
	char szSPACE[40];
	char szPOSEntry[21] = {0};

	if(d_FIRST_PAGE == page)
	{
    	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    	printTIDMID(TRUE); 

		memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
		EMVtagLen = 0;
		memset(szStr, ' ', d_LINE_SIZE);
		vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);

		sprintf(szStr, "%s", srTransRec.szCardLable);
		vdMyEZLib_LogPrintf("Card label: %s",srTransRec.szCardLable);

		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

    	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		if (srTransRec.byEntryMode == CARD_ENTRY_WAVE){
			
			memset(szStr, 0x00, sizeof(szStr));
			strcpy(szStr, "CONTACTLESS");
			vdPrintCenter(szStr);
		}

		memset(szTemp5, 0x00, sizeof(szTemp5));
		vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp5);
		
		memset(szTemp6, 0x00, sizeof(szTemp6));
		memset(szTemp4, 0x00, sizeof(szTemp4));
		
		if (strlen(srTransRec.szPAN) > 16)
			vdRemoveSpace(szTemp6, szTemp5);		
		else
			strcpy(szTemp6, szTemp5);
				
		strcpy(szTemp4, szTemp6);
			
		//if (srTransRec.byEntryMode == CARD_ENTRY_MANUAL){
		//		strcat(szTemp4," *");
		//}

    	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		memset(szPOSEntry, 0x00, sizeof(szPOSEntry));

		switch(srTransRec.byEntryMode)
		{
			case CARD_ENTRY_MSR:
		   		strcat(szPOSEntry, "SWIPE");
			   	break;
			case CARD_ENTRY_MANUAL:
			   	strcat(szPOSEntry, "MANUAL");
			   	break;
			case CARD_ENTRY_ICC:
		 		strcat(szPOSEntry, "CHIP");   
			   	break;
			case CARD_ENTRY_FALLBACK:
			   	strcat(szPOSEntry, "FALLBACK");	 
			   	break;
		}
		
		//memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szTemp4, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);	
		inPrintLeftRight(szTemp4,szPOSEntry,42);

        //card holder name
        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		printCardHolderName();

		//Trans type
        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		memset(szStr, 0x00, sizeof(szStr));
		//szGetTransTitle(srTransRec.byTransType, szStr); 

		if (srTransRec.byTransType == SALE)
			strcpy(szStr, "SALE");
		else if (srTransRec.byTransType == BALANCE_INQUIRY)
			strcpy(szStr, "BALANCE INQUIRY");
		else if (srTransRec.byTransType == VOID)
			strcpy(szStr, "VOID");
			
			
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		
		/* Issue# 000096: BIN VER Checking - start -- jzg*/
		if (srTransRec.fBINVer)
		{
			//BIN Ver
			vdDebug_LogPrintf("fBINVer = [%d]", fBINVer);
			vdDebug_LogPrintf("BIN Ver STAN = [%s]", szBINVerSTAN);
			
			memset(szStr, 0, d_LINE_SIZE);
			memset(baTemp, 0, sizeof(baTemp)); //BDO: Fix for overlapping BIN Check line on receipt --sidumili
			vdCTOS_Pad_String(srTransRec.szBINVerSTAN, 6, '0', POSITION_LEFT);   //sidumili: modified using stTransRec to get record during reprint/void
			sprintf(szStr, "BIN CHECK: %s", srTransRec.szBINVerSTAN);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		/* Issue# 000096: BIN VER Checking - end -- jzg*/

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);
        
		printBatchInvoiceNO();

		printDateTime();

    
        if ((srTransRec.byTransType == SALE) || (srTransRec.byOrgTransType == SALE) || (srTransRec.byTransType == BALANCE_INQUIRY)){
			
			if (strTCT.fDutyFreeMode == TRUE){
		   		//Reference num
		   		sprintf(szStr, "REF. NO. %s", srTransRec.szRRN);
		   		memset (baTemp, 0x00, sizeof(baTemp));	   
		   		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		   		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			
		   		vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);  
		   		sprintf(szStr, "APPR. CODE: %s", srTransRec.szAuthCode);
		   		vdCTOS_Pad_String(szStr, 23, ' ', POSITION_LEFT);
		   		memset (baTemp, 0x00, sizeof(baTemp));	   
		   		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		   		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		   		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
			}else{
			 	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
			 if(strlen(srTransRec.szRRN) <= 0)
				 sprintf(szStr, "REF. NO.               APPR. CODE: %s",srTransRec.szAuthCode);
			 else
				sprintf(szStr, "REF. NO. %s  APPR. CODE: %s", srTransRec.szRRN,srTransRec.szAuthCode);
			 	memset (baTemp, 0x00, sizeof(baTemp)); 	 
			 	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			 	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			}

        }

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);

		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		memset(szTemp1, ' ', d_LINE_SIZE);
		memset(szTemp3, ' ', d_LINE_SIZE);
		wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szTipAmount, szTemp3, AMT_BCD_SIZE);

        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		//1025 - ADD OFFLINE SALE

		wub_hex_2_str(srTransRec.szTotalAmount, szTemp1, AMT_BCD_SIZE);


		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
			
		if (srTransRec.byTransType == BALANCE_INQUIRY)		
			strcpy(szTemp6,"BALANCE:");	
		else
			strcpy(szTemp6,"AMOUNT:");	
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216	
		
		if (srTransRec.byTransType == VOID)
			sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4); /*BDO: Negative sign on amount during void -- sidumili*/
		else
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			
		inPrintLeftRight(szTemp6,szAmountBuff,23);

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);


        if (srTransRec.byTransType == SALE_OFFLINE){

			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	

			memset(szTemp1, 0x00, sizeof(szTemp1));
			wub_hex_2_str(srTransRec.SmacPoints, szTemp1, AMT_BCD_SIZE);

			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"POINTS EARNED");	
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,42);
		
        }

		if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == VOID)){

			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
			memset(szTemp1, 0x00, sizeof(szTemp1));
				
			wub_hex_2_str(srTransRec.SmacBalance, szTemp1, AMT_BCD_SIZE);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"NEW BALANCE:");	
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			sprintf(szAmountBuff,"%s%s pts",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,42);



		}
		
		//CTOS_PrinterFline(d_LINE_DOT * 3);
		vdCTOS_PrinterFline(3);
		vdDebug_LogPrintf("sign 9");
		memset(szStr, 0x00, sizeof(szStr));
		strcpy(szStr, "SIGN:_____________________________________");
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);
    inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		//vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
		vdPrintCenter("   ***** BANK COPY *****  ");
		//CTOS_PrinterFline(d_LINE_DOT);
		vdCTOS_PrinterFline(1);
		vdPrintCenter("I PROMISE TO PAY THE TOTAL AMOUNT ABOVE");
		vdPrintCenter("AND OTHER CHARGES PURSUANT TO THE AGREE");
		vdPrintCenter("MENT/S GOVERNING USE OF THIS CARD, AND");
		vdPrintCenter("AUTHORIZE THE ISSUER OF THIS CARD TO PAY");
		vdPrintCenter("THE TOTAL AMOUNT ABOVE UPON PRESENTATION");
		//CTOS_PrinterFline(d_LINE_DOT * 6); 
		vdCTOS_PrinterFline(6);
	    	
	}
	else if(d_SECOND_PAGE == page)
	{
    	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    	printTIDMID(TRUE); 

		memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
		EMVtagLen = 0;
		memset(szStr, ' ', d_LINE_SIZE);
		vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);

		sprintf(szStr, "%s", srTransRec.szCardLable);
		vdMyEZLib_LogPrintf("Card label: %s",srTransRec.szCardLable);

		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

    	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		if (srTransRec.byEntryMode == CARD_ENTRY_WAVE){
			
			memset(szStr, 0x00, sizeof(szStr));
			strcpy(szStr, "CONTACTLESS");
			vdPrintCenter(szStr);
		}

		memset(szTemp5, 0x00, sizeof(szTemp5));
		vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp5);
		
		memset(szTemp6, 0x00, sizeof(szTemp6));
		memset(szTemp4, 0x00, sizeof(szTemp4));
		
		if (strlen(srTransRec.szPAN) > 16)
			vdRemoveSpace(szTemp6, szTemp5);		
		else
			strcpy(szTemp6, szTemp5);
				
		strcpy(szTemp4, szTemp6);
			
		//if (srTransRec.byEntryMode == CARD_ENTRY_MANUAL){
		//		strcat(szTemp4," *");
		//}
			
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		memset(szPOSEntry, 0x00, sizeof(szPOSEntry));
			
		switch(srTransRec.byEntryMode)
		{
			case CARD_ENTRY_MSR:
				strcat(szPOSEntry, "SWIPE");
				break;
			case CARD_ENTRY_MANUAL:
				strcat(szPOSEntry, "MANUAL");
				break;
			case CARD_ENTRY_ICC:
				strcat(szPOSEntry, "CHIP");   
				break;
			case CARD_ENTRY_FALLBACK:
				strcat(szPOSEntry, "FALLBACK");  
				break;
		}
			
		//memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szTemp4, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);	
		inPrintLeftRight(szTemp4,szPOSEntry,42);

        //card holder name
        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		printCardHolderName();

		//Trans type
        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		memset(szStr, 0x00, sizeof(szStr));
		//szGetTransTitle(srTransRec.byTransType, szStr); 

		if (srTransRec.byTransType == SALE)
			strcpy(szStr, "SALE");
		else if (srTransRec.byTransType == BALANCE_INQUIRY)
			strcpy(szStr, "BALANCE INQUIRY");
		else if (srTransRec.byTransType == VOID)
			strcpy(szStr, "VOID");

			
			
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		
		/* Issue# 000096: BIN VER Checking - start -- jzg*/
		if (srTransRec.fBINVer)
		{
			//BIN Ver
			vdDebug_LogPrintf("fBINVer = [%d]", fBINVer);
			vdDebug_LogPrintf("BIN Ver STAN = [%s]", szBINVerSTAN);
			
			memset(szStr, 0, d_LINE_SIZE);
			memset(baTemp, 0, sizeof(baTemp)); //BDO: Fix for overlapping BIN Check line on receipt --sidumili
			vdCTOS_Pad_String(srTransRec.szBINVerSTAN, 6, '0', POSITION_LEFT);   //sidumili: modified using stTransRec to get record during reprint/void
			sprintf(szStr, "BIN CHECK: %s", srTransRec.szBINVerSTAN);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		/* Issue# 000096: BIN VER Checking - end -- jzg*/

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);
        
		printBatchInvoiceNO();

		printDateTime();

    
	if ((srTransRec.byTransType == SALE) || (srTransRec.byOrgTransType == SALE) || (srTransRec.byTransType == BALANCE_INQUIRY)){
		if (strTCT.fDutyFreeMode == TRUE){
			//Reference num
			sprintf(szStr, "REF. NO. %s", srTransRec.szRRN);
			memset (baTemp, 0x00, sizeof(baTemp));	   
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		
			vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);	
			sprintf(szStr, "APPR. CODE: %s", srTransRec.szAuthCode);
			vdCTOS_Pad_String(szStr, 23, ' ', POSITION_LEFT);
			memset (baTemp, 0x00, sizeof(baTemp));	   
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		}else{
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		 if(strlen(srTransRec.szRRN) <= 0)
			 sprintf(szStr, "REF. NO.				APPR. CODE: %s",srTransRec.szAuthCode);
		 else
			sprintf(szStr, "REF. NO. %s  APPR. CODE: %s", srTransRec.szRRN,srTransRec.szAuthCode);
			memset (baTemp, 0x00, sizeof(baTemp));	 
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
        }

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);

		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		memset(szTemp1, ' ', d_LINE_SIZE);
		memset(szTemp3, ' ', d_LINE_SIZE);
		wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szTipAmount, szTemp3, AMT_BCD_SIZE);

        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		//1025 - ADD OFFLINE SALE

		wub_hex_2_str(srTransRec.szTotalAmount, szTemp1, AMT_BCD_SIZE);

		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
			
		if (srTransRec.byTransType == BALANCE_INQUIRY)		
			strcpy(szTemp6,"BALANCE:");	
		else
			strcpy(szTemp6,"AMOUNT:");	
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216	

		if (srTransRec.byTransType == VOID)
			sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4); /*BDO: Negative sign on amount during void -- sidumili*/
		else
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
		
		inPrintLeftRight(szTemp6,szAmountBuff,23);

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);


        if (srTransRec.byTransType == SALE_OFFLINE){

			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	

			memset(szTemp1, 0x00, sizeof(szTemp1));
			wub_hex_2_str(srTransRec.SmacPoints, szTemp1, AMT_BCD_SIZE);

			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"POINTS EARNED");	
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,42);
		
        }

		if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == VOID)){

			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
			memset(szTemp1, 0x00, sizeof(szTemp1));
				
			wub_hex_2_str(srTransRec.SmacBalance, szTemp1, AMT_BCD_SIZE);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"NEW BALANCE:");	
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			sprintf(szAmountBuff,"%s%s pts",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,42);



		}


		//CTOS_PrinterFline(d_LINE_DOT * 2);
		vdCTOS_PrinterFline(2);
		vdPrintCenter("   ***** CUSTOMER COPY *****  ");
		//CTOS_PrinterFline(d_LINE_DOT);
		vdCTOS_PrinterFline(1);
		vdPrintCenter("I PROMISE TO PAY THE TOTAL AMOUNT ABOVE");
		vdPrintCenter("AND OTHER CHARGES PURSUANT TO THE AGREE");
		vdPrintCenter("MENT/S GOVERNING USE OF THIS CARD, AND");
		vdPrintCenter("AUTHORIZE THE ISSUER OF THIS CARD TO PAY");
		vdPrintCenter("THE TOTAL AMOUNT ABOVE UPON PRESENTATION");
		//CTOS_PrinterFline(d_LINE_DOT * 6);
		vdCTOS_PrinterFline(6);
		
	}

	else if(d_THIRD_PAGE == page)
	{
    	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    	printTIDMID(FALSE); 

		memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
		EMVtagLen = 0;
		memset(szStr, ' ', d_LINE_SIZE);
		vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);

		sprintf(szStr, "%s", srTransRec.szCardLable);
		vdMyEZLib_LogPrintf("Card label: %s",srTransRec.szCardLable);

		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

    	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		if (srTransRec.byEntryMode == CARD_ENTRY_WAVE){
			
			memset(szStr, 0x00, sizeof(szStr));
			strcpy(szStr, "CONTACTLESS");
			vdPrintCenter(szStr);
		}

		memset(szTemp5, 0x00, sizeof(szTemp5));
		vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp5);
		
		memset(szTemp6, 0x00, sizeof(szTemp6));
		memset(szTemp4, 0x00, sizeof(szTemp4));
		
		if (strlen(srTransRec.szPAN) > 16)
			vdRemoveSpace(szTemp6, szTemp5);		
		else
			strcpy(szTemp6, szTemp5);
				
		strcpy(szTemp4, szTemp6);
			
		//if (srTransRec.byEntryMode == CARD_ENTRY_MANUAL){
		//		strcat(szTemp4," *");
		//}
			
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		memset(szPOSEntry, 0x00, sizeof(szPOSEntry));
			
		switch(srTransRec.byEntryMode)
		{
			case CARD_ENTRY_MSR:
				strcat(szPOSEntry, "SWIPE");
				break;
			case CARD_ENTRY_MANUAL:
				strcat(szPOSEntry, "MANUAL");
				break;
			case CARD_ENTRY_ICC:
				strcat(szPOSEntry, "CHIP");   
				break;
			case CARD_ENTRY_FALLBACK:
				strcat(szPOSEntry, "FALLBACK");  
				break;
		}
			
		//memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szTemp4, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);	
		inPrintLeftRight(szTemp4,szPOSEntry,42);
		
        //card holder name
        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		printCardHolderName();

		//Trans type
        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

		memset(szStr, 0x00, sizeof(szStr));
		//szGetTransTitle(srTransRec.byTransType, szStr); 

		if (srTransRec.byTransType == SALE)
			strcpy(szStr, "SALE");
		else if (srTransRec.byTransType == BALANCE_INQUIRY)
			strcpy(szStr, "BALANCE INQUIRY");
		else if (srTransRec.byTransType == VOID)
			strcpy(szStr, "VOID");

			
			
		memset (baTemp, 0x00, sizeof(baTemp));
		//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		
		/* Issue# 000096: BIN VER Checking - start -- jzg*/
		if (srTransRec.fBINVer)
		{
			//BIN Ver
			vdDebug_LogPrintf("fBINVer = [%d]", fBINVer);
			vdDebug_LogPrintf("BIN Ver STAN = [%s]", szBINVerSTAN);
			
			memset(szStr, 0, d_LINE_SIZE);
			memset(baTemp, 0, sizeof(baTemp)); //BDO: Fix for overlapping BIN Check line on receipt --sidumili
			vdCTOS_Pad_String(srTransRec.szBINVerSTAN, 6, '0', POSITION_LEFT);   //sidumili: modified using stTransRec to get record during reprint/void
			sprintf(szStr, "BIN CHECK: %s", srTransRec.szBINVerSTAN);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
		/* Issue# 000096: BIN VER Checking - end -- jzg*/

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);
        
		printBatchInvoiceNO();

		printDateTime();

    
	if ((srTransRec.byTransType == SALE) || (srTransRec.byOrgTransType == SALE) || (srTransRec.byTransType == BALANCE_INQUIRY)){
		if (strTCT.fDutyFreeMode == TRUE){
			//Reference num
			sprintf(szStr, "REF. NO. %s", srTransRec.szRRN);
			memset (baTemp, 0x00, sizeof(baTemp));	   
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		
			vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);	
			sprintf(szStr, "APPR. CODE: %s", srTransRec.szAuthCode);
			vdCTOS_Pad_String(szStr, 23, ' ', POSITION_LEFT);
			memset (baTemp, 0x00, sizeof(baTemp));	   
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		}else{
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		 if(strlen(srTransRec.szRRN) <= 0)
			 sprintf(szStr, "REF. NO.				APPR. CODE: %s",srTransRec.szAuthCode);
		 else
			sprintf(szStr, "REF. NO. %s  APPR. CODE: %s", srTransRec.szRRN,srTransRec.szAuthCode);
			memset (baTemp, 0x00, sizeof(baTemp));	 
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		}
     }

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);
		
		memset(szStr, ' ', d_LINE_SIZE);
		memset(szTemp, ' ', d_LINE_SIZE);
		memset(szTemp1, ' ', d_LINE_SIZE);
		memset(szTemp3, ' ', d_LINE_SIZE);
		wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szTipAmount, szTemp3, AMT_BCD_SIZE);

        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		//1025 - ADD OFFLINE SALE

		wub_hex_2_str(srTransRec.szTotalAmount, szTemp1, AMT_BCD_SIZE);

		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
			
		if (srTransRec.byTransType == BALANCE_INQUIRY)		
			strcpy(szTemp6,"BALANCE:");	
		else
			strcpy(szTemp6,"AMOUNT:");	
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		

		if (srTransRec.byTransType == VOID)
			sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4); /*BDO: Negative sign on amount during void -- sidumili*/
		else
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
		
		inPrintLeftRight(szTemp6,szAmountBuff,23);

		//CTOS_PrinterFline(d_LINE_DOT * 1);
		vdCTOS_PrinterFline(1);


        if (srTransRec.byTransType == SALE_OFFLINE){

			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	

			memset(szTemp1, 0x00, sizeof(szTemp1));
			wub_hex_2_str(srTransRec.SmacPoints, szTemp1, AMT_BCD_SIZE);

			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"POINTS EARNED");	
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,42);
		
        }

		if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == VOID)){

			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
			memset(szTemp1, 0x00, sizeof(szTemp1));
				
			wub_hex_2_str(srTransRec.SmacBalance, szTemp1, AMT_BCD_SIZE);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"NEW BALANCE:");	
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
			sprintf(szAmountBuff,"%s%s pts",strCST.szCurSymbol,szTemp4);
			inPrintLeftRight(szTemp6,szAmountBuff,42);



		}
	
	//CTOS_PrinterFline(d_LINE_DOT * 3);
	vdCTOS_PrinterFline(3);

	vdDebug_LogPrintf("sign 10");
	memset(szStr, 0x00, sizeof(szStr));
	strcpy(szStr, "SIGN:_____________________________________");
	memset (baTemp, 0x00, sizeof(baTemp));
	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	//vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
	vdPrintCenter("   ***** MERCHANT COPY *****  ");
	//CTOS_PrinterFline(d_LINE_DOT);
	vdCTOS_PrinterFline(1);
	vdPrintCenter("I PROMISE TO PAY THE TOTAL AMOUNT ABOVE");
	vdPrintCenter("AND OTHER CHARGES PURSUANT TO THE AGREE");
	vdPrintCenter("MENT/S GOVERNING USE OF THIS CARD, AND");
	vdPrintCenter("AUTHORIZE THE ISSUER OF THIS CARD TO PAY");
	vdPrintCenter("THE TOTAL AMOUNT ABOVE UPON PRESENTATION");
  //CTOS_PrinterFline(d_LINE_DOT * 6);
  vdCTOS_PrinterFline(6);
	
	}

	return d_OK;	
	
}


int inCTOS_PRINT_SUMMARY_SELECTION(void)
{
    int inRet = d_OK;
    char szDebug[40 + 1]={0};
    char szChoiceMsg[30 + 1];
    char szHeaderString[24+1];
    int bHeaderAttr = 0x01+0x04;
    BYTE key = 0; 

    inTCTRead(1);

	vdDebug_LogPrintf("inCTOS_PRINT_SUMMARY_SELECTION");
	
		
    if(strTCT.fPrintSummaryAll == TRUE)
    {
        memset(szChoiceMsg, 0x00, sizeof(szChoiceMsg));
        
        strcpy(szHeaderString, "REPORT");
        strcat(szChoiceMsg,"SINGLE \n");
        strcat(szChoiceMsg,"ALL");
        
        inSetColorMenuMode();
        //key = MenuDisplay(szHeaderString,strlen(szHeaderString), bHeaderAttr, 1, 1, szChoiceMsg, TRUE);
        key = MenuDisplayEx(szHeaderString, strlen(szHeaderString), bHeaderAttr, 1, 1, szChoiceMsg, TRUE, 30); /*Menu with timeout parameter*/
        vdDebug_LogPrintf("::inCTOS_SelectAccountType::MenuDisplayEx::key[%d]", key);
        inSetTextMode();
        
        if (key > 0)
        {
            if(key == 1)
            {
                inCTOS_PRINTF_SUMMARY();
            }
            else if(key == 2)
            {
                inCTOS_PRINT_SUMMARY_ALL();
            }
            else if(key == d_KBD_CANCEL)
            {
                inRet = d_NO;
            } 
            else if (key == 0xFF) /*BDO: For timeout occured -- sidumili*/
            {
                inRet = d_NO;
            }
        }
        else
        {
            inRet = d_NO;
        }			
    }
		else	
			inCTOS_PRINTF_SUMMARY();
		
    return inRet;
}

int inCTOS_PRINT_DETAIL_SELECTION(void)
{
    int inRet = d_OK;
    char szDebug[40 + 1]={0};
    char szChoiceMsg[30 + 1];
    char szHeaderString[24+1];
    int bHeaderAttr = 0x01+0x04;
    BYTE key = 0; 

    inTCTRead(1);
		
    if(strTCT.fPrintDetailAll == TRUE)
    {
        memset(szChoiceMsg, 0x00, sizeof(szChoiceMsg));
        
        strcpy(szHeaderString, "REPORT");
        strcat(szChoiceMsg,"SINGLE \n");
        strcat(szChoiceMsg,"ALL");
        
        inSetColorMenuMode();
        //key = MenuDisplay(szHeaderString,strlen(szHeaderString), bHeaderAttr, 1, 1, szChoiceMsg, TRUE);
        key = MenuDisplayEx(szHeaderString, strlen(szHeaderString), bHeaderAttr, 1, 1, szChoiceMsg, TRUE, 30); /*Menu with timeout parameter*/
        vdDebug_LogPrintf("::inCTOS_SelectAccountType::MenuDisplayEx::key[%d]", key);
        inSetTextMode();
        
        if (key > 0)
        {
            if(key == 1)
            {
                inCTOS_PRINTF_DETAIL();
            }
            else if(key == 2)
            {
                inCTOS_PRINT_DETAIL_ALL();
            }
            else if(key == d_KBD_CANCEL)
            {
                inRet = d_NO;
            } 
            else if (key == 0xFF) /*BDO: For timeout occured -- sidumili*/
            {
                inRet = d_NO;
            }
        }
        else
        {
            inRet = d_NO;
        }			
    }
		else	
			inCTOS_PRINTF_DETAIL();
		
    return inRet;
}

void printCardHolderNameV10(void)	// v10.0 change
{
    USHORT shLen;
    char szStr[d_LINE_SIZE + 1];
    BYTE baTemp[PAPER_X_SIZE * 64];

	vdTrimSpaces(srTransRec.szCardholderName);
	
    shLen = strlen(srTransRec.szCardholderName);

    if(shLen > 0)
    {
        memset(szStr, 0x00, d_LINE_SIZE);
		if (shLen > 30) 	
			memcpy(szStr, srTransRec.szCardholderName, CARD_HOLD_NAME_DIGITS); 
		else
			memcpy(szStr, srTransRec.szCardholderName, shLen); 

        //while(0x20 == szStr[--shLen] && shLen >= 0)
        //    szStr[shLen] = 0x00;

        //if (shLen > 20){	
			//vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
			vdPrintCenter(szStr);
			//vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
			
		//}else{
		//	vdPrintCenter(szStr);
		//}
    }
}

USHORT ushCTOS_PrintSMHeader(int page)
{	
    
	//print Logo	
	vdCTOSS_PrinterBMPPic(0, 0, strTCT.szSMReceiptLogo);

	if(fRePrintFlag == TRUE)
    {   
        vdDebug_LogPrintf("srTransRec.HDTid[%d] srTransRec.MITid[%d]",srTransRec.HDTid, srTransRec.MITid);
		if ( inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid) != d_OK)
        {
            vdSetErrorMessage("LOAD MMT ERR");
            return(d_NO);
        }
        vdDebug_LogPrintf("srTransRec.HDTid[%d] srTransRec.MITid[%d] strMMT[0].szRctHdr1[%s]",srTransRec.HDTid, srTransRec.MITid, strMMT[0].szRctHdr1);
    }
  //aaronnino for BDOCLG ver 9.0 fix on issue #00085 All Header lines are not printing on the first host info report start
	if(strlen(strMMT[0].szRctHdr1) <= 0)
		 inMMTReadRecord(1,1);
	//aaronnino for BDOCLG ver 9.0 fix on issue #00085 All Header lines are not printing on the first host info report end
	
    vdPrintHeaderText();

	//issue-00420
	if (strlen(strTCT.szAppVersionHeader) > 0)
		vdPrintCenter(strTCT.szAppVersionHeader);

    if(fRePrintFlag == TRUE)
    {
        vdSetGolbFontAttrib(d_FONT_24x24, DOUBLE_SIZE, NORMAL_SIZE, 0, 0);
        vdPrintCenterReverseMode("DUPLICATE");
    }

    if(VS_TRUE == strTCT.fDemo)
    {
        ushCTOS_PrintDemo();
    }

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    
	return d_OK;
}

USHORT ushCTOS_PrintSMBody(int page)
{	
	char szStr[d_LINE_SIZE + 1];
	char szTemp[d_LINE_SIZE + 1];
	char szTemp1[d_LINE_SIZE + 1];
	char szTemp2[d_LINE_SIZE + 1];	
	char szTemp3[d_LINE_SIZE + 1];
	char szTemp4[d_LINE_SIZE + 1];
	char szTemp5[d_LINE_SIZE + 1];
	char szTempDate[d_LINE_SIZE + 1];
	char szFormatPAN[strlen(srTransRec.szPAN) + 7];//to account for space as in PAN format and to include additional PAN no. 7 has been added -Meena 08/01/2012
	int inFmtPANSize;
	BYTE baTemp[PAPER_X_SIZE * 64];
	USHORT result;
	int num,i,inResult;
	unsigned char tucPrint [24*4+1];	
	BYTE   EMVtagVal[64+1];
	USHORT EMVtagLen; 
	short spacestring;
	BYTE   key;

	char szAmountBuff[20+1], szTemp6[47+1];

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	
    printDateTime();
	
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "MERCHANT ID  : %s", srTransRec.szMID);
	inPrint(szStr);
	
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "TERMINAL ID  : %s", srTransRec.szTID);
	inPrint(szStr);
	
	memset(szTemp,0x00, sizeof(szTemp));
	wub_hex_2_str(srTransRec.szBatchNo,szTemp,3);
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "BATCH NUM    : %s", szTemp);
	inPrint(szStr);
		
	memset(szTemp,0x00, sizeof(szTemp));
	wub_hex_2_str(srTransRec.szInvoiceNo,szTemp,3);
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "INVOICE NUM  : %s", szTemp);
	inPrint(szStr);

	if(srTransRec.fBINVer)
	{
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "BIN CHECK    : %06ld", atol(srTransRec.szBINVerSTAN));
		inPrint(szStr);
	}
	
	szGetTransTitle(srTransRec.byTransType, szStr);  
	//gcitra-012315
	if(srTransRec.byTransType == SALE){
		memset(szStr, 0x00, sizeof(szStr));
		if(srTransRec.byEntryMode == CARD_ENTRY_WAVE)
		    strcpy(szStr,"Contactless Sale");
		else
		    strcpy(szStr,"Sale");
	}else if(srTransRec.byTransType == VOID){
		memset(szStr, 0x00, sizeof(szStr));
		if(srTransRec.byEntryMode == CARD_ENTRY_WAVE)
		    strcpy(szStr,"Contactless Void");
		else
			strcpy(szStr,"Void Sale");
	}
	
    //vdSetGolbFontAttrib(d_FONT_24x24, DOUBLE_SIZE, NORMAL_SIZE, 0, 0);
    vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	if(srTransRec.byTransType != VOID)
        //vdPrintTitleCenter(szStr);
        vdPrintCenter(szStr);
	else
	    vdPrintCenterReverseMode(szStr);
	
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
	EMVtagLen = 0;
	memset(szStr, ' ', d_LINE_SIZE);
	vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);
	
    memset(szTemp, 0x00, sizeof(szTemp)); 
    if(page == BANK_COPY_RECEIPT) /*bank copy*/
        vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp);
    else if(page == CUSTOMER_COPY_RECEIPT) /*customer copy*/
        vdCTOS_FormatPAN2(strIIT.szMaskCustomerCopy, srTransRec.szPAN, szTemp);		
    else if(page == MERCHANT_COPY_RECEIPT) /*merchant copy*/
        vdCTOS_FormatPAN2(strIIT.szMaskMerchantCopy, srTransRec.szPAN, szTemp);

	memset(szTemp2, 0x00, sizeof(szTemp2)); 
	sprintf(szTemp2, "CARD NUM     : %s", szTemp);
	
	memset(szTemp3, 0x00, sizeof(szTemp3));
	if(srTransRec.byEntryMode==CARD_ENTRY_ICC)
		strcpy(szTemp3,"C");
	else if(srTransRec.byEntryMode==CARD_ENTRY_MANUAL)
		strcpy(szTemp3,"M");
	else if(srTransRec.byEntryMode==CARD_ENTRY_MSR)
		strcpy(szTemp3,"S");
	else if(srTransRec.byEntryMode==CARD_ENTRY_FALLBACK){
		if((srTransRec.szServiceCode[0] == '2') || (srTransRec.szServiceCode[0] == '6'))
			strcat(szTemp3, "F");  
		else			
			strcat(szTemp3, "S");
	}
	inPrintLeftRight(szTemp2, szTemp3, 42);

	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "CARD TYPE    : %s", srTransRec.szCardLable);
	inPrint(szStr);
	
	//aaronnino for BDOCLG ver 9.0 fix on issue #00066 "APPR.CODE" single width printed on transaction receipt 6 of 8 start
    memset(szStr, 0x00, d_LINE_SIZE);
    sprintf(szStr, "APPR CODE    : %s", srTransRec.szAuthCode); 
	inPrint(szStr);

	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "REF NUM      : %s", srTransRec.szRRN);
	inPrint(szStr);

	memset(szTemp, 0x00, d_LINE_SIZE);
	memset(szTemp1, 0x00, d_LINE_SIZE);
	wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
	wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
	
	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	memset(szAmountBuff,0x00,sizeof(szAmountBuff));
	memset(szTemp2, 0x00, sizeof(szTemp2));
	
	memset(szStr,0x00, sizeof(szStr));
	strcpy(szStr,"AMOUNT");
	
	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp, szTemp2);		
	if (srTransRec.byTransType == VOID)
		sprintf(szAmountBuff,"-%s %s", strCST.szCurSymbol, szTemp2);
	else
		sprintf(szAmountBuff,"%s %s", strCST.szCurSymbol, szTemp2);
	
	inPrintLeftRight(szStr,szAmountBuff,24);
	//CTOS_PrinterFline(d_LINE_DOT );

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	memset(szStr, ' ', d_LINE_SIZE);
	memset(szTemp, ' ', d_LINE_SIZE);
	if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
	/* EMV: Revised EMV details printing - start -- jzg */
	//(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
	(srTransRec.bWaveSID == 0x63) ||
	(srTransRec.bWaveSID == 0x65) ||
	(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
	(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
	(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC) ||
	(srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
	(srTransRec.bWaveSID == d_VW_SID_CUP_EMV))

	
	/* EMV: Revised EMV details printing - end -- jzg */
	{
		//CTOS_PrinterFline(d_LINE_DOT);
		vdCTOS_PrinterFline(1);
		//APP
		memset(szStr, ' ', d_LINE_SIZE);
		sprintf(szStr, "APP.         : %s", srTransRec.stEMVinfo.szChipLabel);
		inPrint(szStr);
		
		//AC
		wub_hex_2_str(srTransRec.stEMVinfo.T9F26, szTemp, 8);
		sprintf(szStr, "TC           : %s", szTemp);
		inPrint(szStr);
		
		//AID
		memset(szStr, ' ', d_LINE_SIZE);
		EMVtagLen = srTransRec.stEMVinfo.T84_len;
		memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
		memcpy(EMVtagVal, srTransRec.stEMVinfo.T84, EMVtagLen);
		memset(szTemp, ' ', d_LINE_SIZE);
		wub_hex_2_str(EMVtagVal, szTemp, EMVtagLen);
		sprintf(szStr, "AID          : %s",szTemp);
		inPrint(szStr);			  
	}
	
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	vdCTOS_PrinterFline(1);

	return d_OK;
}

USHORT ushCTOS_PrintSMFooter(int page)
{		
	BYTE EMVtagVal[64] = {0};
	USHORT EMVtagLen = 0; 
    BYTE baTemp[PAPER_X_SIZE * 64];
    char szStr[d_LINE_SIZE + 3];
	int fNSRflag = 0;

    //version16
    BYTE szTag[3+1];
	BYTE szTagLen[2+1];
	int inTaglen;
	BYTE szTagValue[100+1];
	int inTotalLen;
	//version16


	fNSRflag = inNSRFlag();

    memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
    EMVtagLen = 0;
    
    DebugAddINT("ushCTOS_PrintFooter,mode",srTransRec.byEntryMode);  
    
    vdDebug_LogPrintf("CVM [%02X %02X %02X]",
    srTransRec.stEMVinfo.T9F34[0], srTransRec.stEMVinfo.T9F34[1], srTransRec.stEMVinfo.T9F34[2]);
    vdDebug_LogPrintf("srTransRec.byEntryMode = [%d]", srTransRec.byEntryMode);
    if((page != CUSTOMER_COPY_RECEIPT) && (srTransRec.byTransType!=VOID) && srTransRec.byEntryMode != CARD_ENTRY_WAVE && srTransRec.HDTid != SMAC_HDT_INDEX)//WAVE TO COVER ALL SMAC CTLS TXNS.
		//(srTransRec.byTransType != KIT_SALE) && (srTransRec.byTransType != RENEWAL) && (srTransRec.byTransType != PTS_AWARDING))
    {	
        //version 11 - should still check 9f34 even if NSR flag is OFF
		//if(strIIT.fNSR == 1 && srTransRec.fDCC != TRUE)
		if(srTransRec.fDCC != TRUE && inCheckIfSMCardTransRec() != TRUE)
		{
            if(fNSRflag == 1)
            {	
            	vdDebug_LogPrintf("no signature 7");
                vdCTOS_PrinterFline(1);
                vdPrintCenter("*****NO SIGNATURE REQUIRED*****");
            }
			else
			{
                vdCTOS_PrinterFline(1);
                inCCTOS_PrinterBufferOutput("__________________________________________",&stgFONT_ATTRIB,1);
                inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
                vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
                printCardHolderNameV10();			
			}
		}
		else
		{

#if 0		
            if(srTransRec.byEntryMode == CARD_ENTRY_ICC)
            {
                EMVtagLen = 3;
                memcpy(EMVtagVal, srTransRec.stEMVinfo.T9F34, EMVtagLen);
                
                //EMV: Fix for noCVM during above floor limit scenario - start -- jzg
                vdDebug_LogPrintf("EMVtagVal [%02X %02X %02X]", EMVtagVal[0], EMVtagVal[1], EMVtagVal[2]);
                
                // patrick add code 20141208
                if (((EMVtagVal[0] != 0x03) && (EMVtagVal[0] != 0x05) &&
                (EMVtagVal[0] != 0x1E) &&
                (EMVtagVal[0] != 0x5E)) || (EMVtagVal[0] == 0x3F))
                //EMV: Fix for noCVM during above floor limit scenario - end -- jzg
                {
                    if (memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x03\x33",5) == 0)
                    {
                        //for CUP must signature
                        if((page == BANK_COPY_RECEIPT) || (page == MERCHANT_COPY_RECEIPT)) /*bank and merchant copy*/
                        {
                            //CTOS_PrinterFline(d_LINE_DOT * 2);
							              vdCTOS_PrinterFline(2); 
        					//CTOS_PrinterPutString("_______________________________");
							inCCTOS_PrinterBufferOutput("__________________________________________",&stgFONT_ATTRIB,1);
							inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
                            vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
                            printCardHolderNameV10();//printCardHolderName();// v10.0 change
                        }
                    }
                    else
                    {
                        vdCTOS_PrinterFline(1);     
                        if(EMVtagVal[0] & 0x01 || EMVtagVal[0] & 0x02 || EMVtagVal[0] & 0x04) /*offline or online*/
                            vdPrintCenter("PIN VERIFICATION SUCCESSFUL");
                        else
                            vdPrintCenter("*****NO SIGNATURE REQUIRED*****");											
                    }
                }
                else
                {
                    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 7 of 13
                    if((page == BANK_COPY_RECEIPT) || (page == MERCHANT_COPY_RECEIPT)) /*bank and merchant copy*/
                    {
                        //CTOS_PrinterFline(d_LINE_DOT * 2);
						            vdCTOS_PrinterFline(1);    ;
                        //CTOS_PrinterPutString("_______________________________");
						inCCTOS_PrinterBufferOutput("__________________________________________",&stgFONT_ATTRIB,1);
						inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
                        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
                        printCardHolderNameV10();//printCardHolderName();// v10.0 change
                    }
                }
            }

            else if (srTransRec.byEntryMode == CARD_ENTRY_WAVE)
            {
                if(srTransRec.bWaveSCVMAnalysis != d_CVM_REQUIRED_SIGNATURE)
                {
                    if (srTransRec.bWaveSID == d_VW_SID_AE_EMV && srTransRec.bWaveSCVMAnalysis == d_CVM_REQUIRED_NONE)
                    {
                        if((page == BANK_COPY_RECEIPT) || (page == MERCHANT_COPY_RECEIPT))
                        {
                           if (srTransRec.byTransType != VOID)
                           {
                               vdCTOS_PrinterFline(2);   
                               memset(szStr, 0x00, sizeof(szStr));
                               strcpy(szStr, "SIGN:_____________________________________");
                               memset (baTemp, 0x00, sizeof(baTemp));
                               //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
                               // CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);
                               inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
                               inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
                           }
                        }
                        else
                            //CTOS_PrinterFline(d_LINE_DOT);
						                vdCTOS_PrinterFline(1);
                    }
                    else
                    {
                        vdCTOS_PrinterFline(1);
                        vdPrintCenter("*****NO SIGNATURE REQUIRED*****");
                    }
                }
                else
                {
                    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 8 of 21
                    if((page == BANK_COPY_RECEIPT) || (page == MERCHANT_COPY_RECEIPT))
                    {
                        if (srTransRec.byTransType != VOID)
                        {
                            vdCTOS_PrinterFline(2);
                            memset(szStr, 0x00, sizeof(szStr));
                            strcpy(szStr, "SIGN:_____________________________________");
                            memset (baTemp, 0x00, sizeof(baTemp));
                            //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
                            //CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);
                            inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
                            inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
                        }
                    }
                    else
                       // CTOS_PrinterFline(d_LINE_DOT);
					             vdCTOS_PrinterFline(1);
                    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 8 of 21
                }
            }

            else
#endif
            {
                if((page == BANK_COPY_RECEIPT || page == MERCHANT_COPY_RECEIPT) && srTransRec.byTransType != SMAC_BALANCE && srTransRec.byTransType != VOID && srTransRec.HDTid != SMGIFTCARD_HDT_INDEX) /*bank and merchant copy*/
                {
                     //CTOS_PrinterFline(d_LINE_DOT * 2);
                     vdCTOS_PrinterFline(2);     
                     //CTOS_PrinterPutString("_______________________________");
                     inCCTOS_PrinterBufferOutput("__________________________________________",&stgFONT_ATTRIB,1);
                     inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
                     vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
                     if(inCheckIfSMCardTransRec() == TRUE)
                     {
                        if(srTransRec.HDTid == SMECARD_HDT_INDEX)
                        {
                        
	                        if(srTransRec.fPrintSMCardHolder == TRUE)// Received DE63 from host
	                            vdPrintCenter("CARDHOLDER'S SIGNATURE");
	                        else
	                        {
	                            printCardHolderNameV10();
	                        }
                        }
                        else
                            vdPrintCenter("CARDHOLDER'S SIGNATURE");
                     }
                     else
                     printCardHolderNameV10();//printCardHolderName();// v10.0 change
                }
            }
		}
    }
	
    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	
    if(page == BANK_COPY_RECEIPT)
        vdPrintCenter("--- BANK'S COPY ---");
    else if(page == CUSTOMER_COPY_RECEIPT)
        vdPrintCenter("--- CUSTOMER'S COPY ---");
    else if(page == MERCHANT_COPY_RECEIPT)
        vdPrintCenter("--- MERCHANT'S COPY ---");

    //testlang
			//vdCTOSS_PrinterEnd();
			//vdCTOS_PrinterFline(1);
			//CTOS_PrinterCode39Barcode(30,1,"*TEST8052*",10,2,3,TRUE);   
		 	//vdCTOSS_PrinterStart(100);
	//testlang
//version16
	vdDebug_LogPrintf("BARCODE TEST HDT %d tran %d",srTransRec.HDTid ,srTransRec.byTransType);
	if ((srTransRec.HDTid == SMAC_HDT_INDEX && srTransRec.byTransType == SALE  && fSmacScan == TRUE) ||
		( srTransRec.HDTid == SMAC_HDT_INDEX && srTransRec.byTransType == SMAC_BALANCE)){

		vdDebug_LogPrintf("testlang print barcode");
		//vdLineFeed(1);
		vdPrintCenter("");
		vdCTOSS_PrinterEnd();
		vdCTOSS_PrinterStart(100);
        vdDebug_LogPrintf("testlang barcode %s", srTransRec.szBarcodeText);
		if (strlen(srTransRec.szBarcodeText) > 0){
			inTotalLen=0;
	    	//get tag 
	    	vdDebug_LogPrintf("print footer 1");
			memset(szTag, 0x00, sizeof(szTag));
			memcpy(szTag, &srTransRec.szBarcodeText[inTotalLen],3);
			inTotalLen=inTotalLen+3;
			vdDebug_LogPrintf("tag name %s", szTag);

			//get length
			vdDebug_LogPrintf("print footer 2");
			memset(szTagLen, 0x00, sizeof(szTagLen));
			memcpy(szTagLen, &srTransRec.szBarcodeText[inTotalLen],2);
			inTotalLen=inTotalLen+2;
			inTaglen = atoi(szTagLen);
			vdDebug_LogPrintf("tag len %s-%d", szTag, inTaglen);
			

            //get value
            vdDebug_LogPrintf("print footer 3");
			memset(szTagValue, 0x00, sizeof(szTagValue));
			memcpy(szTagValue, &srTransRec.szBarcodeText[inTotalLen],inTaglen);
			inTotalLen=inTotalLen+inTaglen;
			vdDebug_LogPrintf("tag value %s", szTagValue);


			//vdCTOSS_PrinterEnd();
			//CTOS_PrinterCode39Barcode(30,1,"*TEST8052*",10,2,3,TRUE);   
		 	//vdCTOSS_PrinterStart(100);
            if (strcmp(szTag,"001")==0)
				vdCTOSS_PrinterBufferEAN8Barcode(110,0,szTagValue,inTaglen, 5, 30,TRUE);   
			else if (strcmp(szTag,"002")==0)
				vdCTOSS_PrinterBufferEAN13Barcode(50,0,szTagValue, inTaglen , 5, 30,TRUE);   
			else if (strcmp(szTag,"003")==0)
				vdCTOSS_PrinterBufferUPCABarcode(50,0,szTagValue, inTaglen , 5, 30,TRUE);   
			else if (strcmp(szTag,"004")==0){
				 //vdCTOSS_PrinterBufferCode39Barcode(50, 0, szTagValue, inTaglen, 5 ,20, TRUE);
				 //CTOS_PrinterCode39Barcode(25,100,szTagValue,inTaglen,2,3,TRUE);

				#if 0 // from paatrick test
			    //vdCTOSS_PrinterStart(500);
			    //vdCTOSS_PrinterBufferCode39BarcodeEx(1, 1, "8880123412341234", 16, 0 ,15, TRUE);
			    // CRASHED

    			//CTOS_PrinterCode39Barcode(1,1,"048800000966111",15,1,2,TRUE);  
    			//WITH SMALL BARCODE AND BIG DIGITS PRINTED
    			
			    //vdCTOSS_PrinterEnd();		

				//inCTOS_SelectFont(d_FONT_TTF_MODE,d_FONT_24x24,0," ");
        		//vdSetGolbFontAttrib(d_FONT_12x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);
    			//vdCTOSS_PrinterBufferCode39BarcodeEx(1, 1, "8880123412341234", 16, 0 ,15, TRUE);
    			// CTOS_PrinterCode39Barcode(1,1,"048800000966111",15,1,2,TRUE);


				inCTOS_SelectFont(d_FONT_TTF_MODE,d_FONT_24x24,0," ");
						vdSetGolbFontAttrib(d_FONT_12x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);
				vdCTOSS_PrinterStart(500);
					vdCTOSS_PrinterBufferCode39BarcodeEx(1, 1, "8880123412341234", 16, 0 ,15, TRUE);
					vdCTOSS_PrinterEnd();


				#else //original code
				
				CTOS_PrinterCode39Barcode(25,100,szTagValue,inTaglen,2,3,TRUE);
		
    			#endif
		
				 //CTOS_PrinterCode39Barcode(15,50,szTagValue,inTaglen,2,3,TRUE);   
				 //CTOS_PrinterCode39Barcode(10,25,szTagValue,inTaglen,2,3,TRUE);   
				 //CTOS_PrinterCode39Barcode(5,15,szTagValue,inTaglen,2,3,TRUE);   
				 //CTOS_PrinterCode39Barcode(5,5,szTagValue,inTaglen,2,3,TRUE);   
				 //CTOS_PrinterCode39Barcode(5,0,szTagValue,inTaglen,2,3,TRUE);   
				 //CTOS_PrinterCode39Barcode(0,0,szTagValue,inTaglen,2,3,TRUE);   
				 //CTOS_PrinterCode39Barcode(0,0,szTagValue,inTaglen,2,2,TRUE);   
				 //CTOS_PrinterCode39Barcode(0,0,szTagValue,inTaglen,1,3,TRUE);   
				 //CTOS_PrinterCode39Barcode(0,0,szTagValue,inTaglen,0,3,TRUE);
				 //CTOS_PrinterCode39Barcode(0,1,szTagValue,inTaglen,2,3,TRUE);   
			}
			else if (strcmp(szTag,"005")==0){
				vdCTOS_PrinterFline(1);
				vdPrintCenter(szTagValue);
			}
			//vdCTOSS_PrinterEnd();
			//vdCTOSS_PrinterStart(100);



		}
    }
	//VERSION16

    if(srTransRec.byTransType != SMAC_BALANCE && srTransRec.byTransType != BALANCE_INQUIRY && srTransRec.byEntryMode != CARD_ENTRY_WAVE && srTransRec.HDTid != SMAC_HDT_INDEX)
    {
        if(srTransRec.byTransType != VOID && srTransRec.byTransType != SALE_TIP && srTransRec.HDTid != SMGIFTCARD_HDT_INDEX && srTransRec.fDCC != TRUE)//SM GIFTCARD should not print Agreement Statement
        {

			vdDebug_LogPrintf("ushCTOS_PrintSMFooter (page != CUSTOMER_COPY_RECEIPT)");
		
            ushCTOS_PrintAgreement();
        }
    }

    vdPrintFooterText();

    /***************************************************/
    //sidumili: Issue#000135 [Print Footer Logo]
    if (srTransRec.fFooterLogo)
    {
        //vdCTOSS_PrintFooterLogoBMPPic(0, 0, "footer.bmp");
        vdCTOSS_PrinterBMPPicEx(0,0,"/home/ap/pub/footer.bmp");  
    }
    /***************************************************/


	//version16
	vdDebug_LogPrintf("print hdtid %d  fsmacsacn %d srTransRec.byTransType %d",srTransRec.HDTid, fSmacScan, srTransRec.byTransType);

    
	
	if(srTransRec.byTransType != VOID && srTransRec.fSMACFooter == TRUE && page == CUSTOMER_COPY_RECEIPT)
	{
		vdCTOS_PrinterFline(1);

		if(fRePrintFlag == TRUE)
		{
			memset(szField60,0x00,sizeof(szField60));

			vdDebug_LogPrintf("inDatabase_inSMACFooterRead[%d]",inDatabase_inSMACFooterRead(szField60,&srTransRec));			
			vdDebug_LogPrintf("szField60[%s]",szField60);	
		}
		else
			vdDebug_LogPrintf("inDatabase_inSMACFooterSave[%d]",inDatabase_inSMACFooterSave(szField60,&srTransRec)); 
		
		inSMACPrintField60();
		vdLineFeed(srTransRec.fFooterLogo);
	}
	else
		vdLineFeed(srTransRec.fFooterLogo);

    vdDebug_LogPrintf("testlang print footer %s", srTransRec.szBarcodeText);
	
	return d_OK;	
}

void vdCTOS_PrintReceiptCopies(BOOL BankCopy, BOOL CustCopy, BOOL MercCopy, BOOL fERM)

{
    BOOL fFirstReceipt=TRUE; 
    int inReceiptCtr=0;
    BYTE szPrintOption[3+1];
    BYTE chPrintOption=0x00;
	BYTE  key;
	ULONG ulFileSize;
	BYTE  szTotalAmt[12+1];
	
    memset(szPrintOption, 0x00, sizeof(szPrintOption)); 
    memcpy(szPrintOption, strIIT.szPrintOption, 3); /*get sequence from IIT*/
    
	inReceiptCtr=0;
	fFirstReceipt=TRUE;
    do
    {
        chPrintOption=(unsigned char)szPrintOption[inReceiptCtr];
        if((chPrintOption == '1') && (BankCopy == TRUE)) /*bank copy*/
        {
			if(fFirstReceipt == TRUE)
			{
				ushCTOS_printAll(BANK_COPY_RECEIPT);
				if(fERM == TRUE)
					inCTOSS_ERM_Form_Receipt(0);
				CTOS_KBDBufFlush();	
				fFirstReceipt=FALSE;
			}
			else
			{
				CTOS_TimeOutSet(TIMER_ID_1, UI_TIMEOUT);
				if(strTCT.fPrintReceiptPrompt == TRUE)
				{
					vduiDisplayStringCenter(7,"PRINT BANK COPY?");
					vduiDisplayStringCenter(8,"NO[X] YES[OK]");
				}
				else
				{
					vduiDisplayStringCenter(7,"PRINT BANK COPY");
					vduiDisplayStringCenter(8,"PRESS ENTER TO PRINT");
				}
	                while(1)
	                { 
	                    if (strTCT.fPrintWarningSound == TRUE)
	                    vduiWarningSound();
	                    
	                    CTOS_KBDHit(&key);
	                    if(key == d_KBD_ENTER)
	                    {
	                        ushCTOS_printAll(BANK_COPY_RECEIPT);
                            if(fERM == TRUE)
                                inCTOSS_ERM_Form_Receipt(0);
	                        CTOS_KBDBufFlush();//cleare key buffer
	                        break;
	                    }
	                    else if(key == d_KBD_CANCEL && strTCT.fPrintReceiptPrompt == TRUE)
	                        break;
	                    if(CTOS_TimeOutCheck(TIMER_ID_1) == d_YES)
	                    {
							ushCTOS_printAll(BANK_COPY_RECEIPT);
	                        break;
	                    }
	                }
			}
        }
        else if((chPrintOption == '2') && (CustCopy == TRUE)) /*customer copy*/
        {
			if(fFirstReceipt == TRUE)
			{
				ushCTOS_printAll(CUSTOMER_COPY_RECEIPT);
                if(fERM == TRUE)
                    inCTOSS_ERM_Form_Receipt(0);
				CTOS_KBDBufFlush();//cleare key buffer	
				fFirstReceipt=FALSE;
			}
			else
			{
				
				wub_hex_2_str(srTransRec.szTotalAmount, szTotalAmt, AMT_BCD_SIZE); 
				vdDebug_LogPrintf("fPrintReceiptPrompt[%d] :: fNSRCustCopy[%d] :: szNSRLimit[%d] :: szTotalAmt[%d]",
					strTCT.fPrintReceiptPrompt, strIIT.fNSRCustCopy, atol(strIIT.szNSRLimit),atol(szTotalAmt));

				
				CTOS_TimeOutSet(TIMER_ID_1, UI_TIMEOUT);  
				if(strTCT.fPrintReceiptPrompt == FALSE && strIIT.fNSRCustCopy == FALSE)
				{
					vduiDisplayStringCenter(7,"PRINT CUSTOMER COPY");
					vduiDisplayStringCenter(8,"PRESS ENTER TO PRINT");
				}
				else
				{
					if(strTCT.fPrintReceiptPrompt == FALSE && ( (strIIT.fNSRCustCopy == TRUE && atol(strIIT.szNSRLimit) < atol(szTotalAmt)) 
						|| srTransRec.byEntryMode == CARD_ENTRY_FALLBACK || srTransRec.fDCC == TRUE))
					{
						vduiDisplayStringCenter(7,"PRINT CUSTOMER COPY");
						vduiDisplayStringCenter(8,"PRESS ENTER TO PRINT");
					}
					else
					{
						vduiDisplayStringCenter(7,"PRINT CUSTOMER COPY?");
						vduiDisplayStringCenter(8,"NO[X] YES[OK]");
					}
						
				}
                while(1)
                { 
                    if (strTCT.fPrintWarningSound == TRUE)
                    vduiWarningSound();
                    
                    CTOS_KBDHit(&key);
                    if(key == d_KBD_ENTER)
                    {
                        ushCTOS_printAll(CUSTOMER_COPY_RECEIPT);
                        if(fERM == TRUE)
                            inCTOSS_ERM_Form_Receipt(0);						
                        CTOS_KBDBufFlush();//cleare key buffer
                        break;
                    }
                    else if(key == d_KBD_CANCEL)
                    {
						if(strTCT.fPrintReceiptPrompt == TRUE || ((strTCT.fPrintReceiptPrompt == FALSE && strIIT.fNSRCustCopy
							&& atol(strIIT.szNSRLimit) >= atol(szTotalAmt)) && srTransRec.byEntryMode != CARD_ENTRY_FALLBACK && srTransRec.fDCC != TRUE) )
	                        break;
                    }	
                    if(CTOS_TimeOutCheck(TIMER_ID_1) == d_YES)
                    {
						ushCTOS_printAll(CUSTOMER_COPY_RECEIPT);
                        break;
                    }
                }
			}
			
        }  	
        else if((chPrintOption == '3') && (MercCopy== TRUE)) /*merchant copy*/
        {
			if(fFirstReceipt == TRUE)
			{
				ushCTOS_printAll(MERCHANT_COPY_RECEIPT);
                if(fERM == TRUE)
                    inCTOSS_ERM_Form_Receipt(0);
				CTOS_KBDBufFlush();//cleare key buffer	
				fFirstReceipt=FALSE;
			}
			else
			{
				CTOS_TimeOutSet(TIMER_ID_1, UI_TIMEOUT);  

				
				if(strTCT.fSMMode == TRUE){

					if(strTCT.fPrintReceiptPrompt == FALSE && strIIT.fNSRCustCopy == FALSE)
					{
						vduiDisplayStringCenter(7,"PRINT MERCHANT COPY");
						vduiDisplayStringCenter(8,"PRESS ENTER TO PRINT");
					}
					else
					{
						if(strTCT.fPrintReceiptPrompt == FALSE && ( (strIIT.fNSRCustCopy == TRUE && atol(strIIT.szNSRLimit) < atol(szTotalAmt)) 
						|| srTransRec.byEntryMode == CARD_ENTRY_FALLBACK || srTransRec.fDCC == TRUE))
						{
							vduiDisplayStringCenter(7,"PRINT MERCHANT COPY");
							vduiDisplayStringCenter(8,"PRESS ENTER TO PRINT");
						}
						else
						{
							vduiDisplayStringCenter(7,"PRINT MERCHANT COPY?");
							vduiDisplayStringCenter(8,"NO[X] YES[OK]");
					}
						
				}

				}else{
					if(strTCT.fPrintReceiptPrompt == TRUE)
					{
						vduiDisplayStringCenter(7,"PRINT MERCHANT COPY?");
						vduiDisplayStringCenter(8,"NO[X] YES[OK]");
					}
					else
					{
						vduiDisplayStringCenter(7,"PRINT MERCHANT COPY");
						vduiDisplayStringCenter(8,"PRESS ENTER TO PRINT");
					}
				}
				
                while(1)
                { 
                    if (strTCT.fPrintWarningSound == TRUE) /*BDO PHASE 2: [Warning sound for printing flag] -- sidumili*/
                    vduiWarningSound();
                    
                    CTOS_KBDHit(&key);
                    if(key == d_KBD_ENTER)
                    {
                        ushCTOS_printAll(MERCHANT_COPY_RECEIPT);
                        if(fERM == TRUE)
                            inCTOSS_ERM_Form_Receipt(0);						
                        CTOS_KBDBufFlush();//cleare key buffer
                        break;
                    }
                   // else if(key == d_KBD_CANCEL && strTCT.fPrintReceiptPrompt == TRUE){
				   else if(key == d_KBD_CANCEL){
    
						if(strTCT.fSMMode == TRUE){
					    
							if(strTCT.fPrintReceiptPrompt == TRUE || ((strTCT.fPrintReceiptPrompt == FALSE && strIIT.fNSRCustCopy
								&& atol(strIIT.szNSRLimit) >= atol(szTotalAmt)) && srTransRec.byEntryMode != CARD_ENTRY_FALLBACK && srTransRec.fDCC != TRUE) )
								break;
							
						}else if (strTCT.fPrintReceiptPrompt == TRUE)
					      	 break;
			

					}
                    if(CTOS_TimeOutCheck(TIMER_ID_1) == d_YES)
                    {
						ushCTOS_printAll(MERCHANT_COPY_RECEIPT);
                        break;
                    }
                }
			}
        }  		
		inReceiptCtr++; 
    }while(inReceiptCtr < 3);	

    if(fERM == TRUE)
    {
        if(strTCT.fSignatureFlag == TRUE)
        {
            ulFileSize=lnGetFileSize(DB_SIGN_BMP);
            if(ulFileSize > 0)
                vdLinuxCommandFileCopy();
        }
    }
	
}

void vdLineFeed(BOOL fFooterLogo)
{
    int inLineFeed;

	if(strTCT.byTerminalModel == V3_DESKTOP)
        inLineFeed=((fFooterLogo)?6:7);
    else if(strTCT.byTerminalModel == V3_MOBILE)
		inLineFeed=((fFooterLogo)?2:3);
	else
		inLineFeed=((fFooterLogo)?4:5);//for V5
	
    //CTOS_PrinterFline(d_LINE_DOT * inLineFeed); 
	vdCTOS_PrinterFline(inLineFeed);
}

void vdPrintHeaderText(void)
{

    char szPOSTID[40];
	char szPOSTIDHeader[40];

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	memset(szPOSTID, 0x00, 40);
	
	memset(szPOSTIDHeader, 0x00, 40);
    #ifdef SINGE_HEADER_FOOTER_TEXT
        //inNMTReadRecord(srTransRec.MITid);

		if (srTransRec.MITid > 0)
			inNMTReadRecord(srTransRec.MITid);		
		else	
			inNMTReadRecord(strNMT[0].NMTID);	
	
	        vdPrintCenter(strSingleNMT.szMerchName);
		if(strlen(strSingleNMT.szRctHdr1) > 0)
            vdPrintCenter(strSingleNMT.szRctHdr1);
        if(strlen(strSingleNMT.szRctHdr2) > 0)
            vdPrintCenter(strSingleNMT.szRctHdr2);
        if(strlen(strSingleNMT.szRctHdr3) > 0)
            vdPrintCenter(strSingleNMT.szRctHdr3);
        if(strlen(strSingleNMT.szRctHdr4) > 0)
            vdPrintCenter(strSingleNMT.szRctHdr4);
        if(strlen(strSingleNMT.szRctHdr5) > 0)
            vdPrintCenter(strSingleNMT.szRctHdr5);


		if (srTransRec.fECRTriggerTran == TRUE  && strTCT.fSMMode == TRUE){
			//inCTOSS_GetEnvDB("PTID", szPOSTID);

			if (strlen(srTransRec.szPOSTID)> 0){
				
				sprintf(szPOSTIDHeader,"POS TID %s", srTransRec.szPOSTID);
				vdPrintCenter(szPOSTIDHeader);
			}
		}
		else if(strTCT.fSMMode == TRUE)
		{
		
			memset(szPOSTID,0x00,sizeof(szPOSTID));
			inCTOSS_GetEnvDB("PTID", szPOSTID);
			if (strlen(szPOSTID)> 0){
				sprintf(szPOSTIDHeader,"POS TID %s", szPOSTID);
				vdPrintCenter(szPOSTIDHeader);
			}
		}
				
    #else
        vdPrintCenter(strMMT[0].szMerchantName);
        if(strlen(strMMT[0].szRctHdr1) > 0)
            vdPrintCenter(strMMT[0].szRctHdr1);
        if(strlen(strMMT[0].szRctHdr2) > 0)
            vdPrintCenter(strMMT[0].szRctHdr2);
        if(strlen(strMMT[0].szRctHdr3) > 0)
            vdPrintCenter(strMMT[0].szRctHdr3);
        if(strlen(strMMT[0].szRctHdr4) > 0)
            vdPrintCenter(strMMT[0].szRctHdr4);
        if(strlen(strMMT[0].szRctHdr5) > 0)
            vdPrintCenter(strMMT[0].szRctHdr5);
		
		if (srTransRec.fECRTriggerTran == TRUE && strTCT.fSMMode == TRUE){
			//inCTOSS_GetEnvDB("PTID", szPOSTID);

			if (strlen(srTransRec.szPOSTID)> 0){
				sprintf(szPOSTIDHeader,"POS TID %s", srTransRec.szPOSTID);
				vdPrintCenter(szPOSTIDHeader);
			}			
		}
		else if(strTCT.fSMMode == TRUE)
		{
			memset(szPOSTID,0x00,sizeof(szPOSTID));
			inCTOSS_GetEnvDB("PTID", szPOSTID);
			if (strlen(szPOSTID)> 0){
				sprintf(szPOSTIDHeader,"POS TID %s", szPOSTID);
				vdPrintCenter(szPOSTIDHeader);
			}
		}
    #endif	
	
}

void vdPrintFooterText(void)
{
    #ifdef SINGE_HEADER_FOOTER_TEXT
        if(strlen(strSingleNMT.szRctFoot1) > 0)
            vdPrintCenter(strSingleNMT.szRctFoot1);
        if(strlen(strSingleNMT.szRctFoot2) > 0)
            vdPrintCenter(strSingleNMT.szRctFoot2);
        if(strlen(strSingleNMT.szRctFoot3) > 0)
            vdPrintCenter(strSingleNMT.szRctFoot3); 
    #else
        if(strlen(strMMT[0].szRctFoot1) > 0)
            vdPrintCenter(strMMT[0].szRctFoot1);
        if(strlen(strMMT[0].szRctFoot2) > 0)
            vdPrintCenter(strMMT[0].szRctFoot2);
        if(strlen(strMMT[0].szRctFoot3) > 0)
            vdPrintCenter(strMMT[0].szRctFoot3);
    #endif	
}


void vdCTOS_PrintIP(void)
{
  int shHostIndex = 1, inNumOfMerchant=0;
  int inResult,inRet;
  unsigned char szCRC[8+1];
  char ucLineBuffer[d_LINE_SIZE];
  BYTE baTemp[PAPER_X_SIZE * 64];
	int i;

	char szStr[d_LINE_SIZE + 1];

  vduiLightOn();            
  inCPTRead(1);

	vdSetPrintThreadStatus(1); /*BDO:Display printing image during report -- sidumili*/
		
    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

  vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);

    fRePrintFlag = FALSE;
	
    ushCTOS_PrintHeader(0);
    //CTOS_PrinterFline(d_LINE_DOT);
    vdCTOS_PrinterFline(1);

	printDateTime();
	//CTOS_PrinterFline(d_LINE_DOT);
	vdCTOS_PrinterFline(1);
	
	inPrint("IP REPORT");

	//CTOS_PrinterFline(d_LINE_DOT);  
	vdCTOS_PrinterFline(1);

	inPrint("TERMINAL");

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	//CTOS_PrinterFline(d_LINE_DOT);  
  vdCTOS_PrinterFline(1);
	
  if (strCPT.inCommunicationMode == GPRS_MODE)
  //test-glad
  //if (1)
  {
     //inCTOSS_SIMGetGPRSIP();
     inCTOSS_SIMGetGPRSIPInfo();
     memset(szStr, 0x00, d_LINE_SIZE);
     sprintf(szStr, "                 IP: %s", szIP);
     inPrint(szStr);

     memset(szStr, 0x00, d_LINE_SIZE);
     sprintf(szStr, "              DNS 1: %s", szDNS1);
     inPrint(szStr);
     
     memset(szStr, 0x00, d_LINE_SIZE);
     sprintf(szStr, "              DNS 2: %s", szDNS2);
		 inPrint(szStr);
     
     memset(szStr, 0x00, d_LINE_SIZE);
     sprintf(szStr, "            GATEWAY: %s", szGateWay);
     inPrint(szStr);
     
     memset(szStr, 0x00, d_LINE_SIZE);
     sprintf(szStr, "        SUBNET MASK: %s", szSubnetMask);
     inPrint(szStr);

		 /*AAA temp only need to change value when we have function to get data end*/
  }
	else if (strCPT.inCommunicationMode == WIFI_MODE)
  {
     inWIFI_GetConnectConfig();
     memset(szStr, 0x00, d_LINE_SIZE);
     sprintf(szStr, "                 IP: %s", szIP);
     inPrint(szStr);

     memset(szStr, 0x00, d_LINE_SIZE);
     sprintf(szStr, "              DNS 1: %s", szDNS1);
     inPrint(szStr);
     
     memset(szStr, 0x00, d_LINE_SIZE);
     sprintf(szStr, "              DNS 2: %s", szDNS2);
		 inPrint(szStr);
     
     memset(szStr, 0x00, d_LINE_SIZE);
     sprintf(szStr, "            GATEWAY: %s", szGateWay);
     inPrint(szStr);
     
     memset(szStr, 0x00, d_LINE_SIZE);
     sprintf(szStr, "        SUBNET MASK: %s", szSubnetMask);
     inPrint(szStr);
		 
  }
  else
  {
  	if(strTCP.fDHCPEnable == 1)
  	{
	  	 vdPrint_EthernetStatus();
		 memset(szStr, 0x00, d_LINE_SIZE);
	     sprintf(szStr, "             IP: %s", szIP);
	     inPrint(szStr);

	     memset(szStr, 0x00, d_LINE_SIZE);
	     sprintf(szStr, "          DNS 1: %s", szDNS1);
	     inPrint(szStr);
	     
	     memset(szStr, 0x00, d_LINE_SIZE);
	     sprintf(szStr, "          DNS 2: 0.0.0.0");
		 inPrint(szStr);
	     
	     memset(szStr, 0x00, d_LINE_SIZE);
	     sprintf(szStr, "        GATEWAY: %s", szGateWay);
	     inPrint(szStr);
	     
	     memset(szStr, 0x00, d_LINE_SIZE);
	     sprintf(szStr, "    SUBNET MASK: %s", szSubnetMask);
	     inPrint(szStr);
  	}
	else
	{
	     memset(szStr, 0x00, d_LINE_SIZE);
	     sprintf(szStr, "             IP: %s", (char *)strTCP.szTerminalIP);
	     inPrint(szStr);
	     
	     memset(szStr, 0x00, d_LINE_SIZE);
	     sprintf(szStr, "          DNS 1: %s", (char *)strTCP.szHostDNS1);
	     inPrint(szStr);
	     
	     memset(szStr, 0x00, d_LINE_SIZE);
	     sprintf(szStr, "          DNS 2: %s", (char *)strTCP.szHostDNS2);
	     inPrint(szStr);
	     
	     memset(szStr, 0x00, d_LINE_SIZE);
	     sprintf(szStr, "        GATEWAY: %s", (char *)strTCP.szGetWay);
	     inPrint(szStr);
	     
	     memset(szStr, 0x00, d_LINE_SIZE);
	     sprintf(szStr, "    SUBNET MASK: %s", (char *)strTCP.szSubNetMask);
	     inPrint(szStr);
	}
  }

	//CTOS_PrinterFline(d_LINE_DOT);  
	vdCTOS_PrinterFline(1);

	inPrint("HOST");
	
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	//CTOS_PrinterFline(d_LINE_DOT);  
	vdCTOS_PrinterFline(1);

	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "         PRI IP: %s", (char *)strCPT.szPriTxnHostIP);

	inPrint(szStr);	
	
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "         SEC IP: %s", (char *)strCPT.szSecTxnHostIP);
	inPrint(szStr);

	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "    PRI IP PORT: %04d", strCPT.inPriTxnHostPortNum);
	inPrint(szStr);
	
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "    SEC IP PORT: %04d", strCPT.inSecTxnHostPortNum);
	inPrint(szStr);

	if(strTCT.fSMMode == 0)
	{
		memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "  PRI SETTLE IP: %s", (char *)strCPT.szPriTxnHostIP);
		inPrint(szStr);	
		
		memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "  SEC SETTLE IP: %s", (char *)strCPT.szSecTxnHostIP);
		inPrint(szStr);

		memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "PRI SETTLE PORT: %04d", strCPT.inPriTxnHostPortNum);
		inPrint(szStr);
		
		memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "SEC SETTLE PORT: %04d", strCPT.inSecTxnHostPortNum);
		inPrint(szStr);
	}

	//if(strTCT.fSingleComms == FALSE)
	{
		inHDTReadData(BDOPAY_HDT_INDEX);//READ AND PRINT BDOPAY IP INFO		
		if(strHDT_Temp.fHostEnable == TRUE)
		{
			
			vdCTOS_PrinterFline(1);
			inPrint("BDOPAY");
			vdCTOS_PrinterFline(1);
			
			inCPTRead(BDOPAY_HDT_INDEX);//READ AND PRINT BDO PAY HOST
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         PRI IP: %s", (char *)strCPT.szPriTxnHostIP);

			inPrint(szStr);	
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         SEC IP: %s", (char *)strCPT.szSecTxnHostIP);
			inPrint(szStr);

			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    PRI IP PORT: %04d", strCPT.inPriTxnHostPortNum);
			inPrint(szStr);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    SEC IP PORT: %04d", strCPT.inSecTxnHostPortNum);
			inPrint(szStr);
		}

		
		inHDTReadData(PHQR_HDT_INDEX);//READ AND PRINT BDOPAY IP INFO		
		if(strHDT_Temp.fHostEnable == TRUE)
		{
			
			vdCTOS_PrinterFline(1);
			inPrint("QRPH");
			vdCTOS_PrinterFline(1);
			
			inCPTRead(PHQR_HDT_INDEX);//READ AND PRINT BDO PAY HOST

			inPrint("GENERATE QR:");
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         PRI IP: %s", (char *)strCPT.szPriTxnHostIP);

			inPrint(szStr);	
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         SEC IP: %s", (char *)strCPT.szSecTxnHostIP);
			inPrint(szStr);

			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    PRI IP PORT: %04d", strCPT.inPriTxnHostPortNum);
			inPrint(szStr);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    SEC IP PORT: %04d", strCPT.inSecTxnHostPortNum);
			inPrint(szStr);

			inPHQRRead(1);
			inPrint("TRANSACTION STATUS:");
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         PRI IP: %s", (char *)strPHQR.szGetStatusPriIP);

			inPrint(szStr);	
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         SEC IP: %s", (char *)strPHQR.szGetStatusSecIP);
			inPrint(szStr);

			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    PRI IP PORT: %04d", strPHQR.inGetStatusPriPort);
			inPrint(szStr);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    SEC IP PORT: %04d", strPHQR.inGetStatusSecPort);
			inPrint(szStr);
			
		}


		inHDTReadData(WECHAT_HDT_INDEX);//READ AND PRINT WECHAT IP INFO
		if(strHDT_Temp.fHostEnable == TRUE)
		{
			
			vdCTOS_PrinterFline(1);
			inPrint("WECHAT");
			vdCTOS_PrinterFline(1);
			
			inCPTRead(WECHAT_HDT_INDEX);//READ AND PRINT BDO PAY HOST
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         PRI IP: %s", (char *)strCPT.szPriTxnHostIP);

			inPrint(szStr);	
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         SEC IP: %s", (char *)strCPT.szSecTxnHostIP);
			inPrint(szStr);

			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    PRI IP PORT: %04d", strCPT.inPriTxnHostPortNum);
			inPrint(szStr);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    SEC IP PORT: %04d", strCPT.inSecTxnHostPortNum);
			inPrint(szStr);
		}

		inHDTReadData(ALIPAY_HDT_INDEX);//READ AND PRINT WECHAT IP INFO
		//vdDebug_LogPrintf("WECHAT.fHostEnable[%d]", strHDT_Temp.fHostEnable);
		if(strHDT_Temp.fHostEnable == TRUE)
		{
			
			vdCTOS_PrinterFline(1);
			inPrint("ALIPAY");
			vdCTOS_PrinterFline(1);
			
			inCPTRead(ALIPAY_HDT_INDEX);//READ AND PRINT ALIPAY HOST
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         PRI IP: %s", (char *)strCPT.szPriTxnHostIP);

			inPrint(szStr);	
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         SEC IP: %s", (char *)strCPT.szSecTxnHostIP);
			inPrint(szStr);

			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    PRI IP PORT: %04d", strCPT.inPriTxnHostPortNum);
			inPrint(szStr);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    SEC IP PORT: %04d", strCPT.inSecTxnHostPortNum);
			inPrint(szStr);
		}

		inHDTReadData(GCASH_HDT_INDEX);//READ AND PRINT WECHAT IP INFO
		//vdDebug_LogPrintf("WECHAT.fHostEnable[%d]", strHDT_Temp.fHostEnable);
		if(strHDT_Temp.fHostEnable == TRUE)
		{
			
			vdCTOS_PrinterFline(1);
			inPrint("G-CASH");
			vdCTOS_PrinterFline(1);
			
			inCPTRead(GCASH_HDT_INDEX);//READ AND PRINT ALIPAY HOST
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         PRI IP: %s", (char *)strCPT.szPriTxnHostIP);

			inPrint(szStr);	
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         SEC IP: %s", (char *)strCPT.szSecTxnHostIP);
			inPrint(szStr);

			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    PRI IP PORT: %04d", strCPT.inPriTxnHostPortNum);
			inPrint(szStr);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    SEC IP PORT: %04d", strCPT.inSecTxnHostPortNum);
			inPrint(szStr);
		}

		inHDTReadData(GRABPAY_HDT_INDEX);//READ AND PRINT WECHAT IP INFO
		//vdDebug_LogPrintf("WECHAT.fHostEnable[%d]", strHDT_Temp.fHostEnable);
		if(strHDT_Temp.fHostEnable == TRUE)
		{
			
			vdCTOS_PrinterFline(1);
			inPrint("GRABPAY");
			vdCTOS_PrinterFline(1);
			
			inCPTRead(GRABPAY_HDT_INDEX);//READ AND PRINT ALIPAY HOST
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         PRI IP: %s", (char *)strCPT.szPriTxnHostIP);

			inPrint(szStr);	
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         SEC IP: %s", (char *)strCPT.szSecTxnHostIP);
			inPrint(szStr);

			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    PRI IP PORT: %04d", strCPT.inPriTxnHostPortNum);
			inPrint(szStr);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    SEC IP PORT: %04d", strCPT.inSecTxnHostPortNum);
			inPrint(szStr);
		}

		inHDTReadData(SODEXO_HDT_INDEX);//READ AND PRINT WECHAT IP INFO
		//vdDebug_LogPrintf("WECHAT.fHostEnable[%d]", strHDT_Temp.fHostEnable);
		if(strHDT_Temp.fHostEnable == TRUE)
		{
			
			vdCTOS_PrinterFline(1);
			inPrint("SODEXO");
			vdCTOS_PrinterFline(1);
			
			inCPTRead(SODEXO_HDT_INDEX);//READ AND PRINT ALIPAY HOST
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         PRI IP: %s", (char *)strCPT.szPriTxnHostIP);

			inPrint(szStr);	
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         SEC IP: %s", (char *)strCPT.szSecTxnHostIP);
			inPrint(szStr);

			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    PRI IP PORT: %04d", strCPT.inPriTxnHostPortNum);
			inPrint(szStr);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    SEC IP PORT: %04d", strCPT.inSecTxnHostPortNum);
			inPrint(szStr);
		}

		inHDTReadData(UPI_QR_INDEX);//READ AND PRINT WECHAT IP INFO
		//vdDebug_LogPrintf("WECHAT.fHostEnable[%d]", strHDT_Temp.fHostEnable);
		if(strHDT_Temp.fHostEnable == TRUE)
		{
			
			vdCTOS_PrinterFline(1);
			inPrint("UPI");
			vdCTOS_PrinterFline(1);
			
			inCPTRead(UPI_QR_INDEX);//READ AND PRINT ALIPAY HOST
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         PRI IP: %s", (char *)strCPT.szPriTxnHostIP);

			inPrint(szStr);	
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         SEC IP: %s", (char *)strCPT.szSecTxnHostIP);
			inPrint(szStr);

			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    PRI IP PORT: %04d", strCPT.inPriTxnHostPortNum);
			inPrint(szStr);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    SEC IP PORT: %04d", strCPT.inSecTxnHostPortNum);
			inPrint(szStr);
		}


 		inHDTReadData(BDO_LOYALTY_HDT_INDEX);//READ AND PRINT BDOPAY IP INFO		
		if(strHDT_Temp.fHostEnable == TRUE)
		{
			
			vdCTOS_PrinterFline(1);
			inPrint("BDO LOYALTY");
			vdCTOS_PrinterFline(1);
			
			inCPTRead(BDO_LOYALTY_HDT_INDEX);//READ AND PRINT BDO PAY HOST
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         PRI IP: %s", (char *)strCPT.szPriTxnHostIP);

			inPrint(szStr);	
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "         SEC IP: %s", (char *)strCPT.szSecTxnHostIP);
			inPrint(szStr);

			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    PRI IP PORT: %04d", strCPT.inPriTxnHostPortNum);
			inPrint(szStr);
			
			memset(szStr, 0x00, d_LINE_SIZE);
			sprintf(szStr, "    SEC IP PORT: %04d", strCPT.inSecTxnHostPortNum);
			inPrint(szStr);
		}
		
	}
	
	vdLineFeed(srTransRec.fFooterLogo);
	vdCTOSS_PrinterEnd();
  
	//vdSetPrintThreadStatus(0); /*BDO:Display printing image during report -- sidumili*/
}
/*albert - end - Aug2014 - compute crc*/

/* Get ROOTFS Version - sidumili */
void vdCTOS_GetROOTFS(char* ucBuffer){
int inResult;
BYTE szTemp[d_LINE_SIZE + 1] = {0};

memset(ucBuffer, 0x00, sizeof(ucBuffer));
memset(szTemp, 0x00, sizeof(szTemp));
inResult = CTOS_GetSystemInfo (ID_ROOTFS, szTemp);
memcpy(ucBuffer, szTemp, 6);

return;
}

void vdCTOS_GetFactorySN(char* ucBuffer){
int inResult;
BYTE szTemp[16 + 1] = {0};

memset(ucBuffer, 0x00, sizeof(ucBuffer));
memset(szTemp, 0x00, sizeof(szTemp));
inResult = CTOS_GetFactorySN(ucBuffer);

vdDebug_LogPrintf("::CTOS_GetFactorySN::inResult[%d]::ucBuffer[%s]", inResult, ucBuffer);

return;
}



USHORT ushCTOS_PrintSMACBody(int page)
{	
	char szStr[d_LINE_SIZE + 1];
	char szTemp[d_LINE_SIZE + 1];
	char szTemp1[d_LINE_SIZE + 1];
	char szTemp2[d_LINE_SIZE + 1];	
	char szTemp3[d_LINE_SIZE + 1];
	char szTemp4[d_LINE_SIZE + 1];
	char szTemp5[d_LINE_SIZE + 1];
	char szTempDate[d_LINE_SIZE + 1];
	char szFormatPAN[strlen(srTransRec.szPAN) + 7];//to account for space as in PAN format and to include additional PAN no. 7 has been added -Meena 08/01/2012
	char szSMACCExpDate[8+1];
	int inFmtPANSize;
	BYTE baTemp[PAPER_X_SIZE * 64];
	USHORT result;
	int num,i,inResult;
	unsigned char tucPrint [24*4+1];	
	BYTE   EMVtagVal[64+1];
	USHORT EMVtagLen; 
	short spacestring;
	BYTE   key;
	int inSpace;

	char szAmountBuff[20+1], szTemp6[47+1];

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	vdDebug_LogPrintf("ushCTOS_PrintSMACBody");
	
    vdDebug_LogPrintf("ushCTOS_PrintSMACBody KIKO1 srTransPara->szPAN:%s", srTransRec.szPAN);
	
    printSMDateTime();
	
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "MERCHANT ID  : %s", srTransRec.szMID);
	inPrint(szStr);
	
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "TERMINAL ID  : %s", srTransRec.szTID);
	inPrint(szStr);
	
	memset(szTemp,0x00, sizeof(szTemp));
	wub_hex_2_str(srTransRec.szBatchNo,szTemp,3);
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "BATCH NUM    : %s", szTemp);
	inPrint(szStr);
		
	memset(szTemp,0x00, sizeof(szTemp));
	wub_hex_2_str(srTransRec.szInvoiceNo,szTemp,3);
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "INVOICE NUM  : %s", szTemp);
	inPrint(szStr);

	if(srTransRec.fBINVer)
	{
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "BIN CHECK    : %06ld", atol(srTransRec.szBINVerSTAN));
		inPrint(szStr);
	}
	
	szGetTransTitle(srTransRec.byTransType, szStr);  
	
	//gcitra-012315
/*	if(srTransRec.byTransType == SALE)
	{
		memset(szStr, 0x00, sizeof(szStr));
		
		if(srTransRec.byEntryMode == CARD_ENTRY_WAVE)
		    strcpy(szStr,"Contactless Sale");
		else
		    strcpy(szStr,"Sale");
	}else if(srTransRec.byTransType == VOID)
	{
		memset(szStr, 0x00, sizeof(szStr));
		
		if(srTransRec.byEntryMode == CARD_ENTRY_WAVE)
		    strcpy(szStr,"Contactless Void");
		else
			strcpy(szStr,"Void Sale");
	}
*/
	if (srTransRec.byTransType == SALE_OFFLINE)
		strcpy(szStr, "SMAC PTS");
	else if (srTransRec.byTransType == SALE)
		if(strTCT.fSMMode == FALSE)
			strcpy(szStr, "REDEMPTION");
		else
			strcpy(szStr, "SALE");
	else if (srTransRec.byTransType == SMAC_BALANCE)
		if(strTCT.fSMMode == FALSE)
			strcpy(szStr, "PTS INQUIRY");
		else
			strcpy(szStr, "SMAC BALANCE INQUIRY");		
	else if (srTransRec.byTransType == VOID)
		strcpy(szStr, "VOID");
		
    //vdSetGolbFontAttrib(d_FONT_24x24, DOUBLE_SIZE, NORMAL_SIZE, 0, 0);
    vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	if(srTransRec.byTransType != VOID)
        //vdPrintTitleCenter(szStr);
        vdPrintCenter(szStr);
	else{
	    vdPrintCenterReverseMode(szStr);	
		vdCTOS_PrinterFline(1);
	}
	
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
	EMVtagLen = 0;
	memset(szStr, ' ', d_LINE_SIZE);
	vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);
	
    memset(szTemp, 0x00, sizeof(szTemp));
	//version16
	//if (srTransRec.byTransType == SALE && fSmacScan == TRUE){
	//	memset(srTransRec.szPAN, 0x00, sizeof(srTransRec.szPAN));
	//	strcpy(srTransRec.szPAN,"XXXXXXXXXXXXXXXX");

	//}

	//00188 - [BALANCE INQUIRY] DE02 - PAN is not present in 0100 Request during Balance Inquiry #2
	if (srTransRec.byTransType == SMAC_BALANCE){
		if(strlen(srTransRec.szPAN) <= 0)
			strcpy(srTransRec.szPAN, szSMACBalPAN);
		vdDebug_LogPrintf("ushCTOS_PrintSMACBody szSMACBalPAN");
		
	}

    if(page == BANK_COPY_RECEIPT) /*bank copy*/
        vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp);
    else if(page == CUSTOMER_COPY_RECEIPT) /*customer copy*/
        vdCTOS_FormatPAN2(strIIT.szMaskCustomerCopy, srTransRec.szPAN, szTemp);		
    else if(page == MERCHANT_COPY_RECEIPT) /*merchant copy*/
        vdCTOS_FormatPAN2(strIIT.szMaskMerchantCopy, srTransRec.szPAN, szTemp);

    vdDebug_LogPrintf("ushCTOS_PrintSMACBody KIKO2 srTransRec.byTransType [%d] srTransPara->szPAN: [%s] fSmacScan [%d] srTransRec.fSMACPrintscan [%d]", 
		srTransRec.byTransType, srTransRec.szPAN, fSmacScan, srTransRec.fSMACPrintscan);

	memset(szTemp2, 0x00, sizeof(szTemp2)); 
	memset(szStr, 0x00, d_LINE_SIZE);
	
	inSpace = 5 - (strlen(szTemp) - 20);//5 is number of spaces if card num len is 16(card no)+4(spaces)
	memset(szStr,0X20,inSpace);

	//verrsion16
	if (srTransRec.byTransType == SALE && (fSmacScan == TRUE || srTransRec.fSMACPrintscan)){
		sprintf(szTemp2, "CARD NUM%s: %s", szStr, szTemp); //00133 - SM: Incomplete details printed in barcode for smac qr sareceipt
		
	}else
		sprintf(szTemp2, "CARD NUM%s: %s", szStr, szTemp);

	//sprintf(szTemp2, "CARD NUM     : %s", szTemp);
	
	
	memset(szTemp3, 0x00, sizeof(szTemp3));
	if(srTransRec.byEntryMode==CARD_ENTRY_ICC)
		strcpy(szTemp3,"ICC");
	else if(srTransRec.byEntryMode==CARD_ENTRY_MANUAL)
		strcpy(szTemp3,"MANUAL");
	else if(srTransRec.byEntryMode==CARD_ENTRY_MSR)
		strcpy(szTemp3,"SWIPE");
	else if(srTransRec.byEntryMode==CARD_ENTRY_WAVE)
		strcpy(szTemp3,"TAP");
	else if(srTransRec.byEntryMode==CARD_ENTRY_FALLBACK){
		if((srTransRec.szServiceCode[0] == '2') || (srTransRec.szServiceCode[0] == '6'))
			strcat(szTemp3, "FALLBACK");  
		else			
			strcat(szTemp3, "SWIPE");
	}
	//version16															//00160 - No SCAN label printed in Smac QR void receipt
    else if ((srTransRec.byTransType == SALE || srTransRec.byTransType == VOID) && (fSmacScan == TRUE || srTransRec.fSMACPrintscan)){
		strcpy(szTemp3, "SCAN");
    }
	else if(srTransRec.fVirtualCard == TRUE)
		strcpy(szTemp3, "QR");  
	
	inPrintLeftRight(szTemp2, szTemp3, 42);			
	if(srTransRec.byTransType == SMAC_BALANCE && srTransRec.fPrintExpFlag == TRUE)
	{
		memcpy(szSMACCExpDate, &szField63[12], 8);
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "EXP DATE     : %s", szSMACCExpDate);
		inPrint(szStr);
	}
	
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "CARD TYPE    : %s", srTransRec.szCardLable);
	inPrint(szStr);

	if(srTransRec.byTransType == KIT_SALE)
	{

		
		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szTemp1, 0x00, d_LINE_SIZE);
		memset(szTemp2, 0x00, d_LINE_SIZE);
		memset(szTemp3, 0x00, d_LINE_SIZE);

		memcpy(szTemp1,srTransRec.bySMACPay_MemberSince,2);
		vdSetMonthToText(szTemp1,szTemp2);

		memcpy(szTemp3,&srTransRec.bySMACPay_MemberSince[3],4);
		
		sprintf(szStr,"MEMBER SINCE : %s %s",szTemp2, szTemp3);
		inPrint(szStr);

		
		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szTemp1, 0x00, d_LINE_SIZE);
		memset(szTemp2, 0x00, d_LINE_SIZE);
		memset(szTemp3, 0x00, d_LINE_SIZE);
				
		memcpy(szTemp1,srTransRec.bySMACPay_ExpiryDate,2);
		vdSetMonthToText(szTemp1,szTemp2);

		memcpy(szTemp3,&srTransRec.bySMACPay_ExpiryDate[6],4);
		
		sprintf(szStr,"RENEWAL DATE : %s %s",szTemp2, szTemp3);
		inPrint(szStr);
	}

	
	if(strTCT.fSMMode && strTCT.fPrintIssuerID)
	{
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "ISSUER ID    : %02d", strHDT.inIssuerID);
		inPrint(szStr);
	}
		
	if(srTransRec.byTransType != SMAC_BALANCE)
	{
		//aaronnino for BDOCLG ver 9.0 fix on issue #00066 "APPR.CODE" single width printed on transaction receipt 6 of 8 start
	    memset(szStr, 0x00, d_LINE_SIZE);
	    sprintf(szStr, "APPR CODE    : %s", srTransRec.szAuthCode); 
		inPrint(szStr);

		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "REF NUM      : %s", srTransRec.szRRN);
		inPrint(szStr);
	}

	if(srTransRec.byTransType == RENEWAL)
	{		
		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szTemp1, 0x00, d_LINE_SIZE);
		memset(szTemp2, 0x00, d_LINE_SIZE);
		memset(szTemp3, 0x00, d_LINE_SIZE);
				
		memcpy(szTemp1,srTransRec.bySMACPay_ExpiryDate,2);
		vdSetMonthToText(szTemp1,szTemp2);

		memcpy(szTemp3,&srTransRec.bySMACPay_ExpiryDate[6],4);
		
		sprintf(szStr,"RENEWAL DATE : %s %s",szTemp2, szTemp3);
		inPrint(szStr);
	}
	
	if(srTransRec.byTransType != KIT_SALE && srTransRec.byTransType != RENEWAL)
	{
		memset(szTemp, 0x00, d_LINE_SIZE);
		memset(szTemp1, 0x00, d_LINE_SIZE);
		wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
		wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
		
		vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		memset(szAmountBuff,0x00,sizeof(szAmountBuff));
		memset(szTemp2, 0x00, sizeof(szTemp2));
		
		memset(szStr,0x00, sizeof(szStr));

		if (srTransRec.byTransType == SMAC_BALANCE)		
			strcpy(szStr,"BALANCE:");	
		else
			strcpy(szStr,"AMOUNT");
		
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp, szTemp2);		
		if (srTransRec.byTransType == VOID)
			sprintf(szAmountBuff,"-%s %s", strCST.szCurSymbol, szTemp2);
		else
			sprintf(szAmountBuff,"%s %s", strCST.szCurSymbol, szTemp2);
		
		inPrintLeftRight(szStr,szAmountBuff,24);
	}
	//CTOS_PrinterFline(d_LINE_DOT );

	if (srTransRec.byTransType == SALE_OFFLINE)
	{

		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	

		memset(szTemp1, 0x00, sizeof(szTemp1));
		wub_hex_2_str(srTransRec.SmacPoints, szTemp1, AMT_BCD_SIZE);

		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
		strcpy(szTemp6,"POINTS EARNED");	
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
		sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
		inPrintLeftRight(szTemp6,szAmountBuff,42);
	}

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	if(srTransRec.fPrintSMCardHolder == TRUE || srTransRec.byTransType == SMAC_BALANCE)
		printCardHolderName();
		
	if(srTransRec.fPrintCardHolderBal == TRUE)
	{
		memset(szTemp1, 0x00, sizeof(szTemp1));
		//wub_hex_2_str(srTransRec.SmacBalance, szTemp1, AMT_BCD_SIZE);
		//if(atol(szTemp1)>=0)
		{
			if ((srTransRec.byTransType == SALE || srTransRec.byTransType == VOID))
			{
				vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
			memset(szStr, 0x00, d_LINE_SIZE);
			memset(szAmountBuff,0x00,20);
			memset(szTemp4, 0x00, sizeof(szTemp4));
			memset(szTemp6,0x00, sizeof(szTemp6));
			strcpy(szTemp6,"NEW BALANCE:");	
				//vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp4);// patrick add code 20141216		
				//sprintf(szAmountBuff,"%s PTS",szTemp4);		
				//sprintf(szAmountBuff,"%s %s",strCST.szCurSymbol,szTemp4);
			vdDebug_LogPrintf("srTransRec.szSMACBDORewardsBalance[%s]",srTransRec.szSMACBDORewardsBalance);
			sprintf(szAmountBuff,"%s %s",strCST.szCurSymbol,srTransRec.szSMACBDORewardsBalance);

			
			inPrintLeftRight(szTemp6,szAmountBuff,42);
			}
		}
	}	
	//CTOS_PrinterFline(d_LINE_DOT );
	vdCTOS_PrinterFline(1);

	return d_OK;
}

USHORT ushCTOS_PrintSMGuarantorBody(int page)
{	
	char szStr[d_LINE_SIZE + 1];
	char szTemp[d_LINE_SIZE + 1];
	char szTemp1[d_LINE_SIZE + 1];
	char szTemp2[d_LINE_SIZE + 1];	
	char szTemp3[d_LINE_SIZE + 1];
	char szTemp4[d_LINE_SIZE + 1];
	char szTemp5[d_LINE_SIZE + 1];
	char szTempDate[d_LINE_SIZE + 1];
	char szFormatPAN[strlen(srTransRec.szPAN) + 7];//to account for space as in PAN format and to include additional PAN no. 7 has been added -Meena 08/01/2012
	char szSMACCExpDate[8+1];
	int inFmtPANSize;
	BYTE baTemp[PAPER_X_SIZE * 64];
	USHORT result;
	int num,i,inResult;
	unsigned char tucPrint [24*4+1];	
	BYTE   EMVtagVal[64+1];
	USHORT EMVtagLen; 
	short spacestring;
	BYTE   key;
	int inSpace = 0;

	char szAmountBuff[20+1], szTemp6[47+1];

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	
    printSMDateTime();
	
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "MERCHANT ID  : %s", srTransRec.szMID);
	inPrint(szStr);
	
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "TERMINAL ID  : %s", srTransRec.szTID);
	inPrint(szStr);
	
	memset(szTemp,0x00, sizeof(szTemp));
	wub_hex_2_str(srTransRec.szBatchNo,szTemp,3);
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "BATCH NUM    : %s", szTemp);
	inPrint(szStr);
		
	memset(szTemp,0x00, sizeof(szTemp));
	wub_hex_2_str(srTransRec.szInvoiceNo,szTemp,3);
	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "INVOICE NUM  : %s", szTemp);
	inPrint(szStr);

	if(srTransRec.fBINVer)
	{
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "BIN CHECK    : %06ld", atol(srTransRec.szBINVerSTAN));
		inPrint(szStr);
	}
	
	szGetTransTitle(srTransRec.byTransType, szStr);  
	
	if (srTransRec.byTransType == SALE)
		strcpy(szStr, "SALE");
	else if (srTransRec.byTransType == BALANCE_INQUIRY)
	{
		if(srTransRec.HDTid == SMGIFTCARD_HDT_INDEX)
			strcpy(szStr, "SMGC BALANCE INQUIRY");
		else
			strcpy(szStr, "BALANCE INQUIRY");
	}	
    //vdSetGolbFontAttrib(d_FONT_24x24, DOUBLE_SIZE, NORMAL_SIZE, 0, 0);
    vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

	if(srTransRec.byTransType != VOID)
        //vdPrintTitleCenter(szStr);
        vdPrintCenter(szStr);
	else{
	    vdPrintCenterReverseMode(szStr);	
		vdCTOS_PrinterFline(1);
	}
	
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
	EMVtagLen = 0;
	memset(szStr, ' ', d_LINE_SIZE);
	vdMyEZLib_LogPrintf("CDT index: %d",srTransRec.CDTid);
	
    memset(szTemp, 0x00, sizeof(szTemp)); 
    if(page == BANK_COPY_RECEIPT) /*bank copy*/
        vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp);
    else if(page == CUSTOMER_COPY_RECEIPT) /*customer copy*/
        vdCTOS_FormatPAN2(strIIT.szMaskCustomerCopy, srTransRec.szPAN, szTemp);		
    else if(page == MERCHANT_COPY_RECEIPT) /*merchant copy*/
        vdCTOS_FormatPAN2(strIIT.szMaskMerchantCopy, srTransRec.szPAN, szTemp);

	memset(szTemp2, 0x00, sizeof(szTemp2)); 
	memset(szStr, 0x00, d_LINE_SIZE);
	
	inSpace = 5 - (strlen(szTemp) - 20);//5 is number of spaces if card num len is 16(card no)+4(spaces)
	memset(szStr,0X20,inSpace);

	sprintf(szTemp2, "CARD NUM%s: %s", szStr, szTemp);
	//sprintf(szTemp2, "CARD NUM     : %s", szTemp);
	
	memset(szTemp3, 0x00, sizeof(szTemp3));
	if(srTransRec.byEntryMode==CARD_ENTRY_ICC)
		strcpy(szTemp3,"ICC");
	else if(srTransRec.byEntryMode==CARD_ENTRY_MANUAL)
		strcpy(szTemp3,"MANUAL");
	else if(srTransRec.byEntryMode==CARD_ENTRY_MSR)
		strcpy(szTemp3,"SWIPE");
	else if(srTransRec.byEntryMode==CARD_ENTRY_FALLBACK){
		if((srTransRec.szServiceCode[0] == '2') || (srTransRec.szServiceCode[0] == '6'))
			strcat(szTemp3, "FALLBACK");  
		else			
			strcat(szTemp3, "SWIPE");
	}
	inPrintLeftRight(szTemp2, szTemp3, 42);

	memset(szStr, 0x00, d_LINE_SIZE);
	sprintf(szStr, "CARD TYPE    : %s", srTransRec.szCardLable);
	inPrint(szStr);

	if(strTCT.fSMMode && strTCT.fPrintIssuerID)
	{
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "ISSUER ID    : %02d", strHDT.inIssuerID);
		inPrint(szStr);
	}
		
	if(srTransRec.byTransType != BALANCE_INQUIRY)
	{
		//aaronnino for BDOCLG ver 9.0 fix on issue #00066 "APPR.CODE" single width printed on transaction receipt 6 of 8 start
	    memset(szStr, 0x00, d_LINE_SIZE);
	    sprintf(szStr, "APPR CODE    : %s", srTransRec.szAuthCode); 
		inPrint(szStr);

		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "REF NUM      : %s", srTransRec.szRRN);
		inPrint(szStr);
	}
	
	memset(szTemp, 0x00, d_LINE_SIZE);
	memset(szTemp1, 0x00, d_LINE_SIZE);
	wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
	wub_hex_2_str(srTransRec.szBaseAmount, szTemp1, AMT_BCD_SIZE);
	
	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	memset(szAmountBuff,0x00,sizeof(szAmountBuff));
	memset(szTemp2, 0x00, sizeof(szTemp2));
	
	memset(szStr,0x00, sizeof(szStr));

	if (srTransRec.byTransType == BALANCE_INQUIRY)		
		strcpy(szStr,"BALANCE:");	
	else
		strcpy(szStr,"AMOUNT");

	if (srTransRec.byTransType == BALANCE_INQUIRY)
	{
		memset(szTemp3, 0x00, d_LINE_SIZE);
		wub_hex_2_str(srTransRec.SmacBalance, szTemp3, AMT_BCD_SIZE);
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3, szTemp2);
	}
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp, szTemp2);		

	if (srTransRec.byTransType == VOID)
		sprintf(szAmountBuff,"-%s %s", strCST.szCurSymbol, szTemp2);
	else
		sprintf(szAmountBuff,"%s %s", strCST.szCurSymbol, szTemp2);
	
	inPrintLeftRight(szStr,szAmountBuff,24);
	//CTOS_PrinterFline(d_LINE_DOT );

	if (srTransRec.byTransType == SALE_OFFLINE)
	{

		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	

		memset(szTemp1, 0x00, sizeof(szTemp1));
		wub_hex_2_str(srTransRec.SmacPoints, szTemp1, AMT_BCD_SIZE);

		memset(szStr, 0x00, d_LINE_SIZE);
		memset(szAmountBuff,0x00,20);
		memset(szTemp4, 0x00, sizeof(szTemp4));
		memset(szTemp6,0x00, sizeof(szTemp6));
		strcpy(szTemp6,"POINTS EARNED");	
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
		sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
		inPrintLeftRight(szTemp6,szAmountBuff,42);
	}

//	if(srTransRec.HDTid != SMECARD_HDT_INDEX && srTransRec.HDTid != SMGIFTCARD_HDT_INDEX && srTransRec.HDTid != SMGUARANTOR_HDT_INDEX && srTransRec.HDTid != SMSHOPCARD_HDT_INDEX)
//	{	
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
		if(srTransRec.fPrintSMCardHolder == TRUE && srTransRec.HDTid != SMGIFTCARD_HDT_INDEX && 
			srTransRec.HDTid != SMECARD_HDT_INDEX && srTransRec.HDTid != SMPARTNER_HDT_INDEX)
			printCardHolderName(); 
//	}
	if(srTransRec.fPrintCardHolderBal == TRUE)
	{
		memset(szTemp1, 0x00, sizeof(szTemp1));
			
		wub_hex_2_str(srTransRec.SmacBalance, szTemp1, AMT_BCD_SIZE);
		if(atol(szTemp1)>=0)
		{
			if ( (srTransRec.byTransType == SALE || srTransRec.byTransType == VOID) && srTransRec.HDTid != SMECARD_HDT_INDEX && srTransRec.HDTid != SMPARTNER_HDT_INDEX)
			{
				vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
			
				memset(szStr, 0x00, d_LINE_SIZE);
				memset(szAmountBuff,0x00,20);
				memset(szTemp4, 0x00, sizeof(szTemp4));
				memset(szTemp6,0x00, sizeof(szTemp6));
				strcpy(szTemp6,"NEW BALANCE:");	
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
				sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
				inPrintLeftRight(szTemp6,szAmountBuff,42);
			}
		}
	}
	
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	//CTOS_PrinterFline(d_LINE_DOT );
	vdCTOS_PrinterFline(1);

	return d_OK;
	
}

/*Print ECR Log File -- sidumili*/
void vdPrintISOECRLog()
{
	FILE *ISOFile;
	char szBuf[100] = {0};
	BYTE baTemp[PAPER_X_SIZE*64] = {0};
	
	CTOS_LCDTClearDisplay();

	inTCTRead(1);
	if(strTCT.fECRISOLogging == TRUE)
	{
		ISOFile = fopen(ECRISOLOG_FILE, "r");
		if(ISOFile != NULL)
		{
			CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
			if( printCheckPaper()==-1)
				return -1;
			
			vdSetPrintThreadStatus(1);
			inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_16x16,0," ");
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0); // small font
			CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);	

			fseek(ISOFile, 0, SEEK_SET);
			fgets(szBuf, 80, ISOFile);
			memset(szBuf, 0, sizeof(szBuf));
			do
			{
				memset (szBuf, 0, sizeof(szBuf));		
				fgets(szBuf, 80, ISOFile);
				if(!feof(ISOFile))
				{
					memset (baTemp, 0, sizeof(baTemp));		
					CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szBuf, &stgFONT_ATTRIB);
					CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
				}
			}
			while (!feof(ISOFile));
			fclose(ISOFile);
			
			//CTOS_PrinterFline(d_LINE_DOT * 2); 
			vdCTOS_PrinterFline(2);
		}
		else
		{
			vdDisplayErrorMsg(1, 6, "ECR LOG Empty");
			CTOS_Delay(1000);
		}
	}
}

void vdPrintDCCFooter(void)
{
	char szStr[d_LINE_SIZE + 3];
	char szTemp[d_LINE_SIZE + 3];
	char szFxRate[d_LINE_SIZE + 3];
	char szBaseAmount[20] = {0};
    char szTipAmount[20] = {0};
	char szTotalAmount[AMT_ASC_SIZE+1];
	BYTE szAmtBuff[20+1], szCurAmtBuff[20+1], szDCCAmtBuff[20+1];
	int inLength;
	float inMarkup=0;
	char szLogoPath[50+1];
#if 0
	if(inFLGGet("fPrintForExRate") == TRUE)
	{
		inLength=strlen(srTransRec.szDCCFXRate)-srTransRec.inDCCFXRateMU;
		memset(szFxRate,0x00,sizeof(szFxRate));
		memcpy(szFxRate,srTransRec.szDCCFXRate,inLength);
		memcpy(&szFxRate[inLength],".",1);
		memcpy(&szFxRate[inLength+1],&srTransRec.szDCCFXRate[inLength],srTransRec.inDCCFXRateMU);
		
		memset(szStr,0x00,d_LINE_SIZE);
		sprintf(szStr, "EXCHANGE RATE : %s 1.00 = %s %s", srTransRec.szDCCLocalSymbol, srTransRec.szDCCCurSymbol, szFxRate);	
		inPrint(szStr);
	}
	
	if(inFLGGet("fPrintDCCMarkUp") == TRUE)
	{
		memset(szTemp,0x00,sizeof(szTemp));
		memset(szStr,0x00,sizeof(szStr));
		inMarkup = atof(srTransRec.szDCCMarkupPer);
		sprintf(szTemp,"%.2f",inMarkup);
		sprintf(szStr,"MARK-UP : %s",szTemp);
		strcat(szStr,"%");
		inPrint(szStr);
	}
#endif
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	
		
#if 0

	vdPrintCenter("This currency conversion service is");
	vdPrintCenter("provided by BDO");
	vdPrintCenter("I have been offered a choice to pay");
	vdPrintCenter("in PHP or in Foreign currency.");
	vdPrintCenter("I choose the transaction currency by");
	vdPrintCenter("checking one of the boxes below.");
	CTOS_PrinterFline(d_LINE_DOT);
#endif

	if(srTransRec.byTransType != VOID)
	{
		memset(szBaseAmount,0x00,sizeof(szBaseAmount));
		memset(szTipAmount,0x00,sizeof(szTipAmount));
		memset(szTotalAmount,0x00,sizeof(szTotalAmount));
		memset(szAmtBuff,0x00,sizeof(szAmtBuff));

        /*local amounts*/
		wub_hex_2_str(srTransRec.szDCCLocalTipAmount, szTipAmount, 6);
		wub_hex_2_str(srTransRec.szDCCLocalAmount, szBaseAmount, 6); 
		vdDebug_LogPrintf("LOCAL:: szTipAmount [%s]",szTipAmount);
		vdDebug_LogPrintf("LOCAL:: szDCCLocalAmount [%s]",szBaseAmount);
		//sprintf(szTotalAmount, "%012.0f", atof(szBaseAmount) + ( atof(szTipAmount) / atof(szFxRate))  );
		sprintf(szTotalAmount, "%012.0f", atof(szBaseAmount) + atof(szTipAmount));
		vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTotalAmount,szAmtBuff); 
		sprintf(szCurAmtBuff,"%s%s", srTransRec.szDCCLocalSymbol, szAmtBuff);
		vdDebug_LogPrintf("LOCAL:: szCurAmtBuff [%s]",szCurAmtBuff);
		
		memset(szAmtBuff,0x00,sizeof(szAmtBuff));
		memset(szDCCAmtBuff,0x00,sizeof(szDCCAmtBuff));
		memset(szBaseAmount,0x00,sizeof(szBaseAmount));
		memset(szTipAmount,0x00,sizeof(szTipAmount));
		memset(szTotalAmount,0x00,sizeof(szTotalAmount));

		/*dcc amounts*/
		wub_hex_2_str(srTransRec.szTipAmount, szTipAmount, 6);
	   	wub_hex_2_str(srTransRec.szBaseAmount, szBaseAmount, 6);
		sprintf(szTotalAmount, "%012.0f", atof(szBaseAmount) + atof(szTipAmount));

		if(strTCT.fFormatDCCAmount == TRUE)
    		vdDCCModifyAmount(szTotalAmount,szAmtBuff);
		else
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTotalAmount,szAmtBuff); 
		
		sprintf(szDCCAmtBuff,"%s%s",srTransRec.szDCCCurSymbol, szAmtBuff);// Wait for strCST for foreign currency
		vdDebug_LogPrintf("DCC:: szDCCAmtBuff [%s]",szDCCAmtBuff);

		//inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
		vdCTOSS_PrinterBMPPicEx(0, 0, "./fs_data/dccbox.bmp");
		vdDCCCenter(szCurAmtBuff,szDCCAmtBuff);
		inPrint("Total Transaction     Total Transaction");
		inPrint("      Amount                 Amount");
		sprintf(szTemp,"   %s Currency          %s Currency",srTransRec.szDCCLocalSymbol , srTransRec.szDCCCurSymbol);
		inPrint(szTemp);
	}

}


void vdDCCCenter(unsigned char *szLocCur, unsigned char *szForCur)
{
	unsigned char tucPrint [24*4+1];
	short i;
	short startstring;
	short locBoxCenter=9;
	short forBoxCenter=10;
	USHORT usCharPerLine = 21;
	char szTemp[d_LINE_SIZE + 3];
	char szTemp1[d_LINE_SIZE + 3];

	memset(szTemp,0x00,sizeof(szTemp));
	startstring = locBoxCenter-(strlen(szLocCur)/2);
	//vdDebug_LogPrintf("startstring is %d",startstring);
	
	for(i=0;i<startstring;i++)
		szTemp[i]=0x20;

	strcat(szTemp,szLocCur);
	for(i=strlen(szTemp);i<usCharPerLine;i++)
		szTemp[i]=0x20;
	strcpy(szTemp1,szTemp);
	
	memset(szTemp,0x00,sizeof(szTemp));
	startstring = forBoxCenter-(strlen(szForCur)/2);
	for(i=0;i<startstring;i++)
		szTemp[i]=0x20;

	strcat(szTemp,szForCur);
	strcat(szTemp1,szTemp);

	inPrint(szTemp1);

}

void vdCTOS_PrinterFline(USHORT usLines)
{
	while(usLines > 0)
	{
		//inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
		inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);
		usLines--;
	}
}
void vdCTOS_DCCPrintAccumeByHostAndCard (int inReportType, STRUCT_TOTAL Totals)
{
	char szStr[d_LINE_SIZE + 3] = {0},
		szTemp[d_LINE_SIZE + 3] = {0}, 
		szTemp1[d_LINE_SIZE + 3] = {0}, 
		szTemp2[d_LINE_SIZE + 3] = {0},
		szTemp3[d_LINE_SIZE + 3] = {0}, 
		szTemp4[d_LINE_SIZE + 3] = {0};

	USHORT usTotalCount = 0;
	double ulTotalAmount = 0;
	double ulLocalTotalAmount = 0;
	BYTE baTemp[PAPER_X_SIZE * 64] = {0};

	char szBuff[47] = {0};
	int inPADSize = 0, x = 0;
	char szSPACE[40] = {0};

	//USHORT usSaleCount=(Totals.usSaleCount-Totals.usOffSaleCount)+Totals.usVoidSaleCount;
	USHORT usSaleCount=Totals.usSaleCount;
	//double ulSaleTotalAmount=Totals.ulSaleTotalAmount-Totals.ulOffSaleTotalAmount;
	double ulSaleTotalAmount=Totals.ulSaleTotalAmount;
	USHORT usRefundCount=Totals.usRefundCount;
	double  ulRefundTotalAmount=Totals.ulRefundTotalAmount;	 
	USHORT usVoidSaleCount=Totals.usVoidSaleCount + Totals.usVoidCashAdvCount;
	double  ulVoidSaleTotalAmount=Totals.ulVoidSaleTotalAmount + Totals.ulVoidCashAdvTotalAmount;
	USHORT usOffSaleCount=Totals.usOffSaleCount;
	double  ulOffSaleTotalAmount=Totals.ulOffSaleTotalAmount;
	USHORT usCashAdvCount=Totals.usCashAdvCount;
	double  ulCashAdvTotalAmount=Totals.ulCashAdvTotalAmount;
	USHORT usTipCount=Totals.usTipCount;
	double  ulTipTotalAmount=Totals.ulTipTotalAmount;
	double ulLocalSaleTotalAmount=Totals.ulLocalSaleTotalAmount;
	double  ulLocalVoidSaleTotalAmount=Totals.ulLocalVoidSaleTotalAmount;
	double ulLocalOffSaleTotalAmount=Totals.ulLocalOffSaleTotalAmount;
	double  ulLocalTipTotalAmount=Totals.ulLocalTipTotalAmount;
	double ulLocalRefundTotalAmount=Totals.ulLocalRefundTotalAmount;
	double ulLocalCashAdvTotalAmount=Totals.ulLocalCashAdvTotalAmount;

    
	if(inReportType == PRINT_CARD_TOTAL)
	{
        inHDTReadData(1); //Get the base currency of BDO
        inCSTReadData(strHDT_Temp.inCurrencyIdx);
        CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  
        memset(szTemp, 0x00, d_LINE_SIZE);
        sprintf(szTemp,"          %s      %s",strCST_Temp.szCurSymbol, strCST.szCurSymbol);
        vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
        vdCTOS_PrinterFline(1);
        inCCTOS_PrinterBufferOutput(szTemp,&stgFONT_ATTRIB,1);
        
        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
        //sale
        memset(szStr, 0x00, sizeof(szStr));
        memset(szTemp1, 0x00, sizeof(szTemp1));	
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3));	
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        sprintf(szTemp1,"%.0f", ulLocalSaleTotalAmount+ulLocalOffSaleTotalAmount+ulLocalTipTotalAmount); //local sale
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        
        sprintf(szTemp3,"%.0f", ulSaleTotalAmount+ulOffSaleTotalAmount); //foreign sale
        
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp3,szTemp4);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);
        
        sprintf(szStr,"SALE %04d%16.16s",usSaleCount+usOffSaleCount+usVoidSaleCount, szTemp2);
        inPrintLeftRight2(szStr, szTemp4, 42);
        
        //Base amount
        memset(szStr, 0x00, sizeof(szStr));
        memset(szTemp1, 0x00, sizeof(szTemp1));	
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3));	
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        //sprintf(szTemp1,"%.0f", (ulLocalSaleTotalAmount+ulLocalOffSaleTotalAmount) - ulLocalTipTotalAmount);
        sprintf(szTemp1,"%.0f", (ulLocalSaleTotalAmount+ulLocalOffSaleTotalAmount)); //local base
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        sprintf(szTemp3,"%.0f", (ulSaleTotalAmount+ulOffSaleTotalAmount) - ulTipTotalAmount); //foreign base		
        
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp3,szTemp4);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);
        
        sprintf(szStr,"BASE     %16.16s", szTemp2);
        inPrintLeftRight2(szStr, szTemp4, 42);
        
        //tip
        memset(szStr, 0x00, sizeof(szStr));
        memset(szTemp1, 0x00, sizeof(szTemp1));	
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3));	
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        sprintf(szTemp1,"%.0f", ulLocalTipTotalAmount);
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        sprintf(szTemp3,"%.0f", ulTipTotalAmount);
        
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp3,szTemp4);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);	
        sprintf(szStr,"TIP      %16.16s", szTemp2);
        inPrintLeftRight2(szStr, szTemp4, 42);
        
        //void
        memset(szStr, 0x00, sizeof(szStr));
        memset(szBuff, 0x00, sizeof(szBuff));
        memset(szTemp, 0x00, d_LINE_SIZE);
        memset(szTemp1, 0x00, sizeof(szTemp1));	
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3));	
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        sprintf(szTemp1,"%.0f", ulLocalVoidSaleTotalAmount);
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        sprintf(szTemp,"%.0f", ulVoidSaleTotalAmount);		
        
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp,szTemp3);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp3);
        
        sprintf(szTemp4,"-%s",szTemp3);
        sprintf(szBuff,"-%s",szTemp2);
        sprintf(szStr,"VOID %04d%16.16s",usVoidSaleCount, szBuff);
        inPrintLeftRight2(szStr, szTemp4, 42);

#if 0        
        //refund
        memset(szStr, 0x00, sizeof(szStr));
        memset(szBuff, 0x00, sizeof(szBuff));
        memset(szTemp1, 0x00, sizeof(szTemp1));	
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3));	
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        sprintf(szTemp1,"%.0f", ulLocalRefundTotalAmount);
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        sprintf(szTemp3,"%.0f", ulRefundTotalAmount);	
        
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp3,szTemp4);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);		
        
        sprintf(szStr,"REF. %04d%16.16s",usRefundCount, szTemp2);
        inPrintLeftRight2(szStr, szTemp4, 42);
        
        //Cash Advance
        memset(szStr, 0x00, sizeof(szStr));
        memset(szBuff, 0x00, sizeof(szBuff));
        memset(szTemp1, 0x00, sizeof(szTemp1));	
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3));	
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        sprintf(szTemp1,"%.0f", ulLocalCashAdvTotalAmount);
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        sprintf(szTemp3,"%.0f", ulCashAdvTotalAmount);		
        
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp3,szTemp4);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);		
        sprintf(szStr,"CADV %04d%16.16s",usCashAdvCount, szTemp2);
        inPrintLeftRight2(szStr, szTemp4, 42);
#endif        
        usTotalCount = usSaleCount + usOffSaleCount + usRefundCount+usCashAdvCount+usVoidSaleCount;
        memset(szStr, 0x00, d_LINE_SIZE);
        memset(szTemp, 0x00, d_LINE_SIZE);
        memset(szTemp1, 0x00, sizeof(szTemp1)); 
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3));	
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        ulLocalTotalAmount = (ulLocalSaleTotalAmount+ulLocalOffSaleTotalAmount+ulLocalCashAdvTotalAmount+ulLocalTipTotalAmount) - ulLocalRefundTotalAmount;
        ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount+ulCashAdvTotalAmount) - ulRefundTotalAmount;
        
        sprintf(szTemp1,"%.0f", ulLocalTotalAmount);
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        
        sprintf(szTemp3,"%.0f", ulTotalAmount); 	
        
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp3,szTemp4);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);		
        sprintf(szStr,"TOT. %04d%16.16s",usTotalCount, szTemp2);
        inPrintLeftRight2(szStr, szTemp4, 42);	
	}
	else
    {
        inHDTReadData(1); //Get the base currency of BDO
        inCSTReadData(strHDT_Temp.inCurrencyIdx);
        CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  
        //memset(szTemp, 0x00, d_LINE_SIZE);
        //sprintf(szTemp,"                %s", strCST.szCurSymbol);
        //vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
        //vdCTOS_PrinterFline(1);
        //inCCTOS_PrinterBufferOutput(szTemp,&stgFONT_ATTRIB,1);
        
        vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
        //sale
        memset(szStr, 0x00, sizeof(szStr));
        memset(szTemp1, 0x00, sizeof(szTemp1)); 
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3)); 
        memset(szTemp4, 0x00, sizeof(szTemp4));

        sprintf(szTemp1,"%.0f", ulLocalSaleTotalAmount+ulLocalOffSaleTotalAmount+ulLocalTipTotalAmount); //local sale
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        
        sprintf(szTemp3,"%.0f", ulSaleTotalAmount+ulOffSaleTotalAmount); //foreign sale

		strcpy(szTemp4, strCST.szCurSymbol);
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp3,&szTemp4[3]);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,&szTemp4[3]);
        
        sprintf(szStr,"SALE %04d%16.16s",usSaleCount+usOffSaleCount+usVoidSaleCount, " ");
        inPrintLeftRight2(szStr, szTemp4, 42);
        
        //Base amount
        memset(szStr, 0x00, sizeof(szStr));
        memset(szTemp1, 0x00, sizeof(szTemp1)); 
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3)); 
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        //sprintf(szTemp1,"%.0f", (ulLocalSaleTotalAmount+ulLocalOffSaleTotalAmount) - ulLocalTipTotalAmount);
        sprintf(szTemp1,"%.0f", (ulLocalSaleTotalAmount+ulLocalOffSaleTotalAmount)); //local base
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        sprintf(szTemp3,"%.0f", (ulSaleTotalAmount+ulOffSaleTotalAmount) - ulTipTotalAmount); //foreign base		
        
		strcpy(szTemp4, strCST.szCurSymbol);
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp3,&szTemp4[3]);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,&szTemp4[3]);
        
        sprintf(szStr,"BASE     %16.16s", " ");
        inPrintLeftRight2(szStr, szTemp4, 42);
        
        //tip
        memset(szStr, 0x00, sizeof(szStr));
        memset(szTemp1, 0x00, sizeof(szTemp1)); 
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3)); 
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        sprintf(szTemp1,"%.0f", ulLocalTipTotalAmount);
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        sprintf(szTemp3,"%.0f", ulTipTotalAmount);
        
		strcpy(szTemp4, strCST.szCurSymbol);
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp3,&szTemp4[3]);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,&szTemp4[3]);
        sprintf(szStr,"TIP      %16.16s", " ");
        inPrintLeftRight2(szStr, szTemp4, 42);
        
        //void
        memset(szStr, 0x00, sizeof(szStr));
        memset(szBuff, 0x00, sizeof(szBuff));
        memset(szTemp, 0x00, d_LINE_SIZE);
        memset(szTemp1, 0x00, sizeof(szTemp1));	
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3));	
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        //sprintf(szTemp1,"%.0f", ulLocalVoidSaleTotalAmount);
        //vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        sprintf(szTemp,"%.0f", ulVoidSaleTotalAmount);	
		
		strcpy(szTemp3, strCST.szCurSymbol);		
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp,&szTemp3[3]);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,&szTemp3[3]);
        
        sprintf(szTemp4,"-%s",szTemp3);
        //sprintf(szBuff,"-%s",szTemp2);
        sprintf(szStr,"VOID %04d%16.16s",usVoidSaleCount, " ");
        inPrintLeftRight2(szStr, szTemp4, 42);
#if 0
        //refund
        memset(szStr, 0x00, sizeof(szStr));
        memset(szBuff, 0x00, sizeof(szBuff));
        memset(szTemp1, 0x00, sizeof(szTemp1)); 
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3)); 
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        sprintf(szTemp1,"%.0f", ulLocalRefundTotalAmount);
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        sprintf(szTemp3,"%.0f", ulRefundTotalAmount);	
        
		strcpy(szTemp4, strCST.szCurSymbol);
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp3,&szTemp4[3]);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,&szTemp4[3]);
        
        sprintf(szStr,"REF. %04d%16.16s",usRefundCount, " ");
        inPrintLeftRight2(szStr, szTemp4, 42);
        
        //Cash Advance
        memset(szStr, 0x00, sizeof(szStr));
        memset(szBuff, 0x00, sizeof(szBuff));
        memset(szTemp1, 0x00, sizeof(szTemp1)); 
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3)); 
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        sprintf(szTemp1,"%.0f", ulLocalCashAdvTotalAmount);
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        sprintf(szTemp3,"%.0f", ulCashAdvTotalAmount);		
        
		strcpy(szTemp4, strCST.szCurSymbol);
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp3,&szTemp4[3]);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,&szTemp4[3]);
        sprintf(szStr,"CADV %04d%16.16s",usCashAdvCount, " ");
        inPrintLeftRight2(szStr, szTemp4, 42);
#endif        
        usTotalCount = usSaleCount + usOffSaleCount + usRefundCount+usCashAdvCount+usVoidSaleCount;
        memset(szStr, 0x00, d_LINE_SIZE);
        memset(szTemp, 0x00, d_LINE_SIZE);
        memset(szTemp1, 0x00, sizeof(szTemp1)); 
        memset(szTemp2, 0x00, sizeof(szTemp2));
        memset(szTemp3, 0x00, sizeof(szTemp3)); 
        memset(szTemp4, 0x00, sizeof(szTemp4));
        
        ulLocalTotalAmount = (ulLocalSaleTotalAmount+ulLocalOffSaleTotalAmount+ulLocalCashAdvTotalAmount+ulLocalTipTotalAmount) - ulLocalRefundTotalAmount;
        ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount+ulCashAdvTotalAmount) - ulRefundTotalAmount;
        
        sprintf(szTemp1,"%.0f", ulLocalTotalAmount);
        vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp1,szTemp2);
        
        sprintf(szTemp3,"%.0f", ulTotalAmount); 	
        
		strcpy(szTemp4, strCST.szCurSymbol);
        if(strTCT.fFormatDCCAmount == TRUE)// handling for DCC
            vdDCCModifyAmount(szTemp3,&szTemp4[3]);
        else
            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,&szTemp4[3]);
        sprintf(szStr,"TOT. %04d%16.16s",usTotalCount, " ");
        inPrintLeftRight2(szStr, szTemp4, 42);	
    }
	vdCTOS_PrinterFline(1);
}

void vdPrintISOLog()
{
	FILE *ISOFile;
	char szBuf[100] = {0};
	BYTE baTemp[PAPER_X_SIZE*64] = {0};
/*
	//for MP200 no need print
	if (isCheckTerminalMP200() == d_OK)
    	return (d_OK);
*/
	vduiLightOn();
	
	if( printCheckPaper()==-1)
	return d_NO;                

	vdCTOSS_PrinterStart(100); // For fast printing
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
	
	CTOS_LCDTClearDisplay();

	inTCTRead(1);
	if(strTCT.fISOLogging == TRUE)
	{
		if((ISOFile = fopen(ISOLOG_FILE, "r+t")) != NULL)
		{
			CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
			if( printCheckPaper()==-1)
				return -1;
			
			//vdSetPrintThreadStatus(1);
			vdDisplayAnimateBmp(0,0, "Print1.bmp", "Print2.bmp", "Print3.bmp", NULL, NULL);
			inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_16x16,0," ");
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0); // small font
			CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);	

			fseek(ISOFile, 0, SEEK_SET);
			fgets(szBuf, 80, ISOFile);
			memset(szBuf, 0, sizeof(szBuf));
			do
			{
				memset (szBuf, 0, sizeof(szBuf));		
				fgets(szBuf, 80, ISOFile);
				if(!feof(ISOFile))
				{
					#if 0
					memset (baTemp, 0, sizeof(baTemp));		
					CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szBuf, &stgFONT_ATTRIB);
					CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
					#else
					inPrint(szBuf);
					#endif
				}
			}
			while (!feof(ISOFile));
			fclose(ISOFile);
			
			//CTOS_PrinterFline(d_LINE_DOT * 6); 
			vdCTOS_PrinterFline(5); // For fast printing
		}
		else
		{
			vdDisplayErrorMsg(1, 6, "ISOLOG Empty");
			CTOS_Delay(1000);
		}
	}

	vdLineFeed(FALSE);
	
	vdCTOSS_PrinterEnd(); //For fast printing
	
}

USHORT ushCTOS_ReprintLastSettleReportAll(void)
{
	ACCUM_REC srAccumRec;
	unsigned char chkey;
	short shHostIndex;
	int inResult,inRet;
	int inTranCardType;
	int inReportType;
	int inIITNum , i;
	char szStr[d_LINE_SIZE + 1];
	BYTE baTemp[PAPER_X_SIZE * 64];

	//for MP200 no need print
	if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
    	return (d_OK);
	
	if( printCheckPaper()==-1)
		return;

		srTransRec.MITid = strNMT[0].NMTID; 

	if (inMultiAP_CheckMainAPStatus() == d_OK)
	{
		inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_REPRINT_LAST_SETT);
		if(d_OK != inRet)
			return inRet;
	}
	else
	{
		if (inMultiAP_CheckSubAPStatus() == d_OK)
		{
			inRet = inCTOS_MultiAPGetData();
			if(d_OK != inRet)
				return inRet;

			inRet = inCTOS_MultiAPReloadHost();
			if(d_OK != inRet)
				return inRet;
		}
	}


	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

	memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
	inResult = inCTOS_ReadBKAccumTotal(&srAccumRec,strHDT.inHostIndex,srTransRec.MITid);
	if(inResult == ST_ERROR)
	{
	    //vdSetErrorMessage("NO RECORD FOUND");
	    vdDisplayErrorMsgResp2("","TRANSACTION","NOT FOUND");
		vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
		return ST_ERROR;	
	}		 
	else if(inResult == RC_FILE_READ_OUT_NO_DATA)
	{
	    //vdSetErrorMessage("NO RECORD FOUND");
	    vdDisplayErrorMsgResp2("","TRANSACTION","NOT FOUND");
		return;
	}	 
    strcpy(srTransRec.szTID, srAccumRec.szTID);
    strcpy(srTransRec.szMID, srAccumRec.szMID);
    memcpy(srTransRec.szYear, srAccumRec.szYear, DATE_BCD_SIZE);
    memcpy(srTransRec.szDate, srAccumRec.szDate, DATE_BCD_SIZE);
    memcpy(srTransRec.szTime, srAccumRec.szTime, TIME_BCD_SIZE);
    memcpy(srTransRec.szBatchNo, srAccumRec.szBatchNo, BATCH_NO_BCD_SIZE);

	vdSetPrintThreadStatus(1); /*BDO: Display printing image during report -- sidumili*/
	
    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
    
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	ushCTOS_PrintHeader(0);	
    
    //vdPrintTitleCenter("LAST SETTLE");
    
	//CTOS_PrinterFline(d_LINE_DOT * 1);
	//vdCTOS_PrinterFline(1);

	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);

	vdPrintCenter("DUPLICATE");

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    
	printTIDMID(TRUE);
    
	printDateTime();
    
	printBatchNO();

	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	
/* BDO PHASE2: [Print Settlement Closed for last settle receipt] -- sidumili*/	
#if 0
	if (srTransRec.byTransType == SETTLE)
		vdPrintCenter("SETTLEMENT CLOSED");
	else
		vdPrintCenter("SUMMARY REPORT");
#else
    if(srAccumRec.fManualSettlement == TRUE)
        vdPrintCenter("SUMMARY REPORT");
    else
    {
		vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
		vdPrintCenter("SETTLEMENT CLOSED");		
		vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 0, 0);
		vdPrintCenter("    *** TRANSACTION TOTALS BY ISSUER ***");
    }
#endif
/* BDO PHASE2: [Print Settlement Closed for last settle receipt] -- sidumili*/	
	
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);


    //CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);
	for(inTranCardType = 0; inTranCardType < 1 ;inTranCardType ++)
	{
		if(srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMGIFTCARD_HDT_INDEX)
			inTranCardType = 1;
		
		inReportType = PRINT_CARD_TOTAL;
		
		if(inReportType == PRINT_CARD_TOTAL)
		{
			for(i= 0; i <30; i ++ )
			{
				vdDebug_LogPrintf("--Count[%d]", i);
				if((srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount == 0)
				&&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount == 0))
					continue;
				
				vdDebug_LogPrintf("Count[%d]", i); 
				inIITRead(i);
				memset(szStr, ' ', d_LINE_SIZE);
				memset (baTemp, 0x00, sizeof(baTemp));
				//strcpy(szStr,strIIT.szIssuerLabel);
				sprintf(szStr,"ISSUER: %s",strIIT.szIssuerLabel);
				//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
				//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

				if (inCheckIfSMCardTransRec() == TRUE){
					vdCTOS_PrintAccumeByHostAndCard (inReportType,
					/*issue-00043*/
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount,   
					(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) ,									
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 
					//issue-00296-add void cash advance 				
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
					(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 								
					//srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount), 
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount));	


				}else{
				
					if(inCheckIfDCCHost() == TRUE)
		 				vdCTOS_DCCPrintAccumeByHostAndCard (inReportType, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i]);
					else
						vdCTOS_PrintAccumeByHostAndCard (inReportType, 
						/*issue-00043*/
													srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount  + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount,   
													(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
													
													srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 

													//issue-00296-add void cash advance 				
													srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
													(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 
													
													//srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount), 

													srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),

													srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),

													srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount)

													);	
					}
				}
			//after print issuer total, then print host toal
			{

				if (inCheckIfSMCardTransRec() == TRUE){

				}
				else
				{
					memset(szStr, ' ', d_LINE_SIZE);
					memset (baTemp, 0x00, sizeof(baTemp));
					strcpy(szStr,"GRAND TOTALS");
					//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
					//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
					inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
					vdCTOS_PrintAccumeByHostAndCard (inReportType, 
						/*issue-00043*/
														(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount) +
															srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, 	
														(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
														
														srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
														//issue-00296-add void cash advance 									
														srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
														(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
														
														//srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount), 

														srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),

														srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),

					srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount)

														);		
				}
			}
		}
		else
		{
		
			memset(szStr, ' ', d_LINE_SIZE);
			memset (baTemp, 0x00, sizeof(baTemp));
			strcpy(szStr,srTransRec.szHostLabel);
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			vdCTOS_PrintAccumeByHostAndCard (inReportType, 
				/*issue-00043*/				
												srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount	+ srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount,   
												(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
												
												srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
												//issue-00296-add void cash advance 									
												srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
												(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
												
												//srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, 
												//(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount), 

												srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),

												srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),

			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount)

												);		
		}
	}
	
	//print space one line
	///CTOS_PrinterFline(d_LINE_DOT * 2);		
	//CTOS_PrinterFline(d_LINE_DOT * 2);
	//CTOS_PrinterFline(d_LINE_DOT * 2);
	vdCTOS_PrinterFline(6);
	vdCTOSS_PrinterEnd();
	
	if(srAccumRec.fManualSettlement == TRUE)
         vdCTOS_PrintManualPosting();

	vdSetPrintThreadStatus(0); /*BDO: Display printing image during report -- sidumili*/

	
	
	return d_OK;	
}

void vdCTOS_SMHostInfo(void){
	int shHostIndex = 1, inNumOfMerchant=0;
	int inResult,inRet;
	unsigned char szCRC[8+1];
	char ucLineBuffer[d_LINE_SIZE];
	BYTE baTemp[PAPER_X_SIZE * 64];
	int inLoop = 0;
	char szBillerName[1024] = {0};
	char szBillerCode[1024] = {0};
	char szStr[d_LINE_SIZE + 1];
	BYTE szTempBuf[12+1];
	BYTE szBuf[50];

	int inNumOfHost;
	int inNum;
	int inHostEnb;
	int inApp;
	char szAPName[20+1];
	int inCount=1;
	int inHDTIndex=0, inHDTid[150];
		
	vdDebug_LogPrintf("-->>vdCTOS_HostInfo[START]");
	
	vduiLightOn();								

	memset(szAPName,0x00,sizeof(szAPName));
	inApp = inHostInfoAppSelection(szAPName);
	if(FAIL == inApp)
		return inApp;
	if( printCheckPaper()==-1)
    	return;
		
	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

	vdDebug_LogPrintf("[Merchant ID %d", srTransRec.MITid);


	inNumOfHost = inHDTNumRecord();
	vdDebug_LogPrintf("inNumOfHost=[%d]-----",inNumOfHost);

	inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	inMMTReadRecord(1, srTransRec.MITid);/*temporary - need to reload MMT record for receipt header*/

	vdSetPrintThreadStatus(1); /*BDO:Display printing image during report -- sidumili*/

	vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  
	ushCTOS_PrintHeader(0);

	//CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);

	//vdPrintTitleCenter("HOST INFO REPORT");
	//CTOS_PrinterFline(d_LINE_DOT * 1);
	//vdCTOS_PrinterFline(1);

	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
    vdPrintCenter("HOST INFO REPORT");
	vdCTOS_PrinterFline(1);
	
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	printDateTime();

	inNumOfHost=inHDTReadHostID(szAPName, inHDTid);
	inHostEnb=1;
	for(inNum =1 ;inNum <= inNumOfHost; inNum++)
	{
        inHDTIndex=inHDTid[inNum-1];
		//if(inHDTRead(inHDTIndex) == d_OK)
		if(inHDTReadinSequence(inHDTIndex) == d_OK)
		{	
			if(strcmp(strHDT.szAPName,szAPName) == 0)
			{
				if( printCheckPaper()==-1) //aaronnino SM Ver 12 fix on PRINTING: �OUT OF PAPER� is not displayed when printing HOST INFO REPORT.
					return;
				else
					vdSetPrintThreadStatus(1); /*BDO:Display printing image during report -- sidumili*/
			
			    if(strTCT.fSingleComms == FALSE)
				    //inCPTRead(inHDTIndex);
				    inCPTRead(strHDT.inHostIndex);
				
				//vdDebug_LogPrintf("[HOST %d MID %d", strHDT.inHostIndex, srTransRec.MITid);

				inMMTReadRecord(strHDT.inHostIndex,srTransRec.MITid);
				
				//vdDebug_LogPrintf("[read MMT fail]-Mitid[%d]strHDT.inHostIndex[%d]inResult[%d]", inLoop,strHDT.inHostIndex,inResult);

				//vdDebug_LogPrintf("[inNumOfMerchant]-[%d]strHDT.inHostIndex[%d]", inNumOfMerchant,strHDT.inHostIndex);
				
				//inCCTOS_PrinterBufferOutput("__________________________________________",&stgFONT_ATTRIB,1);
				inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
				memset(szStr, 0x00, d_LINE_SIZE);
				sprintf(szStr, "  HOST NAME: %s", (char *)strHDT.szHostLabel);
				inPrint(szStr);

				memset(szStr, 0x00, sizeof(szStr));
				sprintf(szStr, "TERMINAL ID: %s", strMMT[0].szTID); 											 
				inPrint(szStr);

				memset(szStr, 0x00, sizeof(szStr));
				sprintf(szStr, "MERCHANT ID: %s", strMMT[0].szMID); 											 
				inPrint(szStr);
#if 0			
				memset(szTempBuf, 0x00, sizeof(szTempBuf));
				wub_hex_2_str(strHDT.szTPDU,szTempBuf,5);
				sprintf(szStr, "  TPDU     : %s", szTempBuf);
				inPrint(szStr);
#endif
				memset(szTempBuf, 0x00, sizeof(szTempBuf));
				wub_hex_2_str(strHDT.szNII,szTempBuf,2);
				sprintf(szStr, "        NII: %s", szTempBuf);
				inPrint(szStr);

				if (strTCT.fSingleComms != TRUE)
				{	
					
					memset(szStr, 0x00, d_LINE_SIZE);
					sprintf(szStr, "    PRI NUM: %s", (char *)strCPT.szPriTxnPhoneNumber);
					inPrint(szStr);
	
					memset(szStr, 0x00, d_LINE_SIZE);
					sprintf(szStr, "    SEC NUM: %s", (char *)strCPT.szSecTxnPhoneNumber);
					inPrint(szStr);
#if 0
	
					memset(szStr, 0x00, d_LINE_SIZE);
				sprintf(szStr, "  PRI IP   : %s", (char *)strCPT.szPriTxnHostIP);
					inPrint(szStr);
	
					memset(szStr, 0x00, d_LINE_SIZE);
				sprintf(szStr, "  PRI PORT : %04d", strCPT.inPriTxnHostPortNum);
					inPrint(szStr);
	
					memset(szStr, 0x00, d_LINE_SIZE);
				sprintf(szStr, "  SEC IP   : %s", (char *)strCPT.szSecTxnHostIP);
					inPrint(szStr);
	
					memset(szStr, 0x00, d_LINE_SIZE);
				sprintf(szStr, "  SEC PORT : %04d", strCPT.inSecTxnHostPortNum);
					inPrint(szStr);
#endif
					
				}

				inPrint(" ");

				//inMMTReadNumofRecords(strHDT.inHostIndex,&inNumOfMerchant);
#if 0
				vdDebug_LogPrintf("[HOST %d MID %d", strHDT.inHostIndex, srTransRec.MITid);
	
				
				inMMTReadRecord(strHDT.inHostIndex,srTransRec.MITid);
				
				vdDebug_LogPrintf("[read MMT fail]-Mitid[%d]strHDT.inHostIndex[%d]inResult[%d]", inLoop,strHDT.inHostIndex,inResult);
	
				vdDebug_LogPrintf("[inNumOfMerchant]-[%d]strHDT.inHostIndex[%d]", inNumOfMerchant,strHDT.inHostIndex);
	
				memset(szStr, 0x00, sizeof(szStr));
#ifdef SINGE_HEADER_FOOTER_TEXT
				inNMTReadRecord(srTransRec.MITid);
				sprintf(szStr, "  MERCHANT : %s", strSingleNMT.szMerchName);
#else
				sprintf(szStr, "  MERCHANT : %s", strMMT[0].szMerchantName); 
#endif
				inPrint(szStr);
	
				memset(szStr, 0x00, sizeof(szStr));
				sprintf(szStr, "  TID	   : %s", strMMT[0].szTID); 											 
				inPrint(szStr);
	
				memset(szStr, 0x00, sizeof(szStr));
				sprintf(szStr, "  MID	   : %s", strMMT[0].szMID); 											 
				inPrint(szStr);
	
				memset(szStr, 0x00, sizeof(szStr));
				memset(szBuf, 0x00, sizeof(szBuf));
				wub_hex_2_str(strMMT[0].szBatchNo, szBuf, 3);
				sprintf(szStr, "  BATCH NO : %s", szBuf);											 
				inPrint(szStr);
				vdCTOS_PrinterFline(1);
#endif
				if( (inCount%10) == 0)
				{
					vdCTOSS_PrinterEnd();
					vdCTOSS_PrinterStart(100);
					CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel); 
				}
				inCount++;

			}	
		}		

	 }

	if (strTCT.fSingleComms == TRUE)
	{	
		inCPTRead(1);
		
		inCCTOS_PrinterBufferOutput("__________________________________________",&stgFONT_ATTRIB,1);
		inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
		
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "    PRI NUM: %s", (char *)strCPT.szPriTxnPhoneNumber);
		inPrint(szStr);
	
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "    SEC NUM: %s", (char *)strCPT.szSecTxnPhoneNumber);
		inPrint(szStr);
#if 0	
		memset(szStr, 0x00, d_LINE_SIZE);
		//sprintf(szStr, "PRI IP	  : %s", (char *)strCPT.szPriTxnHostIP);
		sprintf(szStr, "  PRI IP   : %s", (char *)strCPT.szPriTxnHostIP);
		inPrint(szStr);
	
		memset(szStr, 0x00, d_LINE_SIZE);
		//sprintf(szStr, "PRI IP PORT : %04d", strCPT.inPriTxnHostPortNum);
		sprintf(szStr, "  PRI PORT : %04d", strCPT.inPriTxnHostPortNum);
		inPrint(szStr);
	
		memset(szStr, 0x00, d_LINE_SIZE);
		//sprintf(szStr, "SEC IP	  : %s", (char *)strCPT.szSecTxnHostIP);
		sprintf(szStr, "  SEC IP   : %s", (char *)strCPT.szSecTxnHostIP);
		inPrint(szStr);
	
		memset(szStr, 0x00, d_LINE_SIZE);
		//sprintf(szStr, "SEC IP PORT : %04d", strCPT.inSecTxnHostPortNum);
		sprintf(szStr, "  SEC PORT : %04d", strCPT.inSecTxnHostPortNum);
		inPrint(szStr);
#endif

		//inPrint(" ");
		
		//vdCTOS_PrinterFline(1);

	}
	
	//CTOS_PrinterFline(d_LINE_DOT * 5);
	vdCTOS_PrinterFline(6);
	
	vdCTOSS_PrinterEnd();

	vdSetPrintThreadStatus(0); /*BDO:Display printing image during report -- sidumili*/
	
	vdDebug_LogPrintf("-->>vdCTOS_HostInfo[END]");

}

void vdGetSignatureFilename(char *ptrNewFilename)
{
	char szNewFileName[24+1];
    char szInvoiceNo[6+1];
    
    memset(szInvoiceNo, 0x00, sizeof(szInvoiceNo));
    wub_hex_2_str(srTransRec.szInvoiceNo, szInvoiceNo, INVOICE_BCD_SIZE);
    
    memset(szNewFileName, 0x00, sizeof(szNewFileName));
    sprintf(szNewFileName, "signERM%06ld.bmp", atol(szInvoiceNo));
	memcpy(ptrNewFilename, szNewFileName, strlen(szNewFileName));
}

int ushCTOS_ePadSignature(void)
{
    BYTE   EMVtagVal[64];
    USHORT EMVtagLen; 
    ULONG ulFileSize;
	char szNewFileName[24+1];
	int fNSRflag = 0;
	
	if (FALSE ==strTCT.fSignatureFlag)
		return d_OK;

    if(strIIT.fNSR == 1)
    {
		if(inNSRFlag() == 1) /*VEPS below floorlimit*/
            return d_OK;			
    }
	
    memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
    EMVtagLen = 0;
    
    if(srTransRec.byEntryMode==CARD_ENTRY_ICC)
    {
        EMVtagLen = 3;
        memcpy(EMVtagVal, srTransRec.stEMVinfo.T9F34, EMVtagLen);
        if (((EMVtagVal[0] != 0x03) && (EMVtagVal[0] != 0x05) &&
        (EMVtagVal[0] != 0x1E) &&
        (EMVtagVal[0] != 0x5E)) || (EMVtagVal[0] == 0x3F))
        {
            return d_OK;	   	
        }
    }
	else if( srTransRec.byEntryMode == CARD_ENTRY_WAVE)
	{
		if(srTransRec.bWaveSCVMAnalysis != d_CVM_REQUIRED_SIGNATURE)
		{
            return d_OK;
		}
	}
	
	ePad_SignatureCaptureLibEx();
	return d_OK;
}

int ushCTOS_ePadPrintSignature(void)
{
    char szNewFileName[24+1];
    LONG lFileSize;
	
	if (FALSE ==strTCT.fSignatureFlag)
		return d_NO;

	if(srTransRec.byTransType == VOID 
		|| srTransRec.byTransType == SALE_TIP)
		return d_NO;

    vdDebug_LogPrintf("ushCTOS_ePadPrintSignature");

    if(fRePrintFlag == TRUE /*&& fRePrintPwrFailFlag == FALSE*/)
    {
        memset(szNewFileName, 0x00, sizeof(szNewFileName));	
        vdGetSignatureFilename(&szNewFileName);
        lFileSize=lnGetFileSize(szNewFileName);
        vdDebug_LogPrintf("szNewFileName:[%s], ulFileSize:[%ld]",szNewFileName, lFileSize);
        if(lFileSize > 0)
        {
            vdCTOS_PrinterFline(1);
            vdCTOSS_PrinterBMPPicEx(0, 0, szNewFileName);
            inCTOSS_ReadERMSignatureFile(VFBMPONAME);
            return d_OK;
        }
    }
	else
	{
		lFileSize=lnGetFileSize(DB_SIGN_BMP);
		vdDebug_LogPrintf("DB_SIGN_BMP:[%s], ulFileSize:[%ld]",DB_SIGN_BMP, lFileSize);
		if(lFileSize > 0)
		{
			vdCTOS_PrinterFline(1);
			vdCTOSS_PrinterBMPPicEx(0, 0, DB_SIGN_BMP);
			inCTOSS_ReadERMSignatureFile(VFBMPONAME);
			return d_OK;
		}		
	}
	
	return d_NO;
}

int ushCTOS_ClearePadSignature(void)
{
	if (FALSE ==strTCT.fSignatureFlag)
		return d_OK;
	
	ePad_ClearSignatureCaptureLib();
	return d_OK;
}

void vdPrintISOOption(unsigned char *pucTitle,unsigned char *uszData, int inLen)
{
	//inTCTRead(1);
	//if(strTCT.inPrintISOOption == 1 || strEFTPub.inEFTEnable == 1)
	if(strTCT.inPrintISOOption == 1)
	{
		if(memcmp(pucTitle,"RX",2) == 0 && strCPT.inCommunicationMode == DIAL_UP_MODE)
			inPrintISOPacket(pucTitle , uszData, inLen-2);
		else
			inPrintISOPacket(pucTitle , uszData, inLen);
	}
	else if(strTCT.inPrintISOOption == 2)
	{
		vdPrintParseISO(srTransRec.byTransType,pucTitle ,uszData+5);
	}
	else if(strTCT.inPrintISOOption == 3)
	{
		if(memcmp(pucTitle,"RX",2) == 0 && strCPT.inCommunicationMode == DIAL_UP_MODE)
			inPrintISOPacket(pucTitle , uszData, inLen-2);
		else
			inPrintISOPacket(pucTitle , uszData, inLen);
		
		vdPrintParseISO(srTransRec.byTransType,pucTitle ,uszData+5);
	}

}

/*albert - start - 20161202 - Reprint of Detail Report for Last Settlement Report*/
void vdCTOS_PrintSettleMerchantDetailReport(void)
{
    unsigned char chkey;
    short shHostIndex;
    int inResult,i,inCount,inRet;
    int inTranCardType;
    int inReportType;
    int inBatchNumOfRecord;
    int *pinTransDataid;
    
    ACCUM_REC srAccumRec;
    BYTE baTemp[PAPER_X_SIZE * 64];
    char szStr[d_LINE_SIZE + 1];

		//int inRet = d_NO;
		int inNumOfHost = 0, inNum = 0;
		char szBcd[INVOICE_BCD_SIZE+1] = {0};
		char szErrMsg[31] = {0};
		char szAPName[25] = {0};
		int inAPPID = 0;
    BOOL fPrintDetail=FALSE;

	
	vdDebug_LogPrintf("vdCTOS_PrintSettleMerchantDetailReport");

    inCSTRead(strHDT.inCurrencyIdx); /*to load Currence and amount format*/
	
	vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);

	vdPrintReportDisplayBMP();

    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
    vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);

    //ushCTOS_printBatchRecordHeader();
    ushCTOS_ReprintBatchRecordHeader();

    //inBatchNumOfRecord = inBatchNumRecord();
    //change to include even pre-auth, function ushCTOS_printBatchRecordFooter will just exclude the pre-auth trans during printing
    //inBatchNumOfRecord = inBatchNumALLRecord();
    inBatchNumOfRecord = inBackupDetailReportNumRecord();
	
    pinTransDataid = (int*)malloc(inBatchNumOfRecord  * sizeof(int));
    inCount = 0;		
    //inBatchByMerchandHost(inBatchNumOfRecord, srTransRec.HDTid, srTransRec.MITid, srTransRec.szBatchNo, pinTransDataid);
    inBatchByDetailReport(inBatchNumOfRecord, srTransRec.HDTid, srTransRec.MITid, pinTransDataid);
    for(i=0; i<inBatchNumOfRecord; i++)
    {
        //inResult = inDatabase_BatchReadByTransId(&srTransRec, pinTransDataid[inCount]);
        inResult = inDatabase_ReadDetailReport(&srTransRec, pinTransDataid[inCount]);
        inCount ++;
        ushCTOS_printBatchRecordFooter();	
    }

    free(pinTransDataid);
	
    memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    //if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
    if((inResult = inCTOS_ReadBKAccumTotal(&srAccumRec,strHDT.inHostIndex,srTransRec.MITid)) == ST_ERROR)
    {
        vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
        return; 	 
    }

    //CTOS_PrinterFline(d_LINE_DOT * 1);
    //CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(2);
    
    memset(baTemp, 0x00, sizeof(baTemp));
    //sprintf(szStr,"CARD TYPE        COUNT         AMT");
    sprintf(szStr,"CARD TYPE        COUNT                 AMT");
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

    for(inTranCardType = 0; inTranCardType < 1 ;inTranCardType ++)
    {
		if(srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMGIFTCARD_HDT_INDEX)
			inTranCardType = 1;
						
        inReportType = DETAIL_REPORT_TOTAL;
        
        //for(i= 0; i <30; i ++ )
        for(i= 0; i <37; i ++ )
        {
            vdDebug_LogPrintf("--Count[%d]", i);
            if((srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount == 0)
            &&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount == 0)
            &&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount == 0)
            &&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount == 0)
            //issue-00270 - show card type in Detail Report Totals per card even if cash advance is the only transaction
            &&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount == 0)
            &&(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount == 0))
                continue;
            
            vdDebug_LogPrintf("Count[%d]", i); 
            inIITRead(i);
            memset(szStr, ' ', d_LINE_SIZE);
            memset (baTemp, 0x00, sizeof(baTemp));

			//00148 - No card type prints in Detail report	and manual settlement  with detail receipt for BDO Loyalty #2
			#if 1
			strcpy(szStr,strIIT.szIssuerLabel);
			//sprintf(szStr,"ISSUER: %s",strIIT.szIssuerLabel);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			#endif

				
            inCSTRead(strHDT.inCurrencyIdx);

			if (inCheckIfSMCardTransRec() == TRUE){
            	vdCTOS_PrintAccumeByHostAndCard (inReportType, 
				//deduct void cash advance on Detail total
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount, 	
            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount),
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount));	

			}else{

            	vdCTOS_PrintAccumeByHostAndCard (inReportType, 
				//deduct void cash advance on Detail total
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount - srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 	
            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulRefundTotalAmount), 
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usVoidCashAdvCount, 
            	(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulVoidCashAdvTotalAmount), 
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulOffSaleTotalAmount),
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulCashAdvTotalAmount),
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usTipCount, (srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].ulTipTotalAmount));	
			}
        }
			
        printDividingLine(DIVIDING_LINE);
        
        inReportType = DETAIL_REPORT_GRANDTOTAL;

		
		if (inCheckIfSMCardTransRec() == TRUE){
        	vdCTOS_PrintAccumeByHostAndCard (inReportType, 
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, 	
        	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
        	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount));		

		}else{
        
        	vdCTOS_PrintAccumeByHostAndCard (inReportType, 
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 	
        	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount) - (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount), 
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount, 
        	(srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount), 
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount),
        	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount));		
		}
    }
		
		//CTOS_PrinterFline(d_LINE_DOT * 10);
		vdCTOS_PrinterFline(10);

        vdCTOSS_PrinterEnd();
    return;	
}
/*albert - end - 20161202 - Reprint of Detail Report for Last Settlement Report*/

USHORT ushCTOS_ReprintBatchRecordHeader(void)
{
	USHORT result;
	BYTE baTemp[PAPER_X_SIZE * 64];
	ACCUM_REC srAccumRec;
	int inResult;

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

    ushCTOS_PrintHeader(0);	

	memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
	inResult = inCTOS_ReadBKAccumTotal(&srAccumRec,strHDT.inHostIndex,srTransRec.MITid);
	if(inResult == ST_ERROR)
	{
	    //vdSetErrorMessage("NO RECORD FOUND");
	    vdDisplayErrorMsgResp2("","TRANSACTION","NOT FOUND");
		vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
		return ST_ERROR;	
	}		 
	else if(inResult == RC_FILE_READ_OUT_NO_DATA)
	{
	    //vdSetErrorMessage("NO RECORD FOUND");
	    vdDisplayErrorMsgResp2("","TRANSACTION","NOT FOUND");
		return;
	}
	
	memcpy(srTransRec.szYear, srAccumRec.szYear, DATE_BCD_SIZE);
    memcpy(srTransRec.szDate, srAccumRec.szDate, DATE_BCD_SIZE);
    memcpy(srTransRec.szTime, srAccumRec.szTime, TIME_BCD_SIZE);
	memcpy(srTransRec.szBatchNo, srAccumRec.szBatchNo, BATCH_NO_BCD_SIZE);	
	
	printTIDMID(TRUE);   

	//printDateTime();
    printLastSettleDateTime();
	
	memcpy(srTransRec.szBatchNo, srAccumRec.szBatchNo, BATCH_NO_BCD_SIZE);	
	printBatchNO();

	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
    vdPrintCenter("DETAIL REPORT");
    //printHostLabel();
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	#if 0

    //CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);
	memset (baTemp, 0x00, sizeof(baTemp));
	//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, "CARD NAME           CARD NUMBER", &stgFONT_ATTRIB);
	//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	if(strTCT.fSMMode == TRUE)
	{
        inCCTOS_PrinterBufferOutput("CARD NAME              CARD NUMBER",&stgFONT_ATTRIB,fERMTransaction);
        inCCTOS_PrinterBufferOutput("EXP DATE               TRACE NUMBER",&stgFONT_ATTRIB,fERMTransaction);
		inCCTOS_PrinterBufferOutput("TRANSACTION            AMOUNT",&stgFONT_ATTRIB,fERMTransaction);
	}
	else
	{
		inCCTOS_PrinterBufferOutput("CARD NAME              TRACE NUMBER",&stgFONT_ATTRIB,fERMTransaction);
		inCCTOS_PrinterBufferOutput("TRANSACTION            AMOUNT",&stgFONT_ATTRIB,fERMTransaction);
	}

	//inCCTOS_PrinterBufferOutput("APPROVAL CODE",&stgFONT_ATTRIB,1);
	inCCTOS_PrinterBufferOutput("APPROVAL CODE",&stgFONT_ATTRIB,fERMTransaction);
	printDividingLine(DIVIDING_LINE);
#else
    vdCTOS_PrinterFline(1);
    memset (baTemp, 0x00, sizeof(baTemp));
    inCCTOS_PrinterBufferOutput("CARD NAME              CARD NUMBER",&stgFONT_ATTRIB,1);
    memset (baTemp, 0x00, sizeof(baTemp));
            
    if(inCheckIfSMCardTransRec() == TRUE)
		inCCTOS_PrinterBufferOutput("TRANSACTION            TRACE NUMBER",&stgFONT_ATTRIB,1);	
	else
	    inCCTOS_PrinterBufferOutput("EXP DATE               TRACE NUMBER",&stgFONT_ATTRIB,1);
    memset (baTemp, 0x00, sizeof(baTemp));
    /*}
	else
	{
        vdCTOS_PrinterFline(1);
        memset (baTemp, 0x00, sizeof(baTemp));
        inCCTOS_PrinterBufferOutput("CARD NAME              TRACE NUMBER",&stgFONT_ATTRIB,1);
        memset (baTemp, 0x00, sizeof(baTemp));
	}
	*/
	
	if(inCheckIfSMCardTransRec() == TRUE)
		inCCTOS_PrinterBufferOutput("APPROVAL CODE          AMOUNT",&stgFONT_ATTRIB,1);
	else
	{
		if(inCheckIfDCCHost() == TRUE)
			inCCTOS_PrinterBufferOutput("TRANSACTION            DCC AMOUNT",&stgFONT_ATTRIB,1);
		else
			inCCTOS_PrinterBufferOutput("TRANSACTION            AMOUNT",&stgFONT_ATTRIB,1);
		
		memset (baTemp, 0x00, sizeof(baTemp));

		if(inCheckIfDCCHost() == TRUE)
			inCCTOS_PrinterBufferOutput("APPROVAL CODE          PHP AMOUNT",&stgFONT_ATTRIB,1);
		else
			inCCTOS_PrinterBufferOutput("APPROVAL CODE",&stgFONT_ATTRIB,1);
	}
	
	printDividingLine(DIVIDING_LINE);


#endif
	return d_OK;
}
#if 0
void vdCTOS_SMInstallmentHostInfo(void){
	int shHostIndex = 1, inNumOfMerchant=0;
	int inResult,inRet;
	unsigned char szCRC[8+1];
	char ucLineBuffer[d_LINE_SIZE];
	BYTE baTemp[PAPER_X_SIZE * 64];
	int inLoop = 0;
	char szBillerName[1024] = {0};
	char szBillerCode[1024] = {0};
	char szStr[d_LINE_SIZE + 1];
	BYTE szTempBuf[12+1];
	BYTE szBuf[50];

	int inNumOfHost;
	int inNum;
	int inHostEnb;
	int inApp;
	char szAPName[20+1];
	int inCount=1;
	int inHDTIndex=0, inHDTid[150];
		
	vdDebug_LogPrintf("-->>vdCTOS_HostInfo[START]");
	
	vduiLightOn();								

	memset(szAPName,0x00,sizeof(szAPName));
	//inApp = inHostInfoAppSelection(szAPName);
	//if(FAIL == inApp)
		//return inApp;
	if(printCheckPaper()==-1)
    	return;
		
	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

	vdDebug_LogPrintf("[Merchant ID %d", srTransRec.MITid);


	inNumOfHost = inHDTNumRecord();
	vdDebug_LogPrintf("inNumOfHost=[%d]-----",inNumOfHost);

	inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	inMMTReadRecord(1, srTransRec.MITid);/*temporary - need to reload MMT record for receipt header*/

	vdSetPrintThreadStatus(1); /*BDO:Display printing image during report -- sidumili*/

	vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  
	ushCTOS_PrintHeader(0);

	vdCTOS_PrinterFline(1);

	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
    vdPrintCenter("HOST INFO REPORT");
	vdCTOS_PrinterFline(1);
	
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	printDateTime();

	inNumOfHost=inHDTReadHostID("V5S_BDOINST", inHDTid);
	inHostEnb=1;
	for(inNum =1 ;inNum <= inNumOfHost; inNum++)
	{
        inHDTIndex=inHDTid[inNum-1];
		if(inHDTRead(inHDTIndex) == d_OK)
		{	
			if(strcmp(strHDT.szAPName,"V5S_BDOINST") == 0)
			{
			    if(strTCT.fSingleComms == FALSE)
				    inCPTRead(inHDTIndex);
				
				//vdDebug_LogPrintf("[HOST %d MID %d", strHDT.inHostIndex, srTransRec.MITid);

				inMMTReadRecord(strHDT.inHostIndex,srTransRec.MITid);
				
				//vdDebug_LogPrintf("[read MMT fail]-Mitid[%d]strHDT.inHostIndex[%d]inResult[%d]", inLoop,strHDT.inHostIndex,inResult);

				//vdDebug_LogPrintf("[inNumOfMerchant]-[%d]strHDT.inHostIndex[%d]", inNumOfMerchant,strHDT.inHostIndex);
				
				//inCCTOS_PrinterBufferOutput("__________________________________________",&stgFONT_ATTRIB,1);
				inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
				memset(szStr, 0x00, d_LINE_SIZE);
				sprintf(szStr, "  HOST NAME: %s", (char *)strHDT.szHostLabel);
				inPrint(szStr);

				memset(szStr, 0x00, sizeof(szStr));
				sprintf(szStr, "TERMINAL ID: %s", strMMT[0].szTID); 											 
				inPrint(szStr);

				memset(szStr, 0x00, sizeof(szStr));
				sprintf(szStr, "MERCHANT ID: %s", strMMT[0].szMID); 											 
				inPrint(szStr);
				
				memset(szTempBuf, 0x00, sizeof(szTempBuf));
				wub_hex_2_str(strHDT.szNII,szTempBuf,2);
				sprintf(szStr, "        NII: %s", szTempBuf);
				inPrint(szStr);

				if (strTCT.fSingleComms != TRUE)
				{	
					
					memset(szStr, 0x00, d_LINE_SIZE);
					sprintf(szStr, "    PRI NUM: %s", (char *)strCPT.szPriTxnPhoneNumber);
					inPrint(szStr);
	
					memset(szStr, 0x00, d_LINE_SIZE);
					sprintf(szStr, "    SEC NUM: %s", (char *)strCPT.szSecTxnPhoneNumber);
					inPrint(szStr);
					
				}

				inPrint(" ");

				if( (inCount%10) == 0)
				{
					vdCTOSS_PrinterEnd();
					vdCTOSS_PrinterStart(100);
					CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel); 
				}
				inCount++;

			}	
		}		

	 }

	if (strTCT.fSingleComms == TRUE)
	{	
		inCPTRead(1);
		
		inCCTOS_PrinterBufferOutput("__________________________________________",&stgFONT_ATTRIB,1);
		inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
		
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "    PRI NUM: %s", (char *)strCPT.szPriTxnPhoneNumber);
		inPrint(szStr);
	
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "    SEC NUM: %s", (char *)strCPT.szSecTxnPhoneNumber);
		inPrint(szStr);

		//inPrint(" ");
		
		//vdCTOS_PrinterFline(1);

	}
	
	//CTOS_PrinterFline(d_LINE_DOT * 5);
	vdCTOS_PrinterFline(6);
	
	vdCTOSS_PrinterEnd();

	vdSetPrintThreadStatus(0); /*BDO:Display printing image during report -- sidumili*/
	
	vdDebug_LogPrintf("-->>vdCTOS_HostInfo[END]");

}
#endif

int inSMACPrintField60(void)
{
	char szPrintBuff[50]={0};
	char szTemp[24]={0};
	int inField60Len;
	int inFontSize; 
	int inLineLen; 
	int inCount = 0;
	int inFontTemp = 0;

	inField60Len = strlen(szField60);
	vdDebug_LogPrintf("szField60[%d]",inField60Len);
	
	while(1)
	{
		
		memset(szTemp,0x00,sizeof(szTemp));
		memcpy(szTemp,&szField60[inCount],2);
		inCount+=2;
		inFontSize = atoi(szTemp);
				
		vdDebug_LogPrintf("szTemp[%s] :: inFontSize[%d] :: inCount[%d]",szTemp, inFontSize, inCount);

		memset(szTemp,0x00,sizeof(szTemp));
		memcpy(szTemp,&szField60[inCount],2);
		inCount+=2;
		inLineLen = atoi(szTemp);
		vdDebug_LogPrintf("inLineLen[%d] :: inCount[%d]",inLineLen, inCount);
		vdSetSMACFooterFontSize(inFontSize,inLineLen);

		memset(szPrintBuff,0x00,sizeof(szPrintBuff));
		memcpy(szPrintBuff,&szField60[inCount],inLineLen);

		if(inFontSize == 1 && inFontTemp>inFontSize && strcmp(szPrintBuff," ") != 0)//Add space if font size is 1 and previous font is 2-4 and previous line is not space.
			vdCTOS_PrinterFline(1);


		
		inFontTemp = inFontSize;


		if(inFontSize == 3 || inFontTemp == 1)
			vdCTOS_PrinterFline(1);


		vdSMACFooterPrintCenter(szPrintBuff);
		
		if(inFontSize == 4)
			vdCTOS_PrinterFline(2);
		//else if(inFontSize == 3)
		//	vdCTOS_PrinterFline(1);

		inCount+=inLineLen;
		vdDebug_LogPrintf("szPrintBuff[%s] :: inCount[%d]",szPrintBuff, inCount);
		

		if(inCount>=inField60Len){
			vdCTOS_PrinterFline(7); //linefeed issue 03322023
			
			break;
		}
	}	
}

void vdSetSMACFooterFontSize(int inFontSize, int inLineLen)
{

	switch(inFontSize)
	{
		case 1:
			//stgFONT_ATTRIB.FontSize = d_FONT_8x8;
			//stgFONT_ATTRIB.X_Zoom = NORMAL_SIZE;
			
			//stgFONT_ATTRIB.Y_Zoom = DOUBLE_SIZE;
			vdSetGolbFontAttrib(d_FONT_8x8, NORMAL_SIZE, DOUBLE_SIZE, 0, 0);
			break;

		case 2:
			/*
			stgFONT_ATTRIB.FontSize = d_FONT_16x16;

			if(inLineLen < 21)
				stgFONT_ATTRIB.X_Zoom = DOUBLE_SIZE;
			else
				stgFONT_ATTRIB.X_Zoom = NORMAL_SIZE;

			
			stgFONT_ATTRIB.Y_Zoom = DOUBLE_SIZE;
			*/
			vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 0, 0);
			break;	

		case 3:
			/*
			stgFONT_ATTRIB.FontSize = d_FONT_24x24;
			stgFONT_ATTRIB.X_Zoom = NORMAL_SIZE;
			stgFONT_ATTRIB.Y_Zoom = NORMAL_SIZE;
			stgFONT_ATTRIB.Y_Space = 0; 
			break;
			*/
			
			vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);
			break;

		case 4:
			
			vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, DOUBLE_SIZE, 0, 0);
			/*
			stgFONT_ATTRIB.FontSize = d_FONT_24x24;

			if(inLineLen < 16)
				stgFONT_ATTRIB.X_Zoom = DOUBLE_SIZE;
			else
				stgFONT_ATTRIB.X_Zoom = NORMAL_SIZE;
			break;*/

	}


}

void vdSMACFooterPrintCenter(unsigned char *strIn)
{
	unsigned char tucPrint [24*4+1];
	short i,spacestring;
    USHORT usCharPerLine = 32;
    BYTE baTemp[PAPER_X_SIZE * 64];
    int inSpacing=3;
	
    if(d_FONT_24x24 == stgFONT_ATTRIB.FontSize && NORMAL_SIZE == stgFONT_ATTRIB.X_Zoom)
        usCharPerLine = 32;
    else if(d_FONT_24x24 == stgFONT_ATTRIB.FontSize && DOUBLE_SIZE == stgFONT_ATTRIB.X_Zoom)
         //usCharPerLine = 16;
         usCharPerLine = 32;
    else if(d_FONT_16x16 == stgFONT_ATTRIB.FontSize && NORMAL_SIZE == stgFONT_ATTRIB.X_Zoom)
        usCharPerLine = 42;
    else if(d_FONT_16x16 == stgFONT_ATTRIB.FontSize && DOUBLE_SIZE == stgFONT_ATTRIB.X_Zoom)
        usCharPerLine = 24;
	else if(d_FONT_8x8 == stgFONT_ATTRIB.FontSize && NORMAL_SIZE== stgFONT_ATTRIB.X_Zoom)
        usCharPerLine = 42;
    else
        usCharPerLine = 32;

    if(stgFONT_ATTRIB.X_Zoom == DOUBLE_SIZE)
         inSpacing=4;
	
    i = strlen(strIn);
	spacestring=(usCharPerLine-i)/2;
				
	memset(tucPrint,0x20,55);
	memcpy(tucPrint+spacestring,strIn,usCharPerLine);	
	
	tucPrint[i+spacestring]=0;
    memset (baTemp, 0x00, sizeof(baTemp));
      
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, tucPrint, &stgFONT_ATTRIB);
		//CTOS_PrinterBufferOutput((BYTE *)baTemp, inSpacing); 
		inCCTOS_PrinterBufferOutput(tucPrint,&stgFONT_ATTRIB,1);
}

USHORT printLastSettleDateTime(void)
{
    char szStr[d_LINE_SIZE + 1];
    char szTemp[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    USHORT result;
    BYTE baTemp[PAPER_X_SIZE * 64];
  	CTOS_RTC SetRTC;
	char szYear[3];
//1102
	char sMonth[4];
	char szTempMonth[3];
	char szMonthNames[40];

	memset(sMonth,0x00,4);
	memset(szMonthNames,0x00,40);
	strcpy(szMonthNames,"JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC");
	memset(szTempMonth, 0x00, 3);

//1102
	
    memset(szStr, ' ', d_LINE_SIZE);
    memset(szTemp, ' ', d_LINE_SIZE);

	vdDebug_LogPrintf("year[%s],date[%02x][%02x]",srTransRec.szYear,srTransRec.szDate[0],srTransRec.szDate[1]);
    wub_hex_2_str(srTransRec.szDate, szTemp,DATE_BCD_SIZE);
    wub_hex_2_str(srTransRec.szTime, szTemp1,TIME_BCD_SIZE);
	vdDebug_LogPrintf("date[%s],time[%s]atol(szTemp)=[%d](atol(szTemp1)=[%d]",szTemp,szTemp1,atol(szTemp),atol(szTemp1) );
	vdDebug_LogPrintf("date[%s],time[%s]",szTemp,szTemp1);
	
	memcpy(szTempMonth,&szTemp[0],2);
	memcpy(sMonth, &szMonthNames[(atoi(szTempMonth) - 1)* 3], 3);
#if 0 //removed for version 11

	if (strTCT.fSMReceipt== 1)
		sprintf(szStr,"Date/Time    : %02lu/%02lu/%04lu         %02lu:%02lu:%02lu",atol(szTemp)/100,atol(szTemp)%100,atol(srTransRec.szYear)+2000,atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100);
	else
#endif
		sprintf(szStr,"DATE/TIME    : %s %02lu, %02lu    %02lu:%02lu:%02lu",sMonth,atol(szTemp)%100,atol(srTransRec.szYear),atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100);

    //inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
	inPrint(szStr);
	
    return(result);
     
}

USHORT printBatchInvoiceNOEx(void)
{
    char szStr[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    char szTemp2[d_LINE_SIZE + 1];
    USHORT result;
    BYTE baTemp[PAPER_X_SIZE * 64];
        
    memset(szStr, ' ', d_LINE_SIZE);
    memset(szTemp1, ' ', d_LINE_SIZE);
    memset(szTemp2, ' ', d_LINE_SIZE);
	
	wub_hex_2_str(srTransRec.szBatchNo,szTemp1,3);
    wub_hex_2_str(srTransRec.szInvoiceNo, szTemp2, INVOICE_BCD_SIZE);
    vdMyEZLib_LogPrintf("invoice no: %s",szTemp2);

    //sprintf(szStr, "BATCH: %-14.14sINVOICE: %s", szTemp1, szTemp2);	// v10.0 change
    sprintf(szStr, "BATCH: %s", szTemp1);	// v10.0 change
	inPrint(szStr);
	
	memset(szStr, ' ', d_LINE_SIZE);
	sprintf(szStr, "INVOICE: %s", szTemp2);	// v10.0 change
	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	inPrint(szStr);

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 0, 0);
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
	//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
    //inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB, fERMTransaction);
    return(d_OK);
}


USHORT usPrintReceiptDCCCopies(BOOL BankCopy, BOOL CustCopy, BOOL MercCopy, BOOL fERM)
{
	int inDCC = 0;
	USHORT inRet = d_NO;
	BOOL fFirstReceipt=TRUE; 
    int inReceiptCtr=0;
    BYTE szPrintOption[3+1];
    BYTE chPrintOption=0x00;
	BYTE  key;
	ULONG ulFileSize;
	BYTE  szTotalAmt[12+1];
	
    memset(szPrintOption, 0x00, sizeof(szPrintOption)); 
    memcpy(szPrintOption, strIIT.szPrintOption, 3); /*get sequence from IIT*/
    
	inReceiptCtr=0;
	fFirstReceipt=TRUE;
    do
    {
        chPrintOption=(unsigned char)szPrintOption[inReceiptCtr];
        if((chPrintOption == '1') && (BankCopy == TRUE)) /*bank copy*/
        {
			if(fFirstReceipt == TRUE)
			{
				ushCTOS_printAll(BANK_COPY_RECEIPT);
				if(fERM == TRUE)
					inCTOSS_ERM_Form_Receipt(0);
				CTOS_KBDBufFlush();	
				fFirstReceipt=FALSE;
			}
			else
			{
				CTOS_TimeOutSet(TIMER_ID_1, UI_TIMEOUT);
				CTOS_LCDTClearDisplay();
				if(strTCT.fPrintReceiptPrompt == TRUE)
				{
					vduiDisplayStringCenter(7,"PRINT BANK COPY?");
					vduiDisplayStringCenter(8,"NO[X] YES[OK]");
				}
				else
				{
					vduiDisplayStringCenter(7,"PRINT BANK COPY");
					vduiDisplayStringCenter(8,"PRESS ENTER TO PRINT");
				}
	                while(1)
	                { 
	                    if (strTCT.fPrintWarningSound == TRUE)
	                    vduiWarningSound();
	                    
	                    CTOS_KBDHit(&key);
	                    if(key == d_KBD_ENTER)
	                    {
	                        ushCTOS_printAll(BANK_COPY_RECEIPT);
                            if(fERM == TRUE)
                                inCTOSS_ERM_Form_Receipt(0);
	                        CTOS_KBDBufFlush();//cleare key buffer
	                        break;
	                    }
	                    else if(key == d_KBD_CANCEL && strTCT.fPrintReceiptPrompt == TRUE)
	                        break;
	                    if(CTOS_TimeOutCheck(TIMER_ID_1) == d_YES)
	                    {
							ushCTOS_printAll(BANK_COPY_RECEIPT);
	                        break;
	                    }
	                }
					
			}
        }
        else if((chPrintOption == '2') && (CustCopy == TRUE)) /*customer copy*/
        {
			if(fFirstReceipt == TRUE)
			{
				ushCTOS_printAll(CUSTOMER_COPY_RECEIPT);
                if(fERM == TRUE)
                    inCTOSS_ERM_Form_Receipt(0);
				CTOS_KBDBufFlush();//cleare key buffer	
				fFirstReceipt=FALSE;
			}
			else
			{
				
				wub_hex_2_str(srTransRec.szTotalAmount, szTotalAmt, AMT_BCD_SIZE); 
				vdDebug_LogPrintf("fPrintReceiptPrompt[%d] :: fNSRCustCopy[%d] :: szNSRLimit[%d] :: szTotalAmt[%d]",strTCT.fPrintReceiptPrompt, strIIT.fNSRCustCopy, atol(strIIT.szNSRLimit),atol(szTotalAmt));
				CTOS_TimeOutSet(TIMER_ID_1, UI_TIMEOUT);
				CTOS_LCDTClearDisplay();
				if(strTCT.fPrintReceiptPrompt == FALSE && strIIT.fNSRCustCopy == FALSE)
				{
					vduiDisplayStringCenter(7,"PRINT CUSTOMER COPY");
					vduiDisplayStringCenter(8,"PRESS ENTER TO PRINT");
				}
				else
				{
					if(strTCT.fPrintReceiptPrompt == FALSE && ( (strIIT.fNSRCustCopy == TRUE && atol(strIIT.szNSRLimit) < atol(szTotalAmt)) 
						|| srTransRec.byEntryMode == CARD_ENTRY_FALLBACK || srTransRec.fDCC == TRUE))
					{
						vduiDisplayStringCenter(7,"PRINT CUSTOMER COPY");
						vduiDisplayStringCenter(8,"PRESS ENTER TO PRINT");
					}
					else
					{
						vduiDisplayStringCenter(7,"PRINT CUSTOMER COPY?");
						vduiDisplayStringCenter(8,"NO[X] YES[OK]");
					}
						
				}
                while(1)
                { 
                    if (strTCT.fPrintWarningSound == TRUE)
                    vduiWarningSound();
                    
                    CTOS_KBDHit(&key);
                    if(key == d_KBD_ENTER)
                    {
                        ushCTOS_printAll(CUSTOMER_COPY_RECEIPT);
                        if(fERM == TRUE)
                            inCTOSS_ERM_Form_Receipt(0);						
                        CTOS_KBDBufFlush();//cleare key buffer
                        break;
                    }
                    else if(key == d_KBD_CANCEL)
                    {
						if(strTCT.fPrintReceiptPrompt == TRUE || ((strTCT.fPrintReceiptPrompt == FALSE && strIIT.fNSRCustCopy
							&& atol(strIIT.szNSRLimit) >= atol(szTotalAmt)) && srTransRec.byEntryMode != CARD_ENTRY_FALLBACK && srTransRec.fDCC != TRUE) )
	                        break;
                    }	
                    if(CTOS_TimeOutCheck(TIMER_ID_1) == d_YES)
                    {
						ushCTOS_printAll(CUSTOMER_COPY_RECEIPT);
                        break;
                    }
                }
			}
			
        }  	
        else if((chPrintOption == '3') && (MercCopy== TRUE)) /*merchant copy*/
        {
			if(fFirstReceipt == TRUE)
			{
				ushCTOS_printAll(MERCHANT_COPY_RECEIPT);
                if(fERM == TRUE)
                    inCTOSS_ERM_Form_Receipt(0);
				CTOS_KBDBufFlush();//cleare key buffer	
				fFirstReceipt=FALSE;
			}
			else
			{
				CTOS_TimeOutSet(TIMER_ID_1, UI_TIMEOUT);
				CTOS_LCDTClearDisplay();
				if(strTCT.fPrintReceiptPrompt == TRUE)
				{
					vduiDisplayStringCenter(7,"PRINT MERCHANT COPY?");
					vduiDisplayStringCenter(8,"NO[X] YES[OK]");
				}
				else
				{
					vduiDisplayStringCenter(7,"PRINT MERCHANT COPY");
					vduiDisplayStringCenter(8,"PRESS ENTER TO PRINT");
				}
                while(1)
                { 
                    if (strTCT.fPrintWarningSound == TRUE) /*BDO PHASE 2: [Warning sound for printing flag] -- sidumili*/
                    vduiWarningSound();
                    
                    CTOS_KBDHit(&key);
                    if(key == d_KBD_ENTER)
                    {
                        ushCTOS_printAll(MERCHANT_COPY_RECEIPT);
                        if(fERM == TRUE)
                            inCTOSS_ERM_Form_Receipt(0);						
                        CTOS_KBDBufFlush();//cleare key buffer
                        break;
                    }
                    else if(key == d_KBD_CANCEL && strTCT.fPrintReceiptPrompt == TRUE)
                        break;
                    if(CTOS_TimeOutCheck(TIMER_ID_1) == d_YES)
                    {
						ushCTOS_printAll(MERCHANT_COPY_RECEIPT);
                        break;
                    }
                }
			}
        }
		
		if(fRePrintFlag == FALSE)
		{
			if(srTransRec.fDCC == VS_TRUE && inReceiptCtr == 0)
			{
				inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

				if(inFLGGet("fSignPad") == TRUE)
				{
					inDCC = inSignPadSendReceive(d_COM2, DCC_RATE);
					if(inDCC == SIGNPAD_NOT_DETECTED)
					{
						inDCC = inDisplayDCCRateScreenEx();//Use terminal screen if touch pad is not detected.
						CTOS_LCDTClearDisplay();
					    if(inDCC != VS_CONTINUE)
					    {
							inRet = inRevertToPHP();

							if(inRet == VS_OPTOUT_FAILED)
							{
								vdDisplayErrorMsgResp2("PLEASE RETRY","OPT OUT","TRANSACTION");
							}
							
							return VS_TXNFINISH;

							srTransRec.fDCC = VS_TRUE; //If OptOut fails, set to true to continue printing DCC Receipts.
					    }
					}
					else if(inDCC == FAIL)//Opt-out.
				    {
						inRet = inRevertToPHP();

						if(inRet == VS_OPTOUT_FAILED)
						{
							vdDisplayErrorMsgResp2("PLEASE RETRY","OPT OUT","TRANSACTION");
						}
						
						return VS_TXNFINISH;

						srTransRec.fDCC = VS_TRUE; //If OptOut fails, set to true to continue printing DCC Receipts.
				    }
					
					
				}
				else
				{
					inDCC = inDisplayDCCRateScreenEx();
					CTOS_LCDTClearDisplay();
				    if(inDCC != VS_CONTINUE)
				    {
						inRet = inRevertToPHP();

						if(inRet == VS_OPTOUT_FAILED)
						{
							vdDisplayErrorMsgResp2("PLEASE RETRY","OPT OUT","TRANSACTION");
						}
						
						return VS_TXNFINISH;

						srTransRec.fDCC = VS_TRUE; //If OptOut fails, set to true to continue printing DCC Receipts.
				    }
				}
			}
		}
		
		inReceiptCtr++; 
    }while(inReceiptCtr < 3);	

    if(fERM == TRUE)
    {
        if(strTCT.fSignatureFlag == TRUE)
        {
            ulFileSize=lnGetFileSize(DB_SIGN_BMP);
            if(ulFileSize > 0)
                vdLinuxCommandFileCopy();
        }
    }
	
}

USHORT ushCTOS_PrintDCCRateBody(int page)
{	
    char szStr[d_LINE_SIZE + 3];
    char szTemp[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    char szTemp3[d_LINE_SIZE + 1];
    char szTemp4[d_LINE_SIZE + 1];
    char szTemp5[d_LINE_SIZE + 1];
    char szFormatPAN[strlen(srTransRec.szPAN) + 7];//to account for space as in PAN format and to include additional PAN no. 7 has been added -Meena 08/01/2012
    int inFmtPANSize;
    BYTE baTemp[PAPER_X_SIZE * 64];
    USHORT result;
    int num,i,inResult,inLength;
	float inMarkup=0;
    unsigned char tucPrint [24*4+1];	
    BYTE   EMVtagVal[64];
    USHORT EMVtagLen; 
    short spacestring;
    BYTE   key;
   	BOOL fCTLSEMVCheck = CN_FALSE;
    char szAmountBuff[20], szTemp6[47];
    int inPADSize,x;
    char szSPACE[40];
	BYTE szBatchNoTemp[BATCH_NO_BCD_SIZE+1];
    BYTE szInvoiceNoTemp[INVOICE_BCD_SIZE+1];
    char szPOSEntry[21] = {0}; /* BDOCLG-00134: Reformat cardtype line -- jzg */
	char szFxRate[d_LINE_SIZE + 3];
	char szOutAID[d_LINE_SIZE + 1];
	

    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    /* tid mid */
    printTIDMID(FALSE); 

	memset(szBatchNoTemp,0x00,sizeof(szBatchNoTemp));
	memset(szInvoiceNoTemp,0x00,sizeof(szInvoiceNoTemp));
	
	memcpy(szBatchNoTemp,srTransRec.szBatchNo,sizeof(srTransRec.szBatchNo));
	memcpy(szInvoiceNoTemp,srTransRec.szInvoiceNo,sizeof(srTransRec.szInvoiceNo));

	memset(srTransRec.szBatchNo,0x00,sizeof(srTransRec.szBatchNo));
	memset(srTransRec.szInvoiceNo,0x00,sizeof(srTransRec.szInvoiceNo));
	
    /* batch invoice no. */
	if(strFLG.fLargeInvoice)
   		printBatchInvoiceNOExForDCCPrint();
	else
    	printBatchInvoiceNOForDCCPrint();

	memcpy(srTransRec.szBatchNo,szBatchNoTemp,sizeof(srTransRec.szBatchNo));
	memcpy(srTransRec.szInvoiceNo,szInvoiceNoTemp,sizeof(srTransRec.szInvoiceNo));
	
    /* card no. */
    memset(szTemp5, 0x00, sizeof(szTemp5));
    //BDO: Enable PAN Masking for each receipt - start -- jzg
    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 4 of 21
    if(page == CUSTOMER_COPY_RECEIPT)
        vdCTOS_FormatPAN2(strIIT.szMaskCustomerCopy, srTransRec.szPAN, szTemp5);
    else if(page == MERCHANT_COPY_RECEIPT)
        vdCTOS_FormatPAN2(strIIT.szMaskMerchantCopy, srTransRec.szPAN, szTemp5);
    else if(page == BANK_COPY_RECEIPT)
        vdCTOS_FormatPAN2(strIIT.szMaskBankCopy, srTransRec.szPAN, szTemp5);
    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 4 of 21
    
    vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 1, 0);
    memset(szTemp6, 0x00, sizeof(szTemp6));
    memset(szStr, 0x00, sizeof(szStr));
    
    if (strlen(srTransRec.szPAN) > 16)
        vdRemoveSpace(szStr, szTemp5);		
    else
        strcpy(szStr, szTemp5);
    
	inPrint(szStr);

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

    if(strTCT.fSMMode && strTCT.fPrintIssuerID)
	{
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "ISSUER ID: %02d", strHDT.inIssuerID);
		inPrint(szStr);
	}
		
    if ((strIIT.fGetPolicyNumber == TRUE) && (strlen(srTransRec.szPolicyNumber) > 0))
    {
        memset(szStr, 0x00, d_LINE_SIZE);
        sprintf(szStr, "POLICY NO: %s", srTransRec.szPolicyNumber);
        inPrint(szStr);
    }

	
	if(srTransRec.fBINVer)
	{
		memset(szStr, 0x00, d_LINE_SIZE);
		sprintf(szStr, "BIN CHECK: %06ld", atol(srTransRec.szBINVerSTAN));
		inPrint(szStr);
	}

    /* card holder name */
    printCardHolderName();
    
    /*Trans type*/
    memset(szStr, 0x00, sizeof(szStr));
    if (srTransRec.byTransType == PRE_AUTH)
        strcpy(szStr,"CARD VERIFY");
    else if(srTransRec.byTransType == CASH_ADVANCE)
        strcpy(szStr,"CASH ADVANCE");
    else if(srTransRec.byTransType == VOID && srTransRec.byOrgTransType == CASH_ADVANCE)
        strcpy(szStr,"CASH ADVANCE VOID");
    else
        szGetTransTitle(srTransRec.byTransType, szStr); 
    
    vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
    if ((srTransRec.byTransType == SALE||srTransRec.byTransType == SALE_OFFLINE) && (srTransRec.byEntryMode == CARD_ENTRY_WAVE))
        vdPrintCenter("CONTACTLESS SALE");
	else if ((srTransRec.byTransType == VOID) && (srTransRec.byEntryMode == CARD_ENTRY_WAVE))
        vdPrintCenter("CONTACTLESS VOID");
    else
    {
		//memset (baTemp, 0x00, sizeof(baTemp));
        //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
        //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		vdPrintCenter(szStr);  
    }
    
    /* date time entry mode */
    switch(srTransRec.byEntryMode)
    {
        case CARD_ENTRY_MSR:
            strcat(szPOSEntry, "S");
        break;

        case CARD_ENTRY_MANUAL:
            strcat(szPOSEntry, "M");
        break;

        case CARD_ENTRY_ICC:
            strcat(szPOSEntry, "C");   
        break;

        case CARD_ENTRY_FALLBACK:		
			if((srTransRec.szServiceCode[0] == '2') || (srTransRec.szServiceCode[0] == '6'))
            	strcat(szPOSEntry, "F");  
			else			
            	strcat(szPOSEntry, "S");
        break;
    }
    printDateTimeAndOther(szPOSEntry, 23);
    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

    /* card type approval code */
    memset(szTemp, 0x00, d_LINE_SIZE);
    memset(szTemp1, 0x00, d_LINE_SIZE);
	memset(szTemp3, 0x00, d_LINE_SIZE);
	if (srTransRec.byEntryMode == CARD_ENTRY_WAVE && (srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_2 || srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC || srTransRec.bWaveSID == d_VW_SID_AE_EMV || srTransRec.bWaveSID == d_VW_SID_CUP_EMV || srTransRec.bWaveSID == 0x63 || srTransRec.bWaveSID == 0x65 || srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP  || srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS))
		fCTLSEMVCheck = CN_TRUE;
	
    if (inGetATPBinRouteFlag() == TRUE){
	if( fCTLSEMVCheck || srTransRec.byEntryMode == CARD_ENTRY_ICC || strcmp("SMGUARNTR",srTransRec.szCardLable) == 0 || 
		strcmp("SMADVNTGE",srTransRec.szCardLable) == 0 || strcmp("SHOP CARD",srTransRec.szCardLable) == 0|| 
		strcmp("FLEET",srTransRec.szCardLable) == 0 || strcmp("CASHCARD",srTransRec.szCardLable) == 0 || 
		strcmp("BDOREWARDS",srTransRec.szCardLable) == 0 )
		strcpy(szTemp3,srTransRec.szCardLable);
	else if(srTransRec.inCardType == DEBIT_CARD)
		strcpy(szTemp3,"DEBIT");
	else if (srTransRec.inCardType == CREDIT_CARD){	
		if (srTransRec.fFleetCard == TRUE)	
			strcpy(szTemp3,srTransRec.szCardLable);
		else
			strcpy(szTemp3,"CREDIT");
	}	
    }
	else
		strcpy(szTemp3,srTransRec.szCardLable);
	
	
    if(strTCT.fDutyFreeMode)
    {
       if (strcmp(szTemp3,"CITI VISA")==0)
           sprintf(szTemp,"CARD TYPE: VISA", szTemp3);
       else if (strcmp(szTemp3,"CITI MASTER")==0)
           sprintf(szTemp,"CARD TYPE: MASTERCARD", szTemp3);
       else
           sprintf(szTemp,"CARD TYPE: %s", szTemp3);
		
		sprintf(szTemp1,"APP CODE: %s", " ");
    
       inPrint(szTemp);
       vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
       //inPrintLeftRight("",szTemp1,23);
       inPrint(szTemp1);
	   vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	}
	else
	{
     if (strcmp(szTemp3,"CITI VISA")==0)
     	{
     	   memset(szTemp3,"",sizeof(szTemp3));
				 strcpy(szTemp3,"VISA");
         sprintf(szTemp,"CARD TYPE:%-12.12sAPP CODE: %s", " "," ");
     	}
     else if (strcmp(szTemp3,"CITI MASTER")==0)
     	{
     	   memset(szTemp3,"",sizeof(szTemp3));
				 strcpy(szTemp3,"MASTERCARD");
         sprintf(szTemp,"CARD TYPE:%-12.12sAPP CODE: %s", " "," ");
     	}
     else
  		 sprintf(szTemp,"CARD TYPE:%-12.12sAPP CODE: %s", " "," ");
 		inPrint(szTemp);
	}

	if(inFLGGet("fPrintForExRate") == TRUE)
	{
		inLength=strlen(srTransRec.szDCCFXRate)-srTransRec.inDCCFXRateMU;
		memset(szFxRate,0x00,sizeof(szFxRate));
		memcpy(szFxRate,srTransRec.szDCCFXRate,inLength);
		memcpy(&szFxRate[inLength],".",1);
		memcpy(&szFxRate[inLength+1],&srTransRec.szDCCFXRate[inLength],srTransRec.inDCCFXRateMU);
		
		memset(szStr,0x00,d_LINE_SIZE);
		sprintf(szStr, "ExR: %s 1.00 = %s %s", srTransRec.szDCCLocalSymbol, srTransRec.szDCCCurSymbol, szFxRate);	
		inPrint(szStr);
	}
	
	if(inFLGGet("fPrintDCCMarkUp") == TRUE)
	{
		memset(szTemp,0x00,sizeof(szTemp));
		memset(szStr,0x00,sizeof(szStr));
		inMarkup = atof(srTransRec.szDCCMarkupPer);
		sprintf(szTemp,"%.2f",inMarkup);
		sprintf(szStr,"M-UP: %s",szTemp);
		strcat(szStr,"%");
		inPrint(szStr);
	}
	
    /*Reference num*/
	memset(szTemp, 0x00, d_LINE_SIZE);
    memset(szTemp1, 0x00, d_LINE_SIZE);
	
    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	vdDebug_LogPrintf("ushCTOS_PrintBody srTransRec.byEntryMode=[%d]", srTransRec.byEntryMode);
	
    //if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||    
    
	//00129 - Missing RRN in transaction receipt when performing CREDIT SALE or DCC SALE via fallback and manual #1
    if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) || (srTransRec.byEntryMode == CARD_ENTRY_FALLBACK) ||
    /* EMV: Revised EMV details printing - start -- jzg */
    //(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||  
    (srTransRec.bWaveSID == 0x65) ||
    (srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
    (srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
    //(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||
    (srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
    (srTransRec.bWaveSID == 0x63) ||
    (srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
    (srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
    /* EMV: Revised EMV details printing - end -- jzg */
    {	
		sprintf(szTemp,"RRN: %-17.17sAPP:%s", " "," ");
		//sprintf(szTemp,"RRN: %-17.17sAPP:%s", srTransRec.szRRN,srTransRec.szCardLable);
        //sprintf(szTemp1,"APP: %s", srTransRec.szCardLable);
		//inPrintLeftRight(szTemp,szTemp1,42);
    }
    else	// v10.0 change - depends on srTransRec.byEntryMode
    {
        sprintf(szTemp, "RRN: %-17.17s", " ");
		//inPrint(szStr);
    }

    inPrint(szTemp);

    /* AID TC */
    memset(szStr, ' ', sizeof(szStr));
    memset(szTemp, ' ', sizeof(szTemp));
    memset(szTemp1, ' ', sizeof(szTemp1));
    memset(szTemp3, ' ', sizeof(szTemp3));
    memset(szTemp4, ' ', sizeof(szTemp4));
    if ((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
    /* EMV: Revised EMV details printing - start -- jzg */
    //(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||    
    (srTransRec.bWaveSID == 0x65) ||
    (srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
    (srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
    (srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
    (srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
    //(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||
    
    (srTransRec.bWaveSID == 0x63) ||
    (srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
    
    /* EMV: Revised EMV details printing - end -- jzg */
    {
        //AID
        EMVtagLen = srTransRec.stEMVinfo.T84_len;
        memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
        memcpy(EMVtagVal, srTransRec.stEMVinfo.T84, EMVtagLen);
        wub_hex_2_str(EMVtagVal, szTemp, EMVtagLen);

        //for investigation
		//vdCTOS_FormatHeader(strIIT.szMaskAID, szTemp, szOutAID); // Format AID -- sidumili
		vdDebug_LogPrintf("szOutAID=[%s]", szOutAID);
        sprintf(szTemp1, "AID: %s", szOutAID);
        
        //TC
        if ((srTransRec.byTransType != SALE_OFFLINE && srTransRec.byOrgTransType!= SALE_OFFLINE && srTransRec.byPackType != OFFLINE_VOID) ||
			memcmp(srTransRec.szAuthCode,"Y1",2) == 0)
        {
            //wub_hex_2_str(srTransRec.stEMVinfo.T9F26, szTemp3, 8);
			sprintf(szStr, "AID: %-16.16s TC: %-16.16s", szOutAID, szTemp3);
        }
		else
			sprintf(szStr, "AID: %-16.16s", szOutAID);
		
		memset (baTemp, 0x00, sizeof(baTemp));		
        //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
        //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		
    }		  

	if (strTCT.fSMReceipt == 0)//version 11 - do not put space for SM receipts
		vdCTOS_PrinterFline(1); // Change Request. Added new line before printing amount on BDO receipts.
	
    /* Amount */
    memset(szStr, ' ', d_LINE_SIZE);
    memset(szTemp, ' ', d_LINE_SIZE);
    memset(szTemp1, ' ', d_LINE_SIZE);
    memset(szTemp3, ' ', d_LINE_SIZE);

    wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
    wub_hex_2_str(srTransRec.szDCCCurAmt, szTemp1, AMT_BCD_SIZE);
    wub_hex_2_str(srTransRec.szTipAmount, szTemp3, AMT_BCD_SIZE);
    
    vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
    inCSTReadHostID(srTransRec.szDCCCur);
    //1025 - ADD OFFLINE SALE
    if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == SALE_OFFLINE))
    {
        //Base amount
        memset(szStr, ' ', d_LINE_SIZE);
        memset(szAmountBuff,0x00,20);
        memset(szTemp4, 0x00, sizeof(szTemp4));
        memset(szTemp6,0x00, sizeof(szTemp6));
        
        
        if (strTCT.fTipAllowFlag == CN_FALSE)
        {
            strcpy(szTemp6,"TOTAL:");

			if(strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(srTransRec.szDCCCurAmt,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else	   
            	vdCTOS_FormatAmount(strCST.szAmountFormat, srTransRec.szDCCCurAmt,szTemp4);// patrick add code 20141216		
            	
            sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
            inPrintLeftRight(szTemp6,szAmountBuff,23);
        }
		else
		{
            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));
            strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change

			if(strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(srTransRec.szDCCCurAmt,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else	
	            vdCTOS_FormatAmount(strCST.szAmountFormat, srTransRec.szDCCCurAmt,szTemp4);// patrick add code 20141216		
            sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
            inPrintLeftRight(szTemp6,szAmountBuff,23);
            /*********************************************************/
            /*TIP*/
            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));
            if (atol(szTemp3) == 0L)
            {
                //sprintf(szStr,"TIP:   %s  ___________", strCST.szCurSymbol);
                sprintf(szStr,"TIP:   %s", strCST.szCurSymbol);
                memset (baTemp, 0x00, sizeof(baTemp));		
                //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
                //CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);
				//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
				memset(szStr, 0x00, d_LINE_SIZE);
        		strcpy(szStr,"           ------------");
		        memset (baTemp, 0x00, sizeof(baTemp));		
				//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
				//vdCTOS_PrinterFline(1);
            }
            else
            {
                strcpy(szTemp6,"TIP:");
                if (atol(szTemp3)> 0)
                {
					if(strTCT.fFormatDCCAmount == TRUE)
		   				vdDCCModifyAmount(szTemp3,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   				else
                    	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
                    sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
                }
                inPrintLeftRight(szTemp6,szAmountBuff,23); 
            }
            /*********************************************************/

            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));
            strcpy(szTemp6,"TOTAL:");
            
            if (atol(szTemp3)> 0)
            {
				if(strTCT.fFormatDCCAmount == TRUE)
			   		vdDCCModifyAmount(szTemp,szTemp4);//vdDCCModifyAmount(&szTemp4);
	   			else
                	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp4);// patrick add code 20141216	
                sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
            }
            inPrintLeftRight(szTemp6,szAmountBuff,23);
        }
    
    }
    else if ((srTransRec.byTransType == SALE_TIP) ||(srTransRec.byOrgTransType == SALE_TIP))
    {
        int inCurSymPos = 0, inTempCurSymLen = 0;
        char szTempCurSym[d_LINE_SIZE + 1];
        char szTempStr[d_LINE_SIZE + 1];
        //get the longest amount (total amount) to calculate currency position
        memset(szTemp4, 0x00, sizeof(szTemp4));

		if(strTCT.fFormatDCCAmount == TRUE)
	   		vdDCCModifyAmount(szTemp,szTemp4);//vdDCCModifyAmount(&szTemp4);
   		else
	        vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp4);
		
        memset(szTempCurSym, 0x00, sizeof(szTempCurSym));
        if (srTransRec.byTransType == VOID)
        {
            if (strlen(szTemp4) >= 13 || (srTransRec.byOrgTransType == SALE_TIP) || srTransRec.fFleetCard == TRUE)
                sprintf(szTempCurSym, "-%s", strCST.szCurSymbol);
            else
                sprintf(szTempCurSym, "-%s", strCST.szCurSymbol);
        }
        else
            sprintf(szTempCurSym, "%s", strCST.szCurSymbol);
        inTempCurSymLen = strlen(szTempCurSym);
        inCurSymPos = 23-strlen(szTemp4)-inTempCurSymLen;
        
        //Base amount
        memset(szStr, 0x00, d_LINE_SIZE);
        memset(szAmountBuff,0x00,20);
        memset(szTemp4, 0x00, sizeof(szTemp4));
        memset(szTemp6,0x00, sizeof(szTemp6));
        strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change

		if(strTCT.fFormatDCCAmount == TRUE)
	   		vdDCCModifyAmount(szTemp1,szTemp4); //vdDCCModifyAmount(&szTemp4);
   		else
	        vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
        
        memset(szTempStr, 0x00, sizeof(szTempStr));
        vdCTOS_Pad_String(szTemp6, inCurSymPos+inTempCurSymLen, ' ', POSITION_RIGHT);
        memcpy(&szTemp6[inCurSymPos], szTempCurSym, inTempCurSymLen);
        strcpy(szAmountBuff, szTemp4);
        inPrintLeftRight(szTemp6,szAmountBuff,23);
        /*********************************************************/
        /*TIP*/
        memset(szStr, 0x00, d_LINE_SIZE);
        //memset(szAmountBuff,0x00,20); // haven't reset, needed for tip
        //memset(szTemp4, 0x00, sizeof(szTemp4));	// haven't reset, needed for tip
        memset(szTemp6,0x00, sizeof(szTemp6));
        if (atol(szTemp3) == 0L)
        {
            //sprintf(szStr,"TIP:   %s  ___________", strCST.szCurSymbol);
            sprintf(szStr,"TIP:   %s", strCST.szCurSymbol);
            memset (baTemp, 0x00, sizeof(baTemp));		
            //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
            //CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);
			//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
			
			memset(szStr, 0x00, d_LINE_SIZE);
    		strcpy(szStr,"           ------------");
	        memset (baTemp, 0x00, sizeof(baTemp));		
			//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
			//vdCTOS_PrinterFline(1);
        }
        else
        {
            strcpy(szTemp6,"TIP:");
            if (atol(szTemp3)> 0)
            {
				if(strTCT.fFormatDCCAmount == TRUE)
		   			vdDCCModifyAmount(szTemp3,szTemp4);//vdDCCModifyAmount(&szTemp4);
		   		else
    	            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);// patrick add code 20141216		
    	            
                memset(szTempStr, 0x00, sizeof(szTempStr));
                vdCTOS_Pad_String(szTemp6, inCurSymPos+inTempCurSymLen, ' ', POSITION_RIGHT);
                memcpy(&szTemp6[inCurSymPos], szTempCurSym, inTempCurSymLen);
                strcpy(szAmountBuff, szTemp4);
            }
            inPrintLeftRight(szTemp6,szAmountBuff,23);
        }
        /*********************************************************/
				
        memset(szStr, 0x00, d_LINE_SIZE);
        //strcpy(szStr,"           ____________");
        strcpy(szStr,"           ------------");
        memset (baTemp, 0x00, sizeof(baTemp));		
        //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 0, szStr, &stgFONT_ATTRIB);
        //CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);
		//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
        //vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 1, 0);
        //CTOS_PrinterBufferHLine(10, 1, 20, 1);//test
        //CTOS_PrinterBufferPixel(10, 1, 1);

		//vdCTOS_PrinterFline(1);
        memset(szStr, 0x00, d_LINE_SIZE);
        memset(szAmountBuff,0x00,20);
        memset(szTemp4, 0x00, sizeof(szTemp4));
        memset(szTemp6,0x00, sizeof(szTemp6));
        strcpy(szTemp6,"TOTAL:");
        
        if (atol(szTemp3)> 0)
        {
			if(strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(szTemp,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else
            	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp4);// patrick add code 20141216	
            	
            if (srTransRec.byTransType == VOID)
                sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
            else
                sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
        }
        inPrintLeftRight(szTemp6,szAmountBuff,23);
    }
    else
    {
        if ((strTCT.fTipAllowFlag == CN_TRUE) && (srTransRec.byTransType != PRE_AUTH) && (srTransRec.byTransType != CASH_ADVANCE))
        {
            //Base amount
            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));
            strcpy(szTemp6,"SALE:");	//strcpy(szTemp6,"BASE:");	// v10.0 change

			if(strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(szTemp1,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else
	            vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
            
            if (srTransRec.byTransType == VOID)
            {
                if (strlen(szTemp4) >= 13 || srTransRec.fFleetCard == TRUE)
                    sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
                else
                    sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
            }
            else
                sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
            inPrintLeftRight(szTemp6,szAmountBuff,23);

            /*TIP*/
            memset(szStr, 0x00, d_LINE_SIZE);
            memset(szAmountBuff,0x00,20);
            memset(szTemp4, 0x00, sizeof(szTemp4));
            memset(szTemp6,0x00, sizeof(szTemp6));
            if (atol(szTemp3) == 0L)
            {
	            //sprintf(szStr,"TIP:   %s  ___________", strCST.szCurSymbol);
	            sprintf(szStr,"TIP:   %s", strCST.szCurSymbol);
	            memset (baTemp, 0x00, sizeof(baTemp));		
	            //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	            //CTOS_PrinterBufferOutput((BYTE *)baTemp, 4);
				//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
				memset(szStr, 0x00, d_LINE_SIZE);
	    		strcpy(szStr,"           ------------");
		        memset (baTemp, 0x00, sizeof(baTemp));		
				//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
				inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
				//vdCTOS_PrinterFline(1);
            }
            else
            {
                strcpy(szTemp6,"TIP:");
                if (atol(szTemp3)> 0)
                {
					if(strTCT.fFormatDCCAmount == TRUE)
				   		vdDCCModifyAmount(szTemp3,szTemp4);//vdDCCModifyAmount(&szTemp4);
			   		else
    	                vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp3,szTemp4);	
    	                
                    if (srTransRec.byTransType == VOID)
                    {
                        sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
                    }
                    else
                        sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
                }
                inPrintLeftRight(szTemp6,szAmountBuff,23);
            }
        }
        
        memset(szStr, ' ', d_LINE_SIZE);
        memset(szAmountBuff,0x00,20);
        memset(szTemp4, 0x00, sizeof(szTemp4));
        memset(szTemp6,0x00, sizeof(szTemp6));
        strcpy(szTemp6,"TOTAL:");
        
        if ((atol(szTemp3)> 0) || (srTransRec.byTransType == PRE_AUTH) || (srTransRec.byTransType == CASH_ADVANCE))
        {
			if(strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(szTemp1,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else
            	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
            	
            if (srTransRec.byTransType == VOID)
            {
                if (strlen(szTemp4) >= 13 || srTransRec.fFleetCard == TRUE)
                    sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
                else
                    sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
            }
            else
                sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
        }
        //fix for void receipt - if TIP is off
        else if ((strTCT.fTipAllowFlag == CN_FALSE) &&	(srTransRec.byTransType != PRE_AUTH) && (srTransRec.byTransType != CASH_ADVANCE))
        {
			if(strTCT.fFormatDCCAmount == TRUE)
		   		vdDCCModifyAmount(szTemp1,szTemp4); //vdDCCModifyAmount(&szTemp4);
	   		else
            	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp4);// patrick add code 20141216		
            	
            if (srTransRec.byTransType == VOID)
            {
                if (strlen(szTemp4) >= 13 || srTransRec.fFleetCard == TRUE)
                    sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
                else
                    sprintf(szAmountBuff,"-%s%s",strCST.szCurSymbol,szTemp4);
            }
            else
                sprintf(szAmountBuff,"%s%s",strCST.szCurSymbol,szTemp4);
        }
        //fix for void receipt - if TIP is off
        inPrintLeftRight(szTemp6,szAmountBuff,23); 
    }
    
    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    
    /* BDO CLG: Fleet card support - start -- jzg */
    if((srTransRec.fFleetCard == TRUE) && 
    (strTCT.fFleetGetLiters == TRUE) &&
    (strTCT.fGetDescriptorCode == TRUE)) /* BDOCLG-00347: should be controlled also be parameterized -- jzg */
    {
        memset(szStr, ' ', d_LINE_SIZE);
        memset (baTemp, 0x00, sizeof(baTemp));
        memset(szStr, ' ', d_LINE_SIZE);
        sprintf(szStr, "NO. OF LITERS :   %d", srTransRec.inFleetNumofLiters);
        memset (baTemp, 0x00, sizeof(baTemp));		
        //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
        //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
		
        memset(szStr, ' ', d_LINE_SIZE);
        memset (baTemp, 0x00, sizeof(baTemp));
        memset(szStr, ' ', d_LINE_SIZE);
        sprintf(szStr, "%s", srTransRec.szFleetProductDesc);
        memset (baTemp, 0x00, sizeof(baTemp));		
        //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
       // CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
		//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
		inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
    }

	if (strTCT.fSMReceipt == 0)//version 11 - do not put space for SM receipts
		inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,fERMTransaction);//Added blank line between "TOTAL:" and CVM (NO SIGNATURE REQUIRED, PIN VERIFICATION SUCCESSFUL and etc.)
	
	return d_OK;		
}

USHORT ushCTOS_PrintDCCRateFooter(int page)
{		
	BYTE EMVtagVal[64] = {0};
	USHORT EMVtagLen = 0; 
    BYTE baTemp[PAPER_X_SIZE * 64];
    char szStr[d_LINE_SIZE + 3];
	int fNSRflag = 0;

	//if(srTransRec.fDCC && (srTransRec.byTransType == SALE||srTransRec.byTransType == SALE_OFFLINE||srTransRec.byTransType == SALE_ADJUST||
		//(srTransRec.byTransType == VOID && srTransRec.byOrgTransType == SALE)))

	vdPrintDCCFooter();

	fNSRflag = inNSRFlag();

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
	EMVtagLen = 0;
	
    DebugAddINT("ushCTOS_PrintFooter,mode",srTransRec.byEntryMode);  
    
    vdDebug_LogPrintf("CVM [%02X %02X %02X]",
    srTransRec.stEMVinfo.T9F34[0], srTransRec.stEMVinfo.T9F34[1], srTransRec.stEMVinfo.T9F34[2]);
    vdDebug_LogPrintf("srTransRec.byEntryMode = [%d], strTCT.inCustomerCopy[%d]", srTransRec.byEntryMode, strTCT.inCustomerCopy);
    	
    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    

    vdPrintFooterText();

    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 8 of 13
    if(page == BANK_COPY_RECEIPT)
        vdPrintCenter("--- BANK COPY ---");
    else if(page == CUSTOMER_COPY_RECEIPT)
        vdPrintCenter("--- CUSTOMER COPY ---");
    else if(page = MERCHANT_COPY_RECEIPT)
        vdPrintCenter("--- MERCHANT COPY ---");
    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 8 of 13
    /***************************************************/

    //sidumili: Issue#000135 [Print Footer Logo]
    if (srTransRec.fFooterLogo)
    {
        //CTOS_PrinterFline(d_LINE_DOT * 2); 
        //vdCTOSS_PrintFooterLogoBMPPic(0, 0, "footer.bmp");
        //vdCTOSS_PrinterBMPPicEx(0,0,"/home/ap/pub/footer.bmp");  
        vdCTOSS_PrinterBMPPic(0, 0, "/home/ap/pub/footer.bmp");
    }
    /***************************************************/

	vdLineFeed(srTransRec.fFooterLogo);
	
    return d_OK;	
}

USHORT ushCTOS_printOptOutReceipt(void)
{
	USHORT inRet;
    USHORT result;
    BYTE   key;
    BOOL   needSecond = TRUE;
		//1027
		BOOL   needThird = TRUE;	

    BOOL BankCopy, CustCopy, MercCopy;
		BOOL fFirstReceiptPrinted = VS_FALSE;
	int fNSRflag = 0;
    BOOL fFirstReceipt=TRUE; 
    int inReceiptCtr=0;
    BYTE szPrintOption[3+1];
    BYTE chPrintOption=0x00;
		
     
		if (srTransRec.byTransType == VOID){
			BankCopy = strHDT.fPrintVoidBankReceipt;
			CustCopy = strHDT.fPrintVoidCustReceipt;
			MercCopy = strHDT.fPrintVoidMercReceipt;
		}else{
			BankCopy = strHDT.fPrintBankReceipt;
			CustCopy = strHDT.fPrintCustReceipt;
			MercCopy = strHDT.fPrintMercReceipt;
		}

	//for MP200 no need print
	if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
    	return (d_OK);
    
	if( ((srTransRec.byTransType == BALANCE_INQUIRY || srTransRec.byTransType == SMAC_BALANCE) && strTCT.fEnablePrintBalanceInq == 1)
		|| ((srTransRec.byTransType == BALANCE_INQUIRY || srTransRec.byTransType == SMAC_BALANCE) && srTransRec.fSMACFooter == TRUE) )
		if( printCheckPaper()==-1)
    		return -1;

#if 0	
#if 0
	vdDisplayAnimateBmp(0,0, "Printer1(320240).bmp", "Printer2(320240).bmp", "Printer3(320240).bmp", NULL, NULL);
#else
	if (strlen(srTransRec.szRespCode) > 0){
		CTOS_LCDTClearDisplay();
		//vdDispTransTitle(srTransRec.byTransType);
		
		if(strTCT.fDisplayAPPROVED == TRUE && srTransRec.byTransType != SMAC_BALANCE && srTransRec.byTransType != BALANCE_INQUIRY) // Terminal will display the SMAC balance instead of the "APPROVED" message. 
		{
			vdDispTransTitle(srTransRec.byTransType);
			vdDisplayErrorMsgResp2(" ", " ","APPROVED");
				
			//vduiDisplayStringCenter(8,"TRANSACTION APPROVED"); /*BDO : Request -- sidumili*/
			//WaitKey(1);
		}
		else
			CTOS_Beep();
	}
#endif
#endif	

    //gcitra
	if (srTransRec.byTransType == CASH_LOYALTY){
		result = ushCTOS_printAll(CUSTOMER_COPY_RECEIPT);
		CTOS_KBDBufFlush();//cleare key buffer
	    	return (d_OK);
	}
    //gcitra
	fNSRflag = inNSRFlag();//inCTOSS_GetBatchFieldData(&srTransFlexiData, AMEX_NSR_FLAG, &fNSRflag, 1);
	vdDebug_LogPrintf("fNSRflag=[%d],fNSRCustCopy=[%d]",fNSRflag,strTCT.fNSRCustCopy);
	if (fNSRflag == 1 && 1 != strTCT.fNSRCustCopy)
	{
		CustCopy = FALSE;//return (d_OK);
	}

    if(srTransRec.byTransType == SMAC_BALANCE || srTransRec.byTransType == BALANCE_INQUIRY) 
    {
		BankCopy=MercCopy=CustCopy=FALSE;
        if(strTCT.fEnablePrintBalanceInq == 1 || srTransRec.fSMACFooter == TRUE)
		    CustCopy=TRUE;
    }

	vdCTOS_PrintReceiptCopies(BankCopy, CustCopy, MercCopy, TRUE);
	
	return (d_OK);
}

USHORT ushCTOS_PrintDCCRateFooterEx(int page)
{		
	BYTE EMVtagVal[64] = {0};
	USHORT EMVtagLen = 0; 
    BYTE baTemp[PAPER_X_SIZE * 64];
    char szStr[d_LINE_SIZE + 3];
	int fNSRflag = 0;

	//if(srTransRec.fDCC && (srTransRec.byTransType == SALE||srTransRec.byTransType == SALE_OFFLINE||srTransRec.byTransType == SALE_ADJUST||
		//(srTransRec.byTransType == VOID && srTransRec.byOrgTransType == SALE)))

	vdPrintDCCFooterForPrintDCCRates();

	fNSRflag = inNSRFlag();

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
	EMVtagLen = 0;
	
    DebugAddINT("ushCTOS_PrintFooter,mode",srTransRec.byEntryMode);  
    
    vdDebug_LogPrintf("CVM [%02X %02X %02X]",
    srTransRec.stEMVinfo.T9F34[0], srTransRec.stEMVinfo.T9F34[1], srTransRec.stEMVinfo.T9F34[2]);
    vdDebug_LogPrintf("srTransRec.byEntryMode = [%d], strTCT.inCustomerCopy[%d]", srTransRec.byEntryMode, strTCT.inCustomerCopy);
    	
    vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    

    vdPrintFooterText();

    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 8 of 13
    if(page == BANK_COPY_RECEIPT)
        vdPrintCenter("--- BANK COPY ---");
    else if(page == CUSTOMER_COPY_RECEIPT)
        vdPrintCenter("--- CUSTOMER COPY ---");
    else if(page = MERCHANT_COPY_RECEIPT)
        vdPrintCenter("--- MERCHANT COPY ---");
    //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 8 of 13
    /***************************************************/

    //sidumili: Issue#000135 [Print Footer Logo]
    if (srTransRec.fFooterLogo)
    {
        //CTOS_PrinterFline(d_LINE_DOT * 2); 
        //vdCTOSS_PrintFooterLogoBMPPic(0, 0, "footer.bmp");
        //vdCTOSS_PrinterBMPPicEx(0,0,"/home/ap/pub/footer.bmp");  
        vdCTOSS_PrinterBMPPic(0, 0, "/home/ap/pub/footer.bmp");
    }
    /***************************************************/

	vdLineFeed(srTransRec.fFooterLogo);
	
    return d_OK;	
}

void vdPrintDCCFooterForPrintDCCRates(void)
{
	char szStr[d_LINE_SIZE + 3];
	char szTemp[d_LINE_SIZE + 3];
	char szFxRate[d_LINE_SIZE + 3];
	char szBaseAmount[20] = {0};
    char szTipAmount[20] = {0};
	char szTotalAmount[AMT_ASC_SIZE+1];
	BYTE szAmtBuff[20+1], szCurAmtBuff[20+1], szDCCAmtBuff[20+1];
	int inLength;
	float inMarkup=0;
	char szLogoPath[50+1];
#if 0	
	inLength=strlen(srTransRec.szDCCFXRate)-srTransRec.inDCCFXRateMU;
	memset(szFxRate,0x00,sizeof(szFxRate));
	memcpy(szFxRate,srTransRec.szDCCFXRate,inLength);
	memcpy(&szFxRate[inLength],".",1);
	memcpy(&szFxRate[inLength+1],&srTransRec.szDCCFXRate[inLength],srTransRec.inDCCFXRateMU);
	
	memset(szStr,0x00,d_LINE_SIZE);
	sprintf(szStr, "EXCHANGE RATE : %s 1.00 = %s %s", srTransRec.szDCCLocalSymbol, srTransRec.szDCCCurSymbol, szFxRate);	
	inPrint(szStr);

	memset(szTemp,0x00,sizeof(szTemp));
	memset(szStr,0x00,sizeof(szStr));

	inMarkup = atof(srTransRec.szDCCMarkupPer);
	sprintf(szTemp,"%.2f",inMarkup);
	sprintf(szStr,"MARK-UP : %s",szTemp);
	strcat(szStr,"%");
	inPrint(szStr);

#endif
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);	

	if(srTransRec.byTransType != VOID)
	{
		memset(szBaseAmount,0x00,sizeof(szBaseAmount));
		memset(szTipAmount,0x00,sizeof(szTipAmount));
		memset(szTotalAmount,0x00,sizeof(szTotalAmount));
		memset(szAmtBuff,0x00,sizeof(szAmtBuff));

        /*local amounts*/
		wub_hex_2_str(srTransRec.szTipAmount, szTipAmount, 6);
		wub_hex_2_str(srTransRec.szBaseAmount, szBaseAmount, 6); 
		vdDebug_LogPrintf("LOCAL:: szTipAmount [%s]",szTipAmount);
		vdDebug_LogPrintf("LOCAL:: szDCCLocalAmount [%s]",szBaseAmount);
		//sprintf(szTotalAmount, "%012.0f", atof(szBaseAmount) + ( atof(szTipAmount) / atof(szFxRate))  );
		sprintf(szTotalAmount, "%012.0f", atof(szBaseAmount) + atof(szTipAmount));
		vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTotalAmount,szAmtBuff); 
		sprintf(szCurAmtBuff,"%s%s", srTransRec.szDCCLocalSymbol, szAmtBuff);
		vdDebug_LogPrintf("LOCAL:: szCurAmtBuff [%s]",szCurAmtBuff);
		
		memset(szAmtBuff,0x00,sizeof(szAmtBuff));
		memset(szDCCAmtBuff,0x00,sizeof(szDCCAmtBuff));
		memset(szBaseAmount,0x00,sizeof(szBaseAmount));
		memset(szTipAmount,0x00,sizeof(szTipAmount));
		memset(szTotalAmount,0x00,sizeof(szTotalAmount));

		/*dcc amounts*/
		//wub_hex_2_str(srTransRec.szTipAmount, szTipAmount, 6);
	   	//wub_hex_2_str(srTransRec.szDCCCurAmt, szBaseAmount, 6);
		sprintf(szTotalAmount, "%012.0f", atof(srTransRec.szDCCCurAmt));

		if(strTCT.fFormatDCCAmount == TRUE)
    		vdDCCModifyAmount(szTotalAmount,szAmtBuff);
		else
			vdCTOS_FormatAmount(strCST.szAmountFormat, szTotalAmount,szAmtBuff); 
		
		sprintf(szDCCAmtBuff,"%s%s",srTransRec.szDCCCurSymbol, szAmtBuff);// Wait for strCST for foreign currency
		vdDebug_LogPrintf("DCC:: szDCCAmtBuff [%s]",szDCCAmtBuff);

		//inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
		vdCTOSS_PrinterBMPPicEx(0, 0, "./fs_data/dccbox.bmp");
		vdDCCCenter(szCurAmtBuff,szDCCAmtBuff);
		inPrint("Total Transaction     Total Transaction");
		inPrint("      Amount                 Amount");
		sprintf(szTemp,"   %s Currency          %s Currency",srTransRec.szDCCLocalSymbol , srTransRec.szDCCCurSymbol);
		inPrint(szTemp);
	}

}

USHORT printBatchInvoiceNOExForDCCPrint(void)
{
    char szStr[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    char szTemp2[d_LINE_SIZE + 1];
    USHORT result;
    BYTE baTemp[PAPER_X_SIZE * 64];
        
    memset(szStr, ' ', d_LINE_SIZE);
    memset(szTemp1, ' ', d_LINE_SIZE);
    memset(szTemp2, ' ', d_LINE_SIZE);
	
	wub_hex_2_str(srTransRec.szBatchNo,szTemp1,3);
    wub_hex_2_str(srTransRec.szInvoiceNo, szTemp2, INVOICE_BCD_SIZE);
    vdMyEZLib_LogPrintf("invoice no: %s",szTemp2);

    //sprintf(szStr, "BATCH: %-14.14sINVOICE: %s", szTemp1, szTemp2);	// v10.0 change
    sprintf(szStr, "BATCH: %s", "000000");	// v10.0 change
	inPrint(szStr);
	
	memset(szStr, ' ', d_LINE_SIZE);
	sprintf(szStr, "INVOICE: %s", "000000");	// v10.0 change
	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	inPrint(szStr);

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 0, 0);
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
	//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
    //inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB, fERMTransaction);
    return(d_OK);
}

USHORT printBatchInvoiceNOForDCCPrint(void)
{
    char szStr[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    char szTemp2[d_LINE_SIZE + 1];
    USHORT result;
    BYTE baTemp[PAPER_X_SIZE * 64];
        
    memset(szStr, ' ', d_LINE_SIZE);
    memset(szTemp1, ' ', d_LINE_SIZE);
    memset(szTemp2, ' ', d_LINE_SIZE);
	
	wub_hex_2_str(srTransRec.szBatchNo,szTemp1,3);
    wub_hex_2_str(srTransRec.szInvoiceNo, szTemp2, INVOICE_BCD_SIZE);
    vdMyEZLib_LogPrintf("invoice no: %s",szTemp2);

    sprintf(szStr, "BATCH: %-14.14sINVOICE: %s", "000000", "000000");	// v10.0 change
    memset (baTemp, 0x00, sizeof(baTemp));		

    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
	//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
    inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB, fERMTransaction);
    return(d_OK);
}


USHORT printSMDateTime(void)
{
    char szStr[d_LINE_SIZE + 1];
    char szTemp[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
    USHORT result;
    BYTE baTemp[PAPER_X_SIZE * 64];
  	CTOS_RTC SetRTC;
	char szYear[3];
//1102
	char sMonth[4];
	char szTempMonth[3];
	char szMonthNames[40];

	memset(sMonth,0x00,4);
	memset(szMonthNames,0x00,40);
	strcpy(szMonthNames,"JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC");
	memset(szTempMonth, 0x00, 3);

//1102
	
    memset(szStr, ' ', d_LINE_SIZE);
    memset(szTemp, ' ', d_LINE_SIZE);


	CTOS_RTCGet(&SetRTC);
	sprintf(szYear ,"%02d",SetRTC.bYear);
	memcpy(srTransRec.szYear,szYear,2);
	vdDebug_LogPrintf("year[%s],date[%02x][%02x]",srTransRec.szYear,srTransRec.szDate[0],srTransRec.szDate[1]);
    wub_hex_2_str(srTransRec.szDate, szTemp,DATE_BCD_SIZE);
    wub_hex_2_str(srTransRec.szTime, szTemp1,TIME_BCD_SIZE);
	vdDebug_LogPrintf("date[%s],time[%s]atol(szTemp)=[%d](atol(szTemp1)=[%d]",szTemp,szTemp1,atol(szTemp),atol(szTemp1) );

	if(atol(szTemp) == 0)
	{
		//sprintf(szTemp ,"%02d%02d",SetRTC.bDay,SetRTC.bMonth);
		sprintf(szTemp ,"%02d%02d",SetRTC.bMonth, SetRTC.bDay);	

	}
	
	if(atol(szTemp1) == 0)
	{
		sprintf(szTemp1 ,"%02d%02d%02d",SetRTC.bHour,SetRTC.bMinute,SetRTC.bSecond);	
	}
	vdDebug_LogPrintf("date[%s],time[%s]",szTemp,szTemp1);
	memcpy(szTempMonth,&szTemp[0],2);
	memcpy(sMonth, &szMonthNames[(atoi(szTempMonth) - 1)* 3], 3);

#if 0 //removed for version 11

	if (strTCT.fSMReceipt== 1)
		sprintf(szStr,"Date/Time    : %02lu/%02lu/%04lu         %02lu:%02lu:%02lu",atol(szTemp)/100,atol(szTemp)%100,atol(srTransRec.szYear)+2000,atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100);
	else
#endif
		sprintf(szStr,"DATE/TIME    : %s %02lu, 20%02lu    %02lu:%02lu:%02lu",sMonth,atol(szTemp)%100,atol(srTransRec.szYear),atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100);
//1102    
    //memset (baTemp, 0x00, sizeof(baTemp));		
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //result = CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
    //inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
    inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,fERMTransaction);
	
    return(result);
     
}

void vdCTOS_PrintDCCandLocalAccumeByHostAndCard(int inReportType,
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
	double ulLocalSaleTotalAmount) 
	//1105
{
	char szStr[d_LINE_SIZE + 3] = {0},
		szTemp[d_LINE_SIZE + 3] = {0}, 
		szTemp1[d_LINE_SIZE + 3] = {0}, 
		szTemp2[d_LINE_SIZE + 3] = {0},
		szTemp3[d_LINE_SIZE + 3] = {0},
		szTemp4[d_LINE_SIZE + 3] = {0};
	USHORT usTotalCount = 0;
	double ulTotalAmount = 0;
	BYTE baTemp[PAPER_X_SIZE * 64] = {0};

	char szBuff[47] = {0};
	int inPADSize = 0, x = 0;
	char szSPACE[40] = {0};

	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  
	memset (baTemp, 0x00, sizeof(baTemp));		


	//0720
		if((inReportType == DETAIL_REPORT_TOTAL) || (inReportType == DETAIL_REPORT_GRANDTOTAL)){
	    
			usTotalCount = usSaleCount + usOffSaleCount + usRefundCount + usCashAdvCount + usVoidSaleCount;
			memset(baTemp, 0x00, sizeof(baTemp));
			//add cash advance in totals amount
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount+ulCashAdvTotalAmount) - ulRefundTotalAmount;
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));
			memset(szTemp3, 0x00, sizeof(szTemp3));
			memset(szTemp4, 0x00, sizeof(szTemp4));
			
			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	
				
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);

			sprintf(szTemp3,"%.0f", ulLocalSaleTotalAmount + ulTipTotalAmount);
			vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szTemp3,szTemp4);
			memset(szTemp3, 0x00, sizeof(szTemp3));
			sprintf(szTemp3,"%s%s",srTransRec.szDCCLocalSymbol,szTemp4);
			
			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%d",usTotalCount);
			
			memset(szStr, 0x20, sizeof(szStr));
				
			if (inReportType == DETAIL_REPORT_TOTAL)
				memcpy(&szStr[0],strIIT.szIssuerLabel, strlen(strIIT.szIssuerLabel));
			else
				memcpy(&szStr[0],"TOTAL", 5);
				
			memcpy(&szStr[12],szTemp1, strlen(szTemp1));

			if(strlen(szTemp3) > 12 || strlen(szTemp) > 12)
				memcpy(&szStr[16],szTemp, strlen(szTemp));
			else
				memcpy(&szStr[18],szTemp, strlen(szTemp));
			
			memcpy(&szStr[42-strlen(szTemp3)],szTemp3, strlen(szTemp3));

	    	memset(baTemp, 0x00, sizeof(baTemp));
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	
	    return;
		}
	//0720


//smac
  if (inCheckIfSMCardTransRec() == TRUE)//SM CARDS SUMMARY REPORT
  	{
	  memset(szStr, 0x00, sizeof(szStr));
	  memset(szBuff, 0x00, sizeof(szBuff));
	  memset(szTemp1, 0x00, sizeof(szTemp1)); 
	  memset(szTemp2, 0x00, sizeof(szTemp2));

	  if ((srTransRec.HDTid == SMAC_HDT_INDEX)){
		  sprintf(szTemp1,"%.0f", ulOffSaleTotalAmount);		  
		  vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	  
		  sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
		  sprintf(szStr,"PTS AWARDED   %04d",usOffSaleCount);
		  inPrintLeftRight2(szStr,szBuff,42);

		  sprintf(szTemp1,"%.0f", ulSaleTotalAmount);		  
		  vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	  
		  sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
		  sprintf(szStr,"REDEMPTION    %04d",usSaleCount);
		  
		  inPrintLeftRight2(szStr,szBuff,42);
	  }

	  if (srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMPARTNER_HDT_INDEX || srTransRec.HDTid == SMSHOPCARD_HDT_INDEX || 
	  	srTransRec.HDTid == SMGIFTCARD_HDT_INDEX || srTransRec.HDTid == SMECARD_HDT_INDEX || srTransRec.HDTid == SM_CREDIT_CARD || srTransRec.HDTid == SMSHOPCARD_HDT_INDEX){
	  	  sprintf(szTemp1,"%.0f", ulSaleTotalAmount);		  
		  vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	  
		  sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
		  sprintf(szStr,"SALE          %04d",usSaleCount);
		  
		  inPrintLeftRight2(szStr,szBuff,42);
	  }

	//void
	  memset(szStr, 0x00, sizeof(szStr));
	  memset(szBuff, 0x00, sizeof(szBuff));
	  memset(szTemp1, 0x00, sizeof(szTemp1));	
	  memset(szTemp2, 0x00, sizeof(szTemp2));

	  sprintf(szTemp1,"%.0f", ulVoidSaleTotalAmount);

	  if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
      else
	  	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	  sprintf(szBuff,"-%s%s",strCST.szCurSymbol,szTemp2);
	  sprintf(szStr,"VOID          %04d",usVoidSaleCount);
	  inPrintLeftRight2(szStr,szBuff,42);


	usTotalCount = usSaleCount + usOffSaleCount + usRefundCount + usCashAdvCount + usVoidSaleCount;
	memset(szStr, 0x00, d_LINE_SIZE);
	memset(szTemp, 0x00, d_LINE_SIZE);
	if (inReportType == PRINT_HOST_TOTAL)
	{
		if(ulRefundTotalAmount > (ulSaleTotalAmount+ulOffSaleTotalAmount))
		{
			ulTotalAmount = ulRefundTotalAmount - (ulSaleTotalAmount+ulOffSaleTotalAmount);

			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);	
			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"-%s%s",strCST.szCurSymbol,szTemp2);
			//sprintf(szStr,"  TOTALS");		
			sprintf(szStr,"TOT.          %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}
		else
		{
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount) - ulRefundTotalAmount;

			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);
			
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);
			//sprintf(szStr,"  TOTALS");			
			sprintf(szStr,"TOT.          %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}
	}
	else if(inReportType == PRINT_CARD_TOTAL)
	{
		if(ulRefundTotalAmount > (ulSaleTotalAmount+ulOffSaleTotalAmount))
		{
			ulTotalAmount = ulRefundTotalAmount - (ulSaleTotalAmount+ulOffSaleTotalAmount);
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));
			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"-%s%s",strCST.szCurSymbol,szTemp2);
			//sprintf(szStr,"  TOTALS");		
			sprintf(szStr,"TOT.          %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}
		else
		{
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount) - ulRefundTotalAmount;
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);
			//sprintf(szStr,"  TOTALS");	
			sprintf(szStr,"TOT.          %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}	 
	}



	//CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);



    return;
  }  
//smac
//BDO CARDS SUMMARY REPORT
	//sale 
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulSaleTotalAmount+ulOffSaleTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"SALE     %04d",usSaleCount+usOffSaleCount);
	inPrintLeftRight2(szStr,szBuff,42);

	//Base amount
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", (ulSaleTotalAmount+ulOffSaleTotalAmount) - ulTipTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"BASE");		
	inPrintLeftRight2(szStr,szBuff,42);

	//tip
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulTipTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	strcpy(szStr,"TIP");
	inPrintLeftRight2(szStr,szBuff,42);

	//void
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulVoidSaleTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"-%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"VOID     %04d",usVoidSaleCount);
	inPrintLeftRight2(szStr,szBuff,42);

	//refund
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulRefundTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"REF.     %04d",usRefundCount);
	inPrintLeftRight2(szStr,szBuff,42);

#if 0		
	//offline sale
	memset(szStr, ' ', d_LINE_SIZE);
	sprintf(szStr,"OFFLINE  %3d  %s  %10lu.%02lu", usOffSaleCount, strCST.szCurSymbol,ulOffSaleTotalAmount/100, ulOffSaleTotalAmount%100);
	memset (baTemp, 0x00, sizeof(baTemp));
	CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);		
#endif

	//Cash Advance
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulCashAdvTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"CADV     %04d",usCashAdvCount);
	inPrintLeftRight2(szStr,szBuff,42);

	usTotalCount = usSaleCount + usOffSaleCount + usRefundCount+usCashAdvCount;
	memset(szStr, 0x00, d_LINE_SIZE);
	memset(szTemp, 0x00, d_LINE_SIZE);
	
	if (inReportType == PRINT_HOST_TOTAL)
	{
		if(ulRefundTotalAmount > (ulSaleTotalAmount+ulOffSaleTotalAmount))
		{
			ulTotalAmount = ulRefundTotalAmount - (ulSaleTotalAmount+ulOffSaleTotalAmount);

			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"-%s%s",strCST.szCurSymbol,szTemp2);
			sprintf(szStr,"TOT.     %04d", usTotalCount);	
			inPrintLeftRight2(szStr,szTemp,42);
		}
		else
		{
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount+ulCashAdvTotalAmount) - ulRefundTotalAmount;

			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);
			sprintf(szStr,"TOT.     %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}
	}
	else if(inReportType == PRINT_CARD_TOTAL)
	{
		if(ulRefundTotalAmount > (ulSaleTotalAmount+ulOffSaleTotalAmount))
		{
			ulTotalAmount = ulRefundTotalAmount - (ulSaleTotalAmount+ulOffSaleTotalAmount);
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));
			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"-%s%s",strCST.szCurSymbol,szTemp2);
			sprintf(szStr,"TOT.     %04d", usTotalCount);	
			inPrintLeftRight2(szStr,szTemp,42);
		}
		else
		{
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount+ulCashAdvTotalAmount) - ulRefundTotalAmount;
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);
			sprintf(szStr,"TOT.     %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}	 
	}



	//CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);
}


void vdCTOS_PrintPreAuthReport(void)
{
	unsigned char chkey;
	short shHostIndex;
	int inResult,i,inCount,inRet;
	int inTranCardType;
	int inReportType;
	int inBatchNumOfRecord;
	int *pinTransDataid;

//0720
	ACCUM_REC srAccumRec;
	BYTE baTemp[PAPER_X_SIZE * 64];
	char szStr[d_LINE_SIZE + 1];
//0720

	//for MP200 no need print
	if ((strTCT.byTerminalType == 5) || (strTCT.byTerminalType == 6))
    	return (d_OK);
	
	if( printCheckPaper()==-1)
		return;

	//start-do not select Merchant if Detail report is during settlement
	//	if(fAddtoSettleReport != TRUE){
			inResult = inCTOS_TEMPCheckAndSelectMutipleMID();
			DebugAddINT("summary MITid",srTransRec.MITid);
			if(d_OK != inResult)
				return;
	//	}
	//end


	/* BDO: Include detailed report to settlement receipt - start -- jzg */
	
	//shHostIndex = inCTOS_SelectHostSetting();
	shHostIndex = inCTOS_SelectPreAuthHostSettingWithIndicator(1);
	if (shHostIndex == -1)
		return;
		
		strHDT.inHostIndex = shHostIndex;
	
	/* BDO: Include detailed report to settlement receipt - end -- jzg */
	
	DebugAddINT("summary host Index",shHostIndex);

	if (inMultiAP_CheckMainAPStatus() == d_OK)
	{
	inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_CARDVER_REPORT);
		if(d_OK != inRet)
			return ;
	}
	else
	{
		if (inMultiAP_CheckSubAPStatus() == d_OK)
		{
			inRet = inCTOS_MultiAPGetData();
			if(d_OK != inRet)
				return ;

			inRet = inCTOS_MultiAPReloadHost();
			if(d_OK != inRet)
				return ;
		}
	}


	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

	vdDebug_LogPrintf("TEST DETAIL %d %d", srTransRec.HDTid,srTransRec.MITid);

#if 1
		inResult = inCTOS_ChkifPreAuthExists();
		if(d_OK != inResult)
			return;
		
		vdCTOS_PrintMerchantPreAuthReport(); /*albert - to have a common receipt on Detail Report*/
#endif
	
	return;	
}


void vdCTOS_PrintMerchantPreAuthReport(void)
{
    unsigned char chkey;
    short shHostIndex;
    int inResult,i,inCount,inRet;
    int inTranCardType;
    int inReportType;
    int inBatchNumOfRecord;
    int *pinTransDataid;
    
    ACCUM_REC srAccumRec;
    BYTE baTemp[PAPER_X_SIZE * 64];
    char szStr[d_LINE_SIZE + 1];

		//int inRet = d_NO;
		int inNumOfHost = 0, inNum = 0;
		char szBcd[INVOICE_BCD_SIZE+1] = {0};
		char szErrMsg[31] = {0};
		char szAPName[25] = {0};
		int inAPPID = 0;
    BOOL fPrintDetail=FALSE;

    inCSTRead(strHDT.inCurrencyIdx); /*to load Currence and amount format*/
	
	vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);

	vdPrintReportDisplayBMP();

    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
    vdSetGolbFontAttrib(d_FONT_24x24, NORMAL_SIZE, NORMAL_SIZE, 0, 0);
    
    ushCTOS_printPreAuthBatchRecordHeader();

    //inBatchNumOfRecord = inBatchNumRecord();
    //change to include even pre-auth, function ushCTOS_printBatchRecordFooter will just exclude the pre-auth trans during printing
    inBatchNumOfRecord = inBatchNumALLRecord();
		
    pinTransDataid = (int*)malloc(inBatchNumOfRecord  * sizeof(int));
    inCount = 0;		
    inBatchByMerchandHost(inBatchNumOfRecord, srTransRec.HDTid, srTransRec.MITid, srTransRec.szBatchNo, pinTransDataid);
    for(i=0; i<inBatchNumOfRecord; i++)
    {
        inResult = inDatabase_BatchReadByTransId(&srTransRec, pinTransDataid[inCount]);
        inCount ++;
        ushCTOS_printPreAuthBatchRecordFooter();	
    }

    free(pinTransDataid);
	
    memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
    {
        vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
        return; 	 
    }

    //CTOS_PrinterFline(d_LINE_DOT * 1);
    //CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(2);
    
    memset(szStr, 0x20, sizeof(szStr));
	sprintf(szStr,"CARD TYPE        COUNT                 AMT ");
    inPrint(szStr);

    for(inTranCardType = 0; inTranCardType < 1 ;inTranCardType ++)
    {
		if(srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMGIFTCARD_HDT_INDEX)
			inTranCardType = 1;
						
        inReportType = DETAIL_REPORT_TOTAL;
        
        for(i= 0; i <30; i ++ )
        {
            vdDebug_LogPrintf("--Count[%d]", i);
            if(srAccumRec.stBankTotal[inTranCardType].stCardTotal[i].usPreAuthCount == 0)
                continue;
            
            vdDebug_LogPrintf("Count[%d]", i); 
            inIITRead(i);
            memset(szStr, ' ', d_LINE_SIZE);
            memset (baTemp, 0x00, sizeof(baTemp));
            
            inCSTRead(strHDT.inCurrencyIdx);
			
		   	vdCTOS_PrintPreAuthAccumeByHostAndCard (inReportType, srAccumRec.stBankTotal[inTranCardType].stCardTotal[i]);
			//deduct void cash advance on Detail total
		
        }
			
        printDividingLine(DIVIDING_LINE);
        
        inReportType = DETAIL_REPORT_GRANDTOTAL;

	   	vdCTOS_PrintPreAuthAccumeByHostAndCard (inReportType, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal);

    }
		
	//CTOS_PrinterFline(d_LINE_DOT * 10);
	vdCTOS_PrinterFline(10);

    vdCTOSS_PrinterEnd();
	
    return;	
}


USHORT ushCTOS_printPreAuthBatchRecordFooter(void)
{
	BYTE baTemp[PAPER_X_SIZE * 64] = {0};
	char szStr[d_LINE_SIZE + 1] = {0};
	char szPrintBuf[d_LINE_SIZE + 1] = {0};
	char szTempBuf1[d_LINE_SIZE + 1] = {0};
	char szTempBuf2[d_LINE_SIZE + 1] = {0};
	char szTempBuf3[d_LINE_SIZE + 1] = {0};
	char szTempBuf4[d_LINE_SIZE + 1] = {0};
	char szTemp[d_LINE_SIZE + 3] = {0};
	int i = 0;

	DebugAddSTR("ushCTOS_printBatchRecordFooter", srTransRec.szPAN, 10);

    //test
    memset(szStr, 0x00, sizeof(szStr));
    wub_hex_2_str(srTransRec.szInvoiceNo, szStr, INVOICE_BCD_SIZE);
	vdDebug_LogPrintf("TRANS TYPE %d %s %d", srTransRec.byTransType, szStr, srTransRec.fOnlineSALE );

	
	//test
	/*sidumili: Issue#: 000098 [do not print CARD VERIFY/PRE-AUTH on detail report]*/

	//version16
	//if (srTransRec.byTransType != PRE_AUTH) 
	if (srTransRec.byTransType != PRE_AUTH  && srTransRec.byTransType != VOID_PREAUTH) 
		//version16
	{ 
		return;
	}

	memset(szTempBuf1,0,sizeof(szTempBuf1));
	memset(szTempBuf2,0,sizeof(szTempBuf2));
	memset(szTempBuf4, 0, sizeof(szTempBuf4));
	//strcpy(szTempBuf1,srTransRec.szPAN);    
	inIITRead(srTransRec.IITid);
	strcpy(szTempBuf4,strIIT.szIssuerLabel);

	vdCTOS_FormatPAN2(strHDT.szDetailReportMask, srTransRec.szPAN, szTempBuf1);
	if (strlen(srTransRec.szPAN) > 16)
		vdRemoveSpace(szTempBuf2, szTempBuf1);		
	else
		strcpy(szTempBuf2, szTempBuf1);

	memset (szPrintBuf, 0x00, sizeof(szPrintBuf));
	strcpy(szPrintBuf, szTempBuf2);
	memset(&szPrintBuf[strlen(szPrintBuf)], 0x20, 25-strlen(szTempBuf2));
	strcat(szPrintBuf, szTempBuf4);
	inPrint(szPrintBuf);

	//Exp date and inv num
	memset(szTempBuf1, 0, sizeof(szTempBuf1));
	memset(szTempBuf2, 0, sizeof(szTempBuf2));
	memset(szTempBuf3, 0, sizeof(szTempBuf3));

	wub_hex_2_str(srTransRec.szExpireDate, szTempBuf1,EXPIRY_DATE_BCD_SIZE);
	DebugAddSTR("detail--EXP",szTempBuf1,12);  

	for (i =0; i<4;i++)
		szTempBuf1[i] = '*';
	
	memcpy(szTempBuf2,&szTempBuf1[0],2);
	memcpy(szTempBuf3,&szTempBuf1[2],2);

	memset(szStr, 0,sizeof(szStr));
	wub_hex_2_str(srTransRec.szInvoiceNo, szStr, INVOICE_BCD_SIZE);

	memset (szPrintBuf, 0x00, sizeof(szPrintBuf));
	strcpy(szPrintBuf, szTempBuf2);
	strcat(szPrintBuf, szTempBuf3);
	memset(&szPrintBuf[strlen(szPrintBuf)], 0x20, 25-strlen(szTempBuf2)-strlen(szTempBuf3));
	strcat(szPrintBuf, szStr);
	inPrint(szPrintBuf);

	memset(szTempBuf1, 0,sizeof(szTempBuf1));
	memset(szTempBuf2, 0,sizeof(szTempBuf2));
	memset(szTempBuf3, 0,sizeof(szTempBuf3));
	memset (szPrintBuf, 0x00, sizeof(szPrintBuf));
	strcpy(szTempBuf1, srTransRec.szAuthCode);
	wub_hex_2_str(srTransRec.szTotalAmount, szTempBuf2, AMT_BCD_SIZE);
	vdCTOS_FormatAmount(strCST.szAmountFormat, szTempBuf2, szTempBuf3);// patrick add code 20141216
	strcpy(szPrintBuf,szTempBuf1);
	memset(&szPrintBuf[strlen(szPrintBuf)], 0x20, 25-strlen(szTempBuf1));

    //version16
	if(srTransRec.byTransType == VOID_PREAUTH)
	{
		    memset(szTempBuf2, 0x00, sizeof(szTempBuf2));
			strcpy(szTempBuf2, szTempBuf3);		
			memset(szTempBuf3, 0, sizeof(szTempBuf3));
			sprintf(szTempBuf3, "-%s", szTempBuf2);
	}
	//version16

	strcat(szPrintBuf, szTempBuf3);
	inPrint(szPrintBuf);

	if(srTransRec.byEntryMode == CARD_ENTRY_MSR)
		inPrint("SWIPE");
	else if(srTransRec.byEntryMode == CARD_ENTRY_ICC)
		inPrint("ICC");
	else if(srTransRec.byEntryMode == CARD_ENTRY_FALLBACK)	
		inPrint("FALLBACK");
	else if(srTransRec.byEntryMode == CARD_ENTRY_MANUAL)	
		inPrint("MANUAL");	
	
	vdCTOS_PrinterFline(1);	
	
}


USHORT ushCTOS_printPreAuthBatchRecordHeader(void)
{
	USHORT result;
	BYTE baTemp[PAPER_X_SIZE * 64];


	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

    ushCTOS_PrintHeader(0);	
     
	printTIDMID(TRUE);
    
	printDateTime();
    
	printBatchNO();

	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
    vdPrintCenter("CARD VERIFY REPORT");

	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
    
    vdCTOS_PrinterFline(1);
	inCCTOS_PrinterBufferOutput("CARD NUMBER              CARD NAME",&stgFONT_ATTRIB,1);
    inCCTOS_PrinterBufferOutput("EXP DATE                 TRACE NUMBER",&stgFONT_ATTRIB,1);
	inCCTOS_PrinterBufferOutput("APPROVAL CODE            AMOUNT",&stgFONT_ATTRIB,1);
	inCCTOS_PrinterBufferOutput("ENTRY MODE                        ",&stgFONT_ATTRIB,1);
	
	printDividingLine(DIVIDING_LINE);
	return d_OK;
}

void vdCTOS_PrintPreAuthAccumeByHostAndCard(int inReportType, STRUCT_TOTAL Totals) 
{
	int inPADSize = 0, x = 0;
	char szStr[d_LINE_SIZE + 3] = {0};
	char szTemp[d_LINE_SIZE + 3] = {0}; 
	char szTemp1[d_LINE_SIZE + 3] = {0}; 
	char szTemp2[d_LINE_SIZE + 3] = {0};
	char szSPACE[40] = {0};
	char szBuff[47] = {0};
	BYTE baTemp[PAPER_X_SIZE * 64] = {0};
	USHORT usTotalCount = Totals.usPreAuthCount;
	double ulTotalAmount = Totals.ulPreAuthTotalAmount;
		
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  
	
	//0720
	if((inReportType == DETAIL_REPORT_TOTAL) || (inReportType == DETAIL_REPORT_GRANDTOTAL))
	{
    
		//usTotalCount = usSaleCount + usOffSaleCount + usRefundCount + usCashAdvCount + usVoidSaleCount;
		//add cash advance in totals amount
		//ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount+ulCashAdvTotalAmount) - ulRefundTotalAmount;
		
		memset(szTemp1, 0x00, sizeof(szTemp1)); 
		memset(szTemp2, 0x00, sizeof(szTemp2));
		
		sprintf(szTemp1,"%.0f", ulTotalAmount);

		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	
			
		sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);

		memset(szTemp1, 0x00, sizeof(szTemp1));
		sprintf(szTemp1,"%d",usTotalCount);
		memset(szStr, 0x20, sizeof(szStr));
			
		if (inReportType == DETAIL_REPORT_TOTAL)
			memcpy(&szStr[0],strIIT.szIssuerLabel, strlen(strIIT.szIssuerLabel));
		else
			memcpy(&szStr[0],"TOTAL", 5);
			
		memcpy(&szStr[18],szTemp1, strlen(szTemp1));
		memcpy(&szStr[42-strlen(szTemp)],szTemp, strlen(szTemp));

    	inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);

    	return;
	}
}



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
	double ulPtsAwardTotalAmount) 
	//1105
{
	char szStr[d_LINE_SIZE + 3] = {0},
		szTemp[d_LINE_SIZE + 3] = {0}, 
		szTemp1[d_LINE_SIZE + 3] = {0}, 
		szTemp2[d_LINE_SIZE + 3] = {0};
	USHORT usTotalCount = 0;
	double ulTotalAmount = 0;
	BYTE baTemp[PAPER_X_SIZE * 64] = {0};

	char szBuff[47] = {0};
	int inPADSize = 0, x = 0;
	char szSPACE[40] = {0};

	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  
	memset (baTemp, 0x00, sizeof(baTemp));		


	//0720
		if((inReportType == DETAIL_REPORT_TOTAL) || (inReportType == DETAIL_REPORT_GRANDTOTAL)){
	    
			usTotalCount = usSaleCount + usOffSaleCount + usRefundCount + usCashAdvCount + usVoidSaleCount /*+ usKitSaleCount + usRenewalCount + usPtsAwardCount*/;
			memset(baTemp, 0x00, sizeof(baTemp));
			//add cash advance in totals amount
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount+ulCashAdvTotalAmount/*+ulKitSaleTotalAmount+ulRenewalTotalAmount+ulPtsAwardTotalAmount*/) - ulRefundTotalAmount;
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));
			
			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	
				
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);

			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%d",usTotalCount);
			memset(szStr, 0x20, sizeof(szStr));
				
			if (inReportType == DETAIL_REPORT_TOTAL)
				memcpy(&szStr[0],strIIT.szIssuerLabel, strlen(strIIT.szIssuerLabel));
			else
				memcpy(&szStr[0],"TOTAL", 5);
				
			memcpy(&szStr[18],szTemp1, strlen(szTemp1));
			memcpy(&szStr[42-strlen(szTemp)],szTemp, strlen(szTemp));

	    	memset(baTemp, 0x00, sizeof(baTemp));
			//CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
			//CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
			inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	
	    return;
		}
	//0720


//smac
  if (inCheckIfSMCardTransRec() == TRUE)//SM CARDS SUMMARY REPORT
  	{
	  memset(szStr, 0x00, sizeof(szStr));
	  memset(szBuff, 0x00, sizeof(szBuff));
	  memset(szTemp1, 0x00, sizeof(szTemp1)); 
	  memset(szTemp2, 0x00, sizeof(szTemp2));

	  if ((srTransRec.HDTid == SMAC_HDT_INDEX)){
		  //sprintf(szTemp1,"%.0f", ulPtsAwardTotalAmount);		  
		  sprintf(szTemp1,"%.0f", ulOffSaleTotalAmount);		  
		  vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	  
		  sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
		  //sprintf(szStr,"PTS AWARDED   %04d",usPtsAwardCount);
		  sprintf(szStr,"PTS AWARDED   %04d",usOffSaleCount);
		  inPrintLeftRight2(szStr,szBuff,42);

		  sprintf(szTemp1,"%.0f", ulSaleTotalAmount);		  
		  vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	  
		  sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
		  sprintf(szStr,"REDEMPTION    %04d",usSaleCount);
		  inPrintLeftRight2(szStr,szBuff,42);
/*
		  memset(szTemp1, 0x00, sizeof(szTemp1)); 
	      memset(szTemp2, 0x00, sizeof(szTemp2));
		  sprintf(szTemp1,"%.0f", ulKitSaleTotalAmount);		  
		  vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	  
		  sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
		  sprintf(szStr,"KIT SALE      %04d",usKitSaleCount);	 
		  inPrintLeftRight2(szStr,szBuff,42);

		  memset(szTemp1, 0x00, sizeof(szTemp1)); 
	      memset(szTemp2, 0x00, sizeof(szTemp2));
		  sprintf(szTemp1,"%.0f", ulRenewalTotalAmount);		  
		  vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	  
		  sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
		  sprintf(szStr,"RENEWAL       %04d",usRenewalCount);	 
		  inPrintLeftRight2(szStr,szBuff,42);
*/

	  }

	  if (srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMPARTNER_HDT_INDEX || srTransRec.HDTid == SMSHOPCARD_HDT_INDEX || 
	  	srTransRec.HDTid == SMGIFTCARD_HDT_INDEX || srTransRec.HDTid == SMECARD_HDT_INDEX || srTransRec.HDTid == SM_CREDIT_CARD || srTransRec.HDTid == SMSHOPCARD_HDT_INDEX){
	  	  sprintf(szTemp1,"%.0f", ulSaleTotalAmount);		  
		  vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216	  
		  sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
		  sprintf(szStr,"SALE          %04d",usSaleCount);
		  
		  inPrintLeftRight2(szStr,szBuff,42);
	  }

	//void
	  memset(szStr, 0x00, sizeof(szStr));
	  memset(szBuff, 0x00, sizeof(szBuff));
	  memset(szTemp1, 0x00, sizeof(szTemp1));	
	  memset(szTemp2, 0x00, sizeof(szTemp2));

	  sprintf(szTemp1,"%.0f", ulVoidSaleTotalAmount);

	  if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
      else
	  	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	  sprintf(szBuff,"-%s%s",strCST.szCurSymbol,szTemp2);
	  sprintf(szStr,"VOID          %04d",usVoidSaleCount);
	  inPrintLeftRight2(szStr,szBuff,42);


	usTotalCount = usSaleCount + usOffSaleCount + usRefundCount + usCashAdvCount + usVoidSaleCount/* + usKitSaleCount + usRenewalCount + usPtsAwardCount*/;
	memset(szStr, 0x00, d_LINE_SIZE);
	memset(szTemp, 0x00, d_LINE_SIZE);
	if (inReportType == PRINT_HOST_TOTAL)
	{
		if(ulRefundTotalAmount > (ulSaleTotalAmount+ulOffSaleTotalAmount/*+ulKitSaleTotalAmount+ulRenewalTotalAmount+ulPtsAwardTotalAmount*/))
		{
			ulTotalAmount = ulRefundTotalAmount - (ulSaleTotalAmount+ulOffSaleTotalAmount/*+ulKitSaleTotalAmount+ulRenewalTotalAmount+ulPtsAwardTotalAmount*/);

			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);	
			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"-%s%s",strCST.szCurSymbol,szTemp2);
			//sprintf(szStr,"  TOTALS");		
			sprintf(szStr,"TOT.          %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}
		else
		{
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount/*+ulKitSaleTotalAmount+ulRenewalTotalAmount+ulPtsAwardTotalAmount*/) - ulRefundTotalAmount;

			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);
			
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);
			//sprintf(szStr,"  TOTALS");			
			sprintf(szStr,"TOT.          %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}
	}
	else if(inReportType == PRINT_CARD_TOTAL)
	{
		if(ulRefundTotalAmount > (ulSaleTotalAmount+ulOffSaleTotalAmount/*+ulKitSaleTotalAmount+ulRenewalTotalAmount+ulPtsAwardTotalAmount*/))
		{
			ulTotalAmount = ulRefundTotalAmount - (ulSaleTotalAmount+ulOffSaleTotalAmount/*+ulKitSaleTotalAmount+ulRenewalTotalAmount+ulPtsAwardTotalAmount*/);
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));
			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"-%s%s",strCST.szCurSymbol,szTemp2);
			//sprintf(szStr,"  TOTALS");		
			sprintf(szStr,"TOT.          %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}
		else
		{
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount/*+ulKitSaleTotalAmount+ulRenewalTotalAmount+ulPtsAwardTotalAmount*/) - ulRefundTotalAmount;
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);
			//sprintf(szStr,"  TOTALS");	
			sprintf(szStr,"TOT.          %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}	 
	}



	//CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);



    return;
  }  
//smac
//BDO CARDS SUMMARY REPORT
	//sale 
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulSaleTotalAmount+ulOffSaleTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"SALE     %04d",usSaleCount+usOffSaleCount);
	inPrintLeftRight2(szStr,szBuff,42);

	//Base amount
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", (ulSaleTotalAmount+ulOffSaleTotalAmount) - ulTipTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"BASE");		
	inPrintLeftRight2(szStr,szBuff,42);

	//tip
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulTipTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	strcpy(szStr,"TIP");
	inPrintLeftRight2(szStr,szBuff,42);

	//void
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulVoidSaleTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"-%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"VOID     %04d",usVoidSaleCount);
	inPrintLeftRight2(szStr,szBuff,42);

	//refund
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulRefundTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"REF.     %04d",usRefundCount);
	inPrintLeftRight2(szStr,szBuff,42);

#if 0		
	//offline sale
	memset(szStr, ' ', d_LINE_SIZE);
	sprintf(szStr,"OFFLINE  %3d  %s  %10lu.%02lu", usOffSaleCount, strCST.szCurSymbol,ulOffSaleTotalAmount/100, ulOffSaleTotalAmount%100);
	memset (baTemp, 0x00, sizeof(baTemp));
	CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);		
#endif

	//Cash Advance
	memset(szStr, 0x00, sizeof(szStr));
	memset(szBuff, 0x00, sizeof(szBuff));
	memset(szTemp1, 0x00, sizeof(szTemp1));	
	memset(szTemp2, 0x00, sizeof(szTemp2));

	sprintf(szTemp1,"%.0f", ulCashAdvTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szTemp1,szTemp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
	sprintf(szBuff,"%s%s",strCST.szCurSymbol,szTemp2);
	sprintf(szStr,"CADV     %04d",usCashAdvCount);
	inPrintLeftRight2(szStr,szBuff,42);

	usTotalCount = usSaleCount + usOffSaleCount + usRefundCount+usCashAdvCount;
	memset(szStr, 0x00, d_LINE_SIZE);
	memset(szTemp, 0x00, d_LINE_SIZE);
	
	if (inReportType == PRINT_HOST_TOTAL)
	{
		if(ulRefundTotalAmount > (ulSaleTotalAmount+ulOffSaleTotalAmount))
		{
			ulTotalAmount = ulRefundTotalAmount - (ulSaleTotalAmount+ulOffSaleTotalAmount);

			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"-%s%s",strCST.szCurSymbol,szTemp2);
			sprintf(szStr,"TOT.     %04d", usTotalCount);	
			inPrintLeftRight2(szStr,szTemp,42);
		}
		else
		{
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount+ulCashAdvTotalAmount) - ulRefundTotalAmount;

			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);
			sprintf(szStr,"TOT.     %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}
	}
	else if(inReportType == PRINT_CARD_TOTAL)
	{
		if(ulRefundTotalAmount > (ulSaleTotalAmount+ulOffSaleTotalAmount))
		{
			ulTotalAmount = ulRefundTotalAmount - (ulSaleTotalAmount+ulOffSaleTotalAmount);
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));
			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"-%s%s",strCST.szCurSymbol,szTemp2);
			sprintf(szStr,"TOT.     %04d", usTotalCount);	
			inPrintLeftRight2(szStr,szTemp,42);
		}
		else
		{
			ulTotalAmount = (ulSaleTotalAmount+ulOffSaleTotalAmount+ulCashAdvTotalAmount) - ulRefundTotalAmount;
			memset(szTemp1, 0x00, sizeof(szTemp1)); 
			memset(szTemp2, 0x00, sizeof(szTemp2));

			sprintf(szTemp1,"%.0f", ulTotalAmount);

			if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
				vdDCCModifyAmount(szTemp1,szTemp2);
			else
				vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp1,szTemp2);// patrick add code 20141216		
			sprintf(szTemp,"%s%s",strCST.szCurSymbol,szTemp2);
			sprintf(szStr,"TOT.     %04d", usTotalCount);							
			inPrintLeftRight2(szStr,szTemp,42);
		}	 
	}



	//CTOS_PrinterFline(d_LINE_DOT * 1);
	vdCTOS_PrinterFline(1);
}

char* chGetErrorText(USHORT bErrorCode)
{
	char szErrorText[64+1] = {0};


	vdDebug_LogPrintf("chGetErrorText START --- strTMSDetail.usReterr [%d]" ,strTMSDetail.usReterr);


	if(get_env_int("MISSEDADC") == 1)
		{
			//strcpy(szErrorText,"Missed ADC Sched");
			strcpy(szErrorText,"TERM NO POWER");
			strTMSDetail.usReterr = 0x99;// set for reprint
			return szErrorText;
		}

#if 0
	if ((get_env_int("POWERFAILTMS") == 1) &&
		(bErrorCode != 0x2376))
		{

			strcpy(szErrorText,"POWER FAILED");
			return szErrorText;
	
		}

#endif
	vdDebug_LogPrintf("MISSEDADC [%d]  POWERFAILTMS[%d]",  get_env_int("MISSEDADC"), get_env_int("POWERFAILTMS"));

#if 0	
	
	if(bErrorCode ==  0x5400)
		strcpy(szErrorText,"UNDEFINED ERROR");
	else if (bErrorCode == 0x5411)
		strcpy(szErrorText,"SOCKET FULL");
	else if (bErrorCode == 0x5412)
		strcpy(szErrorText,"SOCKET ERROR");
	else if (bErrorCode == 0x5420)
		strcpy(szErrorText,"DEVICE BUSY");
	else if (bErrorCode == 0x5421)
		strcpy(szErrorText,"DEVICE STATUS ERROR");
	else if (bErrorCode == 0x5422)
		strcpy(szErrorText,"DEVICE NOT SUPPORTED");
	else if (bErrorCode == 0x5430)
		strcpy(szErrorText,"DEVICE NOT NEW");
	else if (bErrorCode == 0x5431)
		strcpy(szErrorText,"CONNECT FAILED");
	else if (bErrorCode == 0x5432)
		strcpy(szErrorText,"DEVICE NOT OPEN");
	else if (bErrorCode == 0x5433)
		strcpy(szErrorText,"PRE-CONNECT FAILED");
	else if (bErrorCode == 0x5434)
		strcpy(szErrorText,"DEVICE NOT CONNECTED");
	else if (bErrorCode == 0x5435)
		strcpy(szErrorText,"DEVICE NOT DISCONNECTED");
	else if (bErrorCode == 0x5436)
		strcpy(szErrorText,"DEVICE NOT CLOSED");
	else if (bErrorCode == 0x5440)
		strcpy(szErrorText,"INVALID CONFIG");
	else if (bErrorCode == 0x5450)
		strcpy(szErrorText,"I/O BUSY");
	else if (bErrorCode == 0x5451)
		strcpy(szErrorText,"I/O PROCESSING");
	else if (bErrorCode == 0x5460)
		strcpy(szErrorText,"TASK NOT SUPPORTED");
	else if (bErrorCode == 0x5461)
		strcpy(szErrorText,"TASK SEQ ERROR");
	else if (bErrorCode == 0x5470)
		strcpy(szErrorText,"FAILED TO NEW DEVICE");
	else if (bErrorCode == 0x5471)
		strcpy(szErrorText,"OPEN FAILED");
	else if (bErrorCode == 0x5472)
		strcpy(szErrorText,"CONNECT FAILED");
	else if (bErrorCode == 0x5473)
		strcpy(szErrorText,"CLOSE FAILED");
	else if (bErrorCode == 0x5480)
		strcpy(szErrorText,"STACK ERROR");
	else if (bErrorCode == 0x5490)
		strcpy(szErrorText,"INVALID PARAM");
	else if (bErrorCode == 0x5491)
		strcpy(szErrorText,"NOT IN DATA MODE");
	else if (bErrorCode == 0x54A0)
		strcpy(szErrorText,"COM OPEN FAILED");
	else if (bErrorCode == 0x54A1)
		strcpy(szErrorText,"SEND FAILED");
	else if (bErrorCode == 0x54B0)
		strcpy(szErrorText,"NO RESPONSE");
	else if (bErrorCode == 0x54B1)
		strcpy(szErrorText,"BUFFER FULL");
	else if (bErrorCode == 0x54B2)
		strcpy(szErrorText,"AT CMD FAILED");
	else if (bErrorCode == 0x54C0)
		strcpy(szErrorText,"LCP TIMEOUT");
	else if (bErrorCode == 0x54C1)
		strcpy(szErrorText,"CHAP TIMEOUT");
	else if (bErrorCode == 0x54C2)
		strcpy(szErrorText,"IPCP TIMEOUT");
	else if (bErrorCode == 0x54D0)
		strcpy(szErrorText,"BAD FRAME");
	else if (bErrorCode == 0x54D1)
		strcpy(szErrorText,"PPP PROT UNSUPP");
	else if (bErrorCode == 0x54D2)
		strcpy(szErrorText,"PPP CONN FAILED");
	else if (bErrorCode == 0x54D3)
		strcpy(szErrorText,"PPP INSUFF TXN LEN");
	else if (bErrorCode == 0x54D4)
		strcpy(szErrorText,"PPP TX TIMEOUT");
	else if (bErrorCode == 0x54D5)
		strcpy(szErrorText,"PPP RX TIMEOUT");
	else if (bErrorCode == 0x54E0)
		strcpy(szErrorText,"WRONG FORMAT");
	else if (bErrorCode == 0x54F0)
		strcpy(szErrorText,"TCP CONN TIMEOUT");
	else if (bErrorCode == 0x54F1)
		strcpy(szErrorText,"TCP DISC FAILED");
	else if (bErrorCode == 0x54F2)
		strcpy(szErrorText,"OVER TCP LEN");
	else if (bErrorCode == 0x54F3)
		strcpy(szErrorText,"TCP WRONG FORMAT");
	else if (bErrorCode == 0x54F4)
		strcpy(szErrorText,"TCP TIMEOUT");
	else if (bErrorCode == 0x54F5)
		strcpy(szErrorText,"INCORRECT SEQUENCE");
	else if (bErrorCode == 0x54F6)
		strcpy(szErrorText,"TCP RETRANSMISSION");
	else if (bErrorCode == 0x54F7)
		strcpy(szErrorText,"NO ACK RECEIVED");
	else if (bErrorCode == 0x54F8)
		strcpy(szErrorText,"BUFFER IS FULL");
	else if (bErrorCode == 0x54F9)
		strcpy(szErrorText,"RESET RECEIVED");
	else if (bErrorCode == 0x5500)
		strcpy(szErrorText,"NO CARRIER");
	else if (bErrorCode == 0x5501)
		strcpy(szErrorText,"LINE BUSY");
	else if (bErrorCode == 0x5502)
		strcpy(szErrorText,"NO DIAL TONE");
	else if (bErrorCode == 0x5503)
		strcpy(szErrorText,"RING BACK");
	else if (bErrorCode == 0x5504)
		strcpy(szErrorText,"NO ANSWER");
	else if (bErrorCode == 0x5505)
		strcpy(szErrorText,"DIAL TIMEOUT");
	else if (bErrorCode == 0x5506)
		strcpy(szErrorText,"DIAL FAILED");
	else if (bErrorCode == 0x5507)
		strcpy(szErrorText,"HOOK-ON FAILED");
	else if (bErrorCode == 0x5510)
		strcpy(szErrorText,"GSM INIT FAILED");
	else if (bErrorCode == 0x5511)
		strcpy(szErrorText,"GPRS NO SIGNAL");
	else if (bErrorCode == 0x5512)
		strcpy(szErrorText,"SIM READY TIMEOUT");
	else if (bErrorCode == 0x5513)
		strcpy(szErrorText,"GPRS REG TIMEOUT");
	else if (bErrorCode == 0x5520)
		strcpy(szErrorText,"ATTACH FAILED");
	else if (bErrorCode == 0x5521)
		strcpy(szErrorText,"SDLC NOT READY");
	else if (bErrorCode == 0x5522)
		strcpy(szErrorText,"MODEM ERROR");
	else if (bErrorCode == 0x55FF)
		strcpy(szErrorText,"USER CANCEL");
	//powerfail and non-existing serial number
	//else if (bErrorCode == 7)
	//	strcpy(szErrorText,"INVALID SERIAL NUMBER");
	//else if (bErrorCode == 20079)
	//	strcpy(szErrorText,"POWER FAILED");
	//
#else
if(bErrorCode ==  0x5400)
	strcpy(szErrorText,"UNDEFINED ERR");
else if (bErrorCode == 0x5411)
	strcpy(szErrorText,"SOCKET FULL");
else if (bErrorCode == 0x5412)
	//strcpy(szErrorText,"SOCKET ERROR");
	strcpy(szErrorText,"CONNECT FAILED");
else if (bErrorCode == 0x5420)
	strcpy(szErrorText,"DEVICE BUSY");
else if (bErrorCode == 0x5421)
	strcpy(szErrorText,"DEV STAT ERR");
else if (bErrorCode == 0x5422)
	strcpy(szErrorText,"DEV NOT SPTD");
else if (bErrorCode == 0x5430)
	strcpy(szErrorText,"DEV NOT NEW");
else if (bErrorCode == 0x5431)
	//strcpy(szErrorText,"CONNECT FAILED");
	strcpy(szErrorText,"INVLID IP/PORT");
//	strcpy(szErrorText,"GENERAL ERROR");
else if (bErrorCode == 0x5432)
	strcpy(szErrorText,"DEV NOT OPEN");
else if (bErrorCode == 0x5433)
	strcpy(szErrorText,"PRE-CON FAIL");
else if (bErrorCode == 0x5434)
	strcpy(szErrorText,"DEV NOT CONTD");
else if (bErrorCode == 0x5435)
	strcpy(szErrorText,"DEV NOT DISC");
else if (bErrorCode == 0x5436)
	strcpy(szErrorText,"DEV NOT CLOSE");
else if (bErrorCode == 0x5440)
	strcpy(szErrorText,"INVALD CONFIG");
else if (bErrorCode == 0x5450)
	strcpy(szErrorText,"I/O BUSY");
else if (bErrorCode == 0x5451)
	strcpy(szErrorText,"I/O PROCESS");
else if (bErrorCode == 0x5460)
	strcpy(szErrorText,"TASK NOT SPTD");
else if (bErrorCode == 0x5461)
	strcpy(szErrorText,"TASK SEQ ERR");
else if (bErrorCode == 0x5470)
	strcpy(szErrorText,"FAIL NEW DEV");
else if (bErrorCode == 0x5471)
	strcpy(szErrorText,"OPEN FAILED");
else if (bErrorCode == 0x5472)
	strcpy(szErrorText,"CONNECT FAILED");
else if (bErrorCode == 0x5473)
	strcpy(szErrorText,"CLOSE FAILED");
else if (bErrorCode == 0x5480)
	strcpy(szErrorText,"STACK ERROR");
else if (bErrorCode == 0x5490)
	strcpy(szErrorText,"INVLD PARAM");
else if (bErrorCode == 0x5491)
	strcpy(szErrorText,"NOT IN DTA MD");
else if (bErrorCode == 0x54A0)
	strcpy(szErrorText,"COM OPEN FAIL");
else if (bErrorCode == 0x54A1)
	strcpy(szErrorText,"SEND FAILED");
else if (bErrorCode == 0x54B0)
	strcpy(szErrorText,"NO RESPONSE");
else if (bErrorCode == 0x54B1)
	strcpy(szErrorText,"BUFFER FULL");
else if (bErrorCode == 0x54B2)
	strcpy(szErrorText,"AT CMD FAILED");
else if (bErrorCode == 0x54C0)
	strcpy(szErrorText,"LCP TIMEOUT");
else if (bErrorCode == 0x54C1)
	strcpy(szErrorText,"CHAP TIMEOUT");
else if (bErrorCode == 0x54C2)
	strcpy(szErrorText,"IPCP TIMEOUT");
else if (bErrorCode == 0x54D0)
	strcpy(szErrorText,"BAD FRAME");
else if (bErrorCode == 0x54D1)
	strcpy(szErrorText,"PPP PROT UNSUPP");
else if (bErrorCode == 0x54D2)
	strcpy(szErrorText,"PPP CONN FAILED");
else if (bErrorCode == 0x54D3)
	strcpy(szErrorText,"PPP INSUFF TXN LEN");
else if (bErrorCode == 0x54D4)
	strcpy(szErrorText,"PPP TX TIMEOUT");
else if (bErrorCode == 0x54D5)
	strcpy(szErrorText,"PPP RX TIMEOUT");
else if (bErrorCode == 0x54E0)
	strcpy(szErrorText,"WRONG FORMAT");
else if (bErrorCode == 0x54F0)
	strcpy(szErrorText,"TCP CONN TIMEOUT");
else if (bErrorCode == 0x54F1)
	strcpy(szErrorText,"TCP DISC FAILED");
else if (bErrorCode == 0x54F2)
	strcpy(szErrorText,"OVER TCP LEN");
else if (bErrorCode == 0x54F3)
	strcpy(szErrorText,"TCP WRONG FORMAT");
else if (bErrorCode == 0x54F4)
	strcpy(szErrorText,"TCP TIMEOUT");
else if (bErrorCode == 0x54F5)
	strcpy(szErrorText,"INCORRECT SEQUENCE");
else if (bErrorCode == 0x54F6)
	strcpy(szErrorText,"TCP RETRANSMISSION");
else if (bErrorCode == 0x54F7)
	strcpy(szErrorText,"NO ACK RECEIVED");
else if (bErrorCode == 0x54F8)
	strcpy(szErrorText,"BUFFER IS FULL");
else if (bErrorCode == 0x54F9)
	strcpy(szErrorText,"RESET RECEIVED");
else if (bErrorCode == 0x5500)
	strcpy(szErrorText,"NO CARRIER");
else if (bErrorCode == 0x5501)
	strcpy(szErrorText,"LINE BUSY");
else if (bErrorCode == 0x5502)
	strcpy(szErrorText,"NO DIAL TONE");
else if (bErrorCode == 0x5503)
	strcpy(szErrorText,"RING BACK");
else if (bErrorCode == 0x5504)
	strcpy(szErrorText,"NO ANSWER");
else if (bErrorCode == 0x5505)
	strcpy(szErrorText,"DIAL TIMEOUT");
else if (bErrorCode == 0x5506)
	strcpy(szErrorText,"DIAL FAILED");
else if (bErrorCode == 0x5507)
	strcpy(szErrorText,"HOOK-ON FAILED");
else if (bErrorCode == 0x5510)
	strcpy(szErrorText,"GSM INIT FAILED");
else if (bErrorCode == 0x5511)
	strcpy(szErrorText,"GPRS NO SIGNAL");
else if (bErrorCode == 0x5512)
	strcpy(szErrorText,"SIM READY TIMEOUT");
else if (bErrorCode == 0x5513)
	strcpy(szErrorText,"GPRS REG TIMEOUT");
else if (bErrorCode == 0x5520)
	strcpy(szErrorText,"ATTACH FAILED");
else if (bErrorCode == 0x5521)
	strcpy(szErrorText,"SDLC NOT READY");
else if (bErrorCode == 0x5522)
	strcpy(szErrorText,"MODEM ERROR");
else if (bErrorCode == 0x55FF)
	strcpy(szErrorText,"USER CANCEL");

else if (bErrorCode == 0x2376)
	strcpy(szErrorText,"CONNECT FAILED");

//else if (bErrorCode == 7)
//	strcpy(szErrorText,"INVALID SERIAL NUMBER");
//else if (bErrorCode == 20079)
//	strcpy(szErrorText,"POWER FAILED");
//

#endif

	else
		{
			if (get_env_int("POWERFAILTMS") == 1) 
			{

				strcpy(szErrorText,"POWER FAILED");
				return szErrorText;
		
			}

			//else if (bErrorCode == 0x5431)
			//	strcpy(szErrorText,"GENERAL ERROR");
			if(bErrorCode ==  0x99)
				strcpy(szErrorText,"TERM NO POWER");
			else
				strcpy(szErrorText,"GENERAL ERROR");

		}


		
	return szErrorText;

}

void vdGetADCDateTime(int inData, CTOS_RTC *SetRTC, char *szStr)
{
	int inSec = 0;
	long inMinute = 0;
	long inHour = 0;
    char szTemp[d_LINE_SIZE + 1];
    char szTemp1[d_LINE_SIZE + 1];
	char szTemp2[d_LINE_SIZE + 1];
    USHORT result;
    BYTE baTemp[PAPER_X_SIZE * 64];
  	char szYear[3];
	char sMonth[4];
	char szTempMonth[3];
	char szMonthNames[40];

	memset(sMonth,0x00,4);
	memset(szMonthNames,0x00,40);
	strcpy(szMonthNames,"JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC");
	memset(szTempMonth, 0x00, 3);


	
    memset(szStr, ' ', d_LINE_SIZE);
    memset(szTemp, ' ', d_LINE_SIZE);


	sprintf(szYear ,"%02d",SetRTC->bYear);
	sprintf(szTemp ,"%02d%02d",SetRTC->bMonth, SetRTC->bDay);	
	sprintf(szTemp1 ,"%02d%02d%02d",SetRTC->bHour,SetRTC->bMinute,SetRTC->bSecond);	
	
	vdDebug_LogPrintf("date[%s],time[%s]",szTemp,szTemp1);
	memcpy(szTempMonth,&szTemp[0],2);
	memcpy(sMonth, &szMonthNames[(atoi(szTempMonth) - 1)* 3], 3);

	if(inData == DATE)
	{
		sprintf(szStr,"%s %02lu, %02lu",sMonth,atol(szTemp)%100,atol(szYear));
		wub_str_2_hex(szTemp,srTransRec.szDate,4);		
	}
	else if(inData == TIME)
	{
		sprintf(szStr,"%02lu:%02lu:%02lu",atol(szTemp1)/10000,atol(szTemp1)%10000/100, atol(szTemp1)%100);
		wub_str_2_hex(szTemp1,srTransRec.szTime,6);		
	}
	else if(inData == DL_TIME_END)
	{
#if 0	
		inMinute = (atol(szTemp1)%10000/100) - 1;
		inHour = (atol(szTemp1)/10000);
		vdDebug_LogPrintf("inMinute %02lu",inMinute);
		if(inMinute < 0)
		{
			inMinute = 59;
			inHour = inHour - 1;
			if(inHour < 0)
			{
				inHour = 0;
				inMinute = 0;
			}
			vdDebug_LogPrintf("inHour %02lu",inHour);
		}
#else
		if(atol(szTemp1)%100 - 30 >= 0)
		{
			inSec = atol(szTemp1)%100 - 30;
			inMinute = (atol(szTemp1)%10000/100);
			inHour = (atol(szTemp1)/10000);
		}
		else//30 seconds before the receipt time.
		{
			inSec = (120 + (atol(szTemp1)%100 - 30)) - 60;
			vdDebug_LogPrintf("inSec %lu", inSec);
			inMinute = (atol(szTemp1)%10000/100) - 1;
			inHour = (atol(szTemp1)/10000);
			vdDebug_LogPrintf("inMinute %02lu",inMinute);
			if(inMinute < 0)
			{
				inMinute = 59;
				inHour = inHour - 1;
				if(inHour < 0)
				{
					inHour = 0;
					inMinute = 0;
					inSec = 0;
				}
				vdDebug_LogPrintf("inHour %02lu",inHour);
			}
		}	
#endif
		sprintf(szStr,"%02lu:%02lu:%02lu",inHour,inMinute,inSec);
	}

	vdDebug_LogPrintf("chGetADCDateTime %s",szStr);
	
	return;
     
}


USHORT ushCTOS_PrintADCReportBody(void)
{
	USHORT usResult;
    USHORT usStatus, usReterr;
	int i = 0, inDLTypeTimeBasis = 0;
	char szStr[d_LINE_SIZE + 1];
	char szTemp1[d_LINE_SIZE+1] = {0};
	char szTemp2[d_LINE_SIZE+1] = {0};
	char szTemp3[d_LINE_SIZE+1] = {0};
	char szTemp4[d_LINE_SIZE+1] = {0};
	char szTemp5[d_LINE_SIZE+1] = {0};
	char szTrigger[d_LINE_SIZE+1] = {0};
	char *szPtr = NULL;
	char *szPtr2 = NULL;
	BYTE ucBuffer[40+1]={0};
	CTOS_RTC SetRTC;
	CTOS_RTC SetRTC_DL;
	CTMS_UpdateInfo st;
    CTMS_GPRSInfo stgprs;     
    CTMS_EthernetInfo stEth;
	CTMS_WIFIInfo stWF;
	STRUCT_TIME_INFO strTimeStart;
	STRUCT_TIME_INFO strTimeStop;
	STRUCT_TIME_INFO strDiff;

	CTMS_UpdateInfo updateInfo;
	int inMissedADC = 0;
	BYTE incount=0;
	CTMS_ItemInfo ctmsinfo;
	BYTE inDownloadCount=0;

	BYTE szUpdateType[6];

	CTMS_ItemInfo UPdateInfoctmsinfo;

	inMissedADC = get_env_int("MISSEDADC");

	vdDebug_LogPrintf("*** ushCTOS_PrintADCReportBody test 1***");
	
	vdCTOS_PrinterFline(1);
	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	vdPrintCenter("CTMS REPORT");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	vdCTOS_PrinterFline(1);

	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));
	memset(szTemp3,0x00,sizeof(szTemp3));
	memset(szTemp4,0x00,sizeof(szTemp4));

//print date and time
	if(fRePrintFlag == FALSE)
	{
		CTOS_RTCGet(&SetRTC);
		vdGetADCDateTime(DATE, &SetRTC,szTemp1);
		vdGetADCDateTime(TIME, &SetRTC,szTemp2);
		strcpy(strTMSDetail.szADCDate,szTemp1);
		strcpy(strTMSDetail.szADCTime,szTemp2);
	}

	vdCTOS_PrinterFline(1);
	
	sprintf(szTemp3,"DATE: %s",strTMSDetail.szADCDate);
	sprintf(szTemp4,"TIME: %s",strTMSDetail.szADCTime);
	
	inPrintLeftRight(szTemp3,szTemp4,42);
	
//print tid and mid
	inMMTReadRecord(1,1); //get BDO TID and MID
	printTIDMID(TRUE); 

	vdCTOS_PrinterFline(1);
//print serial number
	memset(szTemp1,0x00,sizeof(szTemp1));
	CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szTemp1);

	if (strlen(szTemp1) <= 0)
	{
		vdCTOS_GetFactorySN(szTemp1);

		/*Remove non numeric value*/
		for (i=0; i<strlen(szTemp1); i++)
		{
			if (szTemp1[i] < 0x30 || szTemp1[i] > 0x39)
			{
				szTemp1[i] = 0;
				break;
			}
		}
	}

	inPrintLeftRight("SERIAL NO:",szTemp1,42);
//print Download Trigger ===================================================
	memset(szTrigger,0x00,sizeof(szTrigger));
	//if(fRePrintFlag == FALSE)//load inDLTrigger value since terminal did not restart and no strTMSDetail structure has no value.
	//	strTMSDetail.inDLTrigger = inDLTrigger;

	vdDebug_LogPrintf("test trigger tyope %d", strTMSDetail.inDLTrigger);


	if (inMissedADC == 1)
		strTMSDetail.inDLTrigger = AUTO_DOWNLOAD;

	vdDebug_LogPrintf("test 2 trigger type %d", strTMSDetail.inDLTrigger);

	//vdDebug_LogPrintf("FRESH DOWNLOAD %d", fFreshDownload);

    
	//if(fFreshDownload == TRUE){	
		//sprintf(szTrigger,"FRESH DOWNLOAD");
		//fFreshDownload = FALSE;
	//}else{
	
	if(strTMSDetail.inDLTrigger == AUTO_DOWNLOAD /*|| inCheckifAutoDL() == TRUE*/)
		sprintf(szTrigger,"AUTOMATIC");
	else if(strTMSDetail.inDLTrigger == MANUAL_DOWNLOAD)
		sprintf(szTrigger,"MANUAL");
	else
		sprintf(szTrigger,"FRESH DOWNLOAD");
	//}
	
	inPrintLeftRight("TRIGGER:",szTrigger,42);
	
	memset(szStr,0x00,sizeof(szStr));
	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));
	memset(szTemp3,0x00,sizeof(szTemp3));
	memset(szTemp4,0x00,sizeof(szTemp4));
	memset(szTemp5,0x00,sizeof(szTemp5));

		
//print download status
	
	if(fRePrintFlag == FALSE)
	{
	    if (inMissedADC == 1){
			strTMSDetail.inDLStatus = d_CTMS_UPDATE_ERR;

		}else{usResult = CTOS_CTMSGetStatus(&usStatus, &usReterr);

			strTMSDetail.inDLStatus = usResult;
			strTMSDetail.usReterr = usReterr;

			//testlang
			//memset(szTemp1, 0x00, sizeof(szTemp1));
			//sprintf(szTemp1,"%d", usReterr);
			//inPrintLeftRight("usReterr : ",szTemp1,42);
			//testlang

			vdDebug_LogPrintf("CTOS_CTMSGetStatus usResult[%d] usStatus[%d] usReterr[%d]", usResult, usStatus, usReterr);
		
			if(strTMSDetail.inDLStatus == d_CTMS_UPDATE_FINISHED )
				vdAssesTMSDownloadStatus(&SetRTC);//testlang
		}

		vdDebug_LogPrintf("strTMSDetail.inDLStatus[%d]", strTMSDetail.inDLStatus);
	}

	memset(szTemp1,0x00,sizeof(szTemp1));
	if(strTMSDetail.inDLStatus == d_CTMS_UPDATE_UNFINISHED)
		strcpy(szTemp1,"UNFINISHED");
	else if(strTMSDetail.inDLStatus == d_CTMS_UPDATE_FINISHED )
		strcpy(szTemp1,"SUCCESFUL");
	else if(strTMSDetail.inDLStatus == d_CTMS_UPDATE_ERR )
		strcpy(szTemp1,"FAILED");
	else 
		strcpy(szTemp1,"NO DATA FOUND");
	
	inPrintLeftRight("STATUS:",szTemp1,42);

//error reason on failed status
	if(strTMSDetail.inDLStatus != d_CTMS_UPDATE_FINISHED)
	{
		szPtr = NULL;
		memset(szTemp1,0x00,sizeof(szTemp1));
		szPtr = chGetErrorText(strTMSDetail.usReterr);
		vdDebug_LogPrintf("adc error code %d", strTMSDetail.usReterr);

		//strcpy(szTemp1,szPtr);	
		strcpy(strTMSDetail.szReson,szPtr);
		inPrintLeftRight("REASON:",strTMSDetail.szReson,42);

		//test 
		//memset(szTemp1, 0x00, sizeof(szTemp1));
		//sprintf(szTemp1,"%d", strTMSDetail.usReterr);
		//inPrintLeftRight("REASON 2:",szTemp1,42);
	}

	put_env_int("POWERFAILTMS", 0); //clear flag for powerfailed TMS

	//vdCTOS_PrinterFline(1);	

	
	
	if(strTMSDetail.inDLStatus == d_CTMS_UPDATE_FINISHED)//TEST ONLY
	{
		if(fRePrintFlag == FALSE)
		{
			usResult = CTOS_CTMSGetInfo(d_CTMS_INFO_LAST_UPDATE_TIME, &SetRTC_DL);
			vdDebug_LogPrintf("CTOS_CTMSGetInfo usResult=[%x]",usResult);

			
			
			memset(szTemp1,0x00,sizeof(szTemp1));
			
			if(d_OK == usResult)
			{
				vdGetADCDateTime(TIME,&SetRTC_DL,szTemp1);
				//strcpy(strTMSDetail.szDLStartTime,"08:09:10");//TESTONLY
				strcpy(strTMSDetail.szDLStartTime,szTemp1);
				vdDebug_LogPrintf("testonly print adl start time %s", strTMSDetail.szDLStartTime);
			}

			memset(&strTimeStart,0x00,sizeof(STRUCT_TIME_INFO));
			strTimeStart.hours = SetRTC_DL.bHour;
			strTimeStart.minutes= SetRTC_DL.bMinute;
			strTimeStart.seconds = SetRTC_DL.bSecond;

			memset(szTemp2,0x00,sizeof(szTemp2));
			
			vdGetADCDateTime(DL_TIME_END,&SetRTC,szTemp2);//30 seconds before receipt time.
			strcpy(strTMSDetail.szDLEndTime,szTemp2);
			
			memcpy(szTemp5,szTemp2,2);		
			strTimeStop.hours = atol(szTemp5);
			
			memcpy(szTemp3,&szTemp2[3],2);
			strTimeStop.minutes = atol(szTemp3);

			memcpy(szTemp4,&szTemp2[6],2);
			strTimeStop.seconds = atol(szTemp4);

			differenceBetweenTimePeriod(&strTimeStop,&strTimeStart,&strDiff);
			vdDebug_LogPrintf("DIFF :: HRS %d :: MINS %d :: SECS %d",strDiff.hours,strDiff.minutes,strDiff.seconds);
#if 1
			inDLTypeTimeBasis = get_env_int("DLTYPETIMEBASIS");

			
			usResult = CTOS_CTMSGetInfo( d_CTMS_INFO_LAST_UPDATE_COUNT, &incount);
			vdDebug_LogPrintf("UPDATE COUNT %d", incount);
			//memset(szTemp1, 0x00, sizeof(szTemp1));
			//sprintf(szTemp1,"%d", incount);
		    //inPrintLeftRight("update count :",szTemp1,42);


			//memset(szTemp1, 0x00, sizeof(szTemp1));
			//sprintf(szTemp1,"%s", UPdateInfoctmsinfo.baTypeName);
			//inPrintLeftRight("baTypeName : ",szTemp1,42);

			usResult = CTOS_CTMSGetInfo( d_CTMS_INFO_LAST_UPDATE_ITEM, &UPdateInfoctmsinfo);

			memset(szUpdateType, 0x00, sizeof(szUpdateType));
			strncpy(szUpdateType, UPdateInfoctmsinfo.baTypeName, 5);

			vdDebug_LogPrintf("last update name %s", UPdateInfoctmsinfo.baTypeName);

			//testglad
			//memset(szTemp1, 0x00, sizeof(szTemp1));
			//sprintf(szTemp1,"%s", UPdateInfoctmsinfo.baTypeName);
			//inPrintLeftRight("baTypeName : ",szTemp1,42);
			//testglad
	    
            inDownloadCount = 0;
			usResult = CTOS_CTMSGetInfo( d_CTMS_INFO_LAST_DOWNLOAD_COUNT, &inDownloadCount);
			vdDebug_LogPrintf("CTOS_CTMSGetInfo 2 usResult=[%x] count = %d",usResult,inDownloadCount);

//testglad
#else	  

			inDLTypeTimeBasis = get_env_int("DLTYPETIMEBASIS");

	
            inDownloadCount = 0;
			usResult = CTOS_CTMSGetInfo( d_CTMS_INFO_LAST_DOWNLOAD_COUNT, &inDownloadCount);
			vdDebug_LogPrintf("CTOS_CTMSGetInfo 2 usResult=[%x] count = %d",usResult,inDownloadCount);


			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%d", inDownloadCount);
		    inPrintLeftRight("download count :",szTemp1,42);


			//usResult = CTOS_CTMSGetInfo(  d_CTMS_INFO_LAST_UPDATE_ITEM, &ctmsinfo);
			
			usResult = CTOS_CTMSGetInfo( d_CTMS_INFO_LAST_DOWNLOAD_ITME, &ctmsinfo);
			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%s", ctmsinfo.baTypeName);
			inPrintLeftRight("baTypeName : ",szTemp1,42);

			
			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%s", ctmsinfo.baName);
			inPrintLeftRight("baName : ",szTemp1,42);


			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%s", ctmsinfo.bNumber);
			inPrintLeftRight("bNumber : ",szTemp1,42);


			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%s", ctmsinfo.baVersion);
			inPrintLeftRight("baVersion : ",szTemp1,42);




			usResult = CTOS_CTMSGetInfo( d_CTMS_INFO_LAST_UPDATE_COUNT, &incount);
			vdDebug_LogPrintf("UPDATE COUNT %d", incount);
			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%d", incount);
		    inPrintLeftRight("UPDATE Count:",szTemp1,42);





			usResult = CTOS_CTMSGetInfo( d_CTMS_INFO_LAST_UPDATE_ITEM, &UPdateInfoctmsinfo);
			vdDebug_LogPrintf("CTOS_CTMSGetInfo 3 usResult=[%x] ",usResult);


			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%s", UPdateInfoctmsinfo.baTypeName);
			inPrintLeftRight("baTypeName : ",szTemp1,42);

			memset(szUpdateType, 0x00, sizeof(szUpdateType));
			strncpy(szUpdateType, UPdateInfoctmsinfo.baTypeName, 5);

			
			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%s", UPdateInfoctmsinfo.baName);
			inPrintLeftRight("baName : ",szTemp1,42);


			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%s", UPdateInfoctmsinfo.bNumber);
			inPrintLeftRight("bNumber : ",szTemp1,42);


			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%s", UPdateInfoctmsinfo.baVersion);
			inPrintLeftRight("baVersion : ",szTemp1,42);

            //testonly
#endif
#if 0
            {
            BYTE incount=0;
			CTMS_ItemInfo ctmsinfo;
			usResult = CTOS_CTMSGetInfo( d_CTMS_INFO_LAST_DOWNLOAD_COUNT, &incount);
			vdDebug_LogPrintf("CTOS_CTMSGetInfo 2 usResult=[%x] count = %d",usResult,incount);


			usResult = CTOS_CTMSGetInfo( d_CTMS_INFO_LAST_DOWNLOAD_ITME, &ctmsinfo);
			vdDebug_LogPrintf("CTOS_CTMSGetInfo 3 usResult=[%x] ",usResult);
			
			vdDebug_LogPrintf("CTOS_CTMSGetInfo 3 count =[%d] ",incount);
			vdDebug_LogPrintf("CTOS_CTMSGetInfo 3 baName =[%s] ",ctmsinfo.baName);
			vdDebug_LogPrintf("CTOS_CTMSGetInfo 3 baVersion = [%s] ",ctmsinfo.baVersion);
			vdDebug_LogPrintf("CTOS_CTMSGetInfo 3 baTypeName = [%s] ",ctmsinfo.baTypeName);
			vdDebug_LogPrintf("CTOS_CTMSGetInfo 3 baName =[%d] ",ctmsinfo.usUpdateResult);

			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%d", incount);
			inPrintLeftRight("LDCOUNT :",szTemp1,42);

			
			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%s", ctmsinfo.baTypeName);
			inPrintLeftRight("LDTYPE : ",szTemp1,42);
			usResult = CTOS_CTMSGetInfo( d_CTMS_INFO_LAST_UPDATE_COUNT, &incount);
			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%d", incount);
			inPrintLeftRight("LUCOUNT :",szTemp1,42);

			usResult = CTOS_CTMSGetInfo(  d_CTMS_INFO_LAST_UPDATE_ITEM, &ctmsinfo);
			memset(szTemp1, 0x00, sizeof(szTemp1));
			sprintf(szTemp1,"%s", ctmsinfo.baTypeName);
			inPrintLeftRight("LUTYPE : ",szTemp1,42);
           }
#endif
			//testonly
 
			if(inDLTypeTimeBasis <= 0)
				inDLTypeTimeBasis = 4;

            //testonly
            #if 0
			//testlang

            memset(strTMSDetail.szUpdateType, 0x00, sizeof(strTMSDetail.szUpdateType));
			if (incount <= 0){
				strcpy(strTMSDetail.szUpdateType,"NO UPDATE");
			}else{	
				//if(strcmp(szTrigger,"FRESH DOWNLOAD") != 0 && strlen(strTMSDetail.szUpdateType) <= 0)//last condition added as to not overwrite szUpdate type if set by vdAssesTMSDownloadStatus()
				if(strcmp(szTrigger,"FRESH DOWNLOAD") != 0)
				{
			    	vdDebug_LogPrintf("TESTING strDiff.minutes = %d", strDiff.minutes);
					vdDebug_LogPrintf("TESTING inDLTypeTimeBasis = %d", inDLTypeTimeBasis);
					if(strDiff.minutes > inDLTypeTimeBasis)
						strcpy(strTMSDetail.szUpdateType,"APPLICATION");
					else
						strcpy(strTMSDetail.szUpdateType,"PARAMETER ");
				}
			}
			#else
			 memset(strTMSDetail.szUpdateType, 0x00, sizeof(strTMSDetail.szUpdateType));
			 if(strcmp(szTrigger,"FRESH DOWNLOAD") != 0){
				if (incount > 0){

                    if ((incount == 1) && (strcmp(szUpdateType,"Param")==0)){
						strcpy(strTMSDetail.szUpdateType,"PARAMETER");
                    }else	
                        strcpy(strTMSDetail.szUpdateType,"APPLICATION");
				}else{

					if (strTCT.fFirstInit == 1 && incount == 0)
						strcpy(strTMSDetail.szUpdateType,"PARAMETER");
					else
						strcpy(strTMSDetail.szUpdateType,"NO UPDATE");

				}


			 }
			#endif

			
			//testonly
			//usResult = CTOS_CTMSGetUpdateType(&updateInfo);
			
			 //vdDebug_LogPrintf("CTOS_CTMSGetUpdateType 1 usResult=[%x]",usResult);
			 //vdDebug_LogPrintf("CTOS_CTMSGetUpdateType 2 BTYPE=[%x] %c",&updateInfo.bType, &updateInfo.bType);

			 
			 //vdDebug_LogPrintf("CTOS_CTMSGetUpdateType 3 btype=[%x] %c",updateInfo.bType, updateInfo.bType);
			 
			 //vdDebug_LogPrintf("CTOS_CTMSGetUpdateType 4 bnum=[%d] %d",&updateInfo.bNums, updateInfo.bNums);
			 //testonly
			
		}



		vdDebug_LogPrintf("strTMSDetail.szUpdateType len %d :: szTrigger[%s]",strlen(strTMSDetail.szUpdateType),szTrigger);
		if(strcmp(szTrigger,"FRESH DOWNLOAD") != 0)
			inPrintLeftRight("UPDATE:",strTMSDetail.szUpdateType,42);

		
		
		inPrintLeftRight("START TIME DL:",strTMSDetail.szDLStartTime,42);
		inPrintLeftRight("END TIME DL:",strTMSDetail.szDLEndTime,42);
		
		vdCTOS_PrinterFline(1);

//print old and updated version  ===================================================
		vdDebug_LogPrintf("OLD APP VERSION [%s] len [%d]",strTMSDetail.szAppVer,strlen(strTMSDetail.szAppVer));
		//if(strcmp(strTMSDetail.szUpdateType,"NO UPDATE") != 0){
		if(strcmp(strTMSDetail.szUpdateType,"APPLICATION") == 0){
			if(strlen(strTMSDetail.szAppVer) > 0)
				inPrintLeftRight("PREVIOUS APP VERSION:",strTMSDetail.szAppVer,42);
		}

		memset(szTemp1,0x00,sizeof(szTemp1));
		inPrintLeftRight("APPLICATION VERSION:",strTCT.szAppVersionHeader,42);
		
	}

	
//print terminal IP
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	vdCTOS_PrinterFline(1);
	memset(szStr, 0x00, d_LINE_SIZE);
	
	if (strCPT.inCommunicationMode == GPRS_MODE)
		inCTOSS_SIMGetGPRSIPInfo();
	else if (strCPT.inCommunicationMode == WIFI_MODE)
		inWIFI_GetConnectConfig();
	else
	{
		if(strTCP.fDHCPEnable == 1)
			vdPrint_EthernetStatus();
		else
			strcpy(szIP,(char *)strTCP.szTerminalIP);			
	}

	inPrintLeftRight("TERMINAL IP:",szIP,42);
	
//print CTMS IP and Port
	//inPrintLeftRight("CTMS SERVER IP:",strTCT.szTMSRemoteIP,42);
	
	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));

	//sprintf(szTemp1,"%d",strTCT.usTMSRemotePort);
	
	if(strCPT.inCommunicationMode == ETHERNET_MODE)
	{
		memset(&stEth,0x00,sizeof(CTMS_EthernetInfo));
		CTOS_CTMSGetConfig(d_CTMS_ETHERNET_CONFIG, &stEth);
		strcpy(szTemp1,stEth.strRemoteIP);
		sprintf(szTemp2,"%d",stEth.usRemotePort);
	}
	else if(strCPT.inCommunicationMode == GPRS_MODE)
	{
		memset(&stgprs,0x00,sizeof(CTMS_GPRSInfo));
		CTOS_CTMSGetConfig(d_CTMS_GPRS_CONFIG, &stgprs);	
		strcpy(szTemp1,stgprs.strRemoteIP);
		sprintf(szTemp2,"%d",stgprs.usRemotePort);
	}
	else if(strCPT.inCommunicationMode == WIFI_MODE)
	{
		memset(&stWF,0x00,sizeof(CTMS_WIFIInfo));
		CTOS_CTMSGetConfig(d_CTMS_WIFI_CONFIG, &stWF);	
		strcpy(szTemp1,stWF.strRemoteIP);
		sprintf(szTemp2,"%d",stWF.usRemotePort);
	}
	else 
	{
		inTCTRead(1);
		strcpy(szTemp1,strTCT.szTMSRemoteIP);
		sprintf(szTemp2,"%d",strTCT.usTMSRemotePort);
	}
	
	inPrintLeftRight("CTMS SERVER IP:",szTemp1,42);
	inPrintLeftRight("CTMS SERVER PORT:",szTemp2,42);
	
//print ADC TIME RANGE 1
	memset(szStr,0x00,sizeof(szStr));
	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));
	memset(szTemp3,0x00,sizeof(szTemp3));
	memset(szTemp4,0x00,sizeof(szTemp4));


	vdDebug_LogPrintf("szADCStartTime1 %s",strTMSDetail.szADCStartTime1);
	if(strlen(strTMSDetail.szADCStartTime1) <= 0)
	{
	    vdDebug_LogPrintf("test copy adc start time 1");
		inCTOSS_GetEnvDB ("ADL1START", szTemp1);
		memset(strTMSDetail.szADCStartTime1, 0x00, sizeof(strTMSDetail.szADCStartTime1));
		strcpy(strTMSDetail.szADCStartTime1, szTemp1);
		vdFormatADLTime(szTemp1,szTemp2);
	}
	else
		vdFormatADLTime(strTMSDetail.szADCStartTime1,szTemp2);

	vdDebug_LogPrintf("szADCEndTime1 %s",strTMSDetail.szADCEndTime1);
	if(strlen(strTMSDetail.szADCEndTime1) <= 0)
	{
		inCTOSS_GetEnvDB ("ADL1END", szTemp3);
		
		memset(strTMSDetail.szADCEndTime1, 0x00, sizeof(strTMSDetail.szADCEndTime1));
		strcpy(strTMSDetail.szADCEndTime1, szTemp3);

		vdFormatADLTime(szTemp3,szTemp4);
	}
	else
		vdFormatADLTime(strTMSDetail.szADCEndTime1,szTemp4);

	sprintf(szStr,"%s - %s",szTemp2,szTemp4);
	inPrintLeftRight("ADC TIME 1:",szStr,42);


//print ADC TIME RANGE 2
	memset(szStr,0x00,sizeof(szStr));
	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));
	memset(szTemp3,0x00,sizeof(szTemp3));
	memset(szTemp4,0x00,sizeof(szTemp4));

	vdDebug_LogPrintf("szADCStartTime2 %s",strTMSDetail.szADCStartTime2);
	if(strlen(strTMSDetail.szADCStartTime2) <= 0)
	{
		inCTOSS_GetEnvDB ("ADL2START", szTemp1);
		
		memset(strTMSDetail.szADCStartTime2, 0x00, sizeof(strTMSDetail.szADCStartTime2));
		strcpy(strTMSDetail.szADCStartTime2, szTemp1);
		vdFormatADLTime(szTemp1,szTemp2);
	}
	else
		vdFormatADLTime(strTMSDetail.szADCStartTime2,szTemp2);

	vdDebug_LogPrintf("szADCEndTime2 %s",strTMSDetail.szADCEndTime2);
	if(strlen(strTMSDetail.szADCEndTime2) <= 0)
	{
		inCTOSS_GetEnvDB ("ADL2END", szTemp3);
		
		memset(strTMSDetail.szADCEndTime2, 0x00, sizeof(strTMSDetail.szADCEndTime2));
		strcpy(strTMSDetail.szADCEndTime2, szTemp3);
		vdFormatADLTime(szTemp3,szTemp4);
	}
	else
		vdFormatADLTime(strTMSDetail.szADCEndTime2,szTemp4);
	
	sprintf(szStr,"%s - %s",szTemp2,szTemp4);
	inPrintLeftRight("ADC TIME 2:",szStr,42);


//print ADC TIME RANGE 3
	memset(szStr,0x00,sizeof(szStr));
	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));
	memset(szTemp3,0x00,sizeof(szTemp3));
	memset(szTemp4,0x00,sizeof(szTemp4));

	vdDebug_LogPrintf("szADCStartTime3 %s",strTMSDetail.szADCStartTime3);
	if(strlen(strTMSDetail.szADCStartTime3) <= 0)
	{
		inCTOSS_GetEnvDB ("ADL3START", szTemp1);
		
		memset(strTMSDetail.szADCStartTime3, 0x00, sizeof(strTMSDetail.szADCStartTime3));
		strcpy(strTMSDetail.szADCStartTime3, szTemp1);
		vdFormatADLTime(szTemp1,szTemp2);
	}
	else
		vdFormatADLTime(strTMSDetail.szADCStartTime3,szTemp2);

	vdDebug_LogPrintf("szADCEndTime3 %s",strTMSDetail.szADCEndTime3);
	if(strlen(strTMSDetail.szADCEndTime3) <= 0)
	{
		inCTOSS_GetEnvDB ("ADL3END", szTemp3);
		
		memset(strTMSDetail.szADCEndTime3, 0x00, sizeof(strTMSDetail.szADCEndTime3));
		strcpy(strTMSDetail.szADCEndTime3, szTemp3);
		vdFormatADLTime(szTemp3,szTemp4);
	}
	else
		vdFormatADLTime(strTMSDetail.szADCEndTime3,szTemp4);

	sprintf(szStr,"%s - %s",szTemp2,szTemp4);
	inPrintLeftRight("ADC TIME 3:",szStr,42);

//print days gap ===================================================
	memset(szTemp1,0x00,sizeof(szTemp1));
	if(strlen(strTMSDetail.szDayGap) <= 0){		
		sprintf(szTemp1,"%d",strTCT.usTMSGap);
		memset(strTMSDetail.szDayGap, 0x00, sizeof(strTMSDetail.szDayGap));
		sprintf(strTMSDetail.szDayGap,"%d", strTCT.usTMSGap);
		
	}else
		sprintf(szTemp1,"%s",strTMSDetail.szDayGap);
	
	inPrintLeftRight("DAYS GAP:",szTemp1,42);
#if 0
	usResult = CTOS_CTMSInitDaemonProcess(d_CTMS_DEFAULT_ETHERNET);
    vdDebug_LogPrintf("CTOS_CTMSInitDaemonProcess ret[%d]", usResult);
#endif

	vdLineFeed(srTransRec.fFooterLogo);
	
}

USHORT ushCTOS_PrintADCReportBatchNotEmpty(int inType)
{
	USHORT usResult;
    USHORT usStatus, usReterr;
	int i = 0;
	char szStr[d_LINE_SIZE + 1];
	char szTemp1[d_LINE_SIZE+1] = {0};
	char szTemp2[d_LINE_SIZE+1] = {0};
	char szTemp3[d_LINE_SIZE+1] = {0};
	char szTemp4[d_LINE_SIZE+1] = {0};
	char szTemp5[d_LINE_SIZE+1] = {0};
	char *szPtr = NULL;
	char *szPtr2 = NULL;
	CTOS_RTC SetRTC;
	CTOS_RTC SetRTC_DL;
	CTMS_UpdateInfo st;
    CTMS_GPRSInfo stgprs;     
    CTMS_EthernetInfo stEth;
	CTMS_WIFIInfo stWF;
	STRUCT_TIME_INFO strTimeStart;
	STRUCT_TIME_INFO strTimeStop;
	STRUCT_TIME_INFO strDiff;

	vdDebug_LogPrintf("*** ushCTOS_PrintADCReportBatchNotEmpty ***");
	
	vdCTOS_PrinterFline(1);
	vdSetGolbFontAttrib(d_FONT_16x16, DOUBLE_SIZE, DOUBLE_SIZE, 0, 0);
	vdPrintCenter("CTMS REPORT");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);

	vdCTOS_PrinterFline(1);

	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));
	memset(szTemp3,0x00,sizeof(szTemp3));
	memset(szTemp4,0x00,sizeof(szTemp4));

//print date and time
    //for sending in ERM - previous version is the same with current version
	strcpy(strTMSDetail.szAppVer,strTCT.szAppVersionHeader);

	

	if(fRePrintFlag == FALSE)
	{
		CTOS_RTCGet(&SetRTC);
		vdGetADCDateTime(DATE, &SetRTC,szTemp1);
		vdGetADCDateTime(TIME, &SetRTC,szTemp2);
		strcpy(strTMSDetail.szADCDate,szTemp1);
		strcpy(strTMSDetail.szADCTime,szTemp2);		
	}
	else
	
	vdCTOS_PrinterFline(1);
	
	sprintf(szTemp3,"DATE: %s",strTMSDetail.szADCDate);
	sprintf(szTemp4,"TIME: %s",strTMSDetail.szADCTime);
	
	inPrintLeftRight(szTemp3,szTemp4,42);
	
//print tid and mid
	inMMTReadRecord(1,1); //get BDO TID and MID
	printTIDMID(TRUE); 

	vdCTOS_PrinterFline(1);
//print serial number
	memset(szTemp1,0x00,sizeof(szTemp1));
	CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szTemp1);

	if (strlen(szTemp1) <= 0)
	{
		vdCTOS_GetFactorySN(szTemp1);

		/*Remove non numeric value*/
		for (i=0; i<strlen(szTemp1); i++)
		{
			if (szTemp1[i] < 0x30 || szTemp1[i] > 0x39)
			{
				szTemp1[i] = 0;
				break;
			}
		}
	}
	
	inPrintLeftRight("SERIAL NO:",szTemp1,42);
//print Download Trigger ===================================================
	memset(szTemp1,0x00,sizeof(szTemp1));

	//if(inDLTrigger == AUTO_DOWNLOAD)
	if(fRePrintFlag == FALSE)//load inDLTrigger value since terminal did not restart and no strTMSDetail structure has no value.
		strTMSDetail.inDLTrigger = inDLTrigger;
	
	if(strTMSDetail.inDLTrigger == AUTO_DOWNLOAD)
		sprintf(szTemp1,"AUTOMATIC");
	else if(strTMSDetail.inDLTrigger == MANUAL_DOWNLOAD)
		sprintf(szTemp1,"MANUAL");
	else
		sprintf(szTemp1,"FRESH DL");
	
	inPrintLeftRight("TRIGGER:",szTemp1,42);
	
	memset(szStr,0x00,sizeof(szStr));
	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));
	memset(szTemp3,0x00,sizeof(szTemp3));
	memset(szTemp4,0x00,sizeof(szTemp4));
	memset(szTemp5,0x00,sizeof(szTemp5));

		
//print download status
	inPrintLeftRight("STATUS:","FAILED",42);

	if(fRePrintFlag == FALSE)
		strTMSDetail.inDLStatus = 3;
	
//error reason on failed status

    if (inType == 2){//connect failed

	        if(ETHERNET_MODE == strTCT.inTMSComMode){
				inPrintLeftRight("REASON:","CONNECTION TERMINATED",42);
				strcpy(strTMSDetail.szReson,"CONNECTION TERMINATED");
	        }else{
				inPrintLeftRight("REASON:","GPRS NO SIGNAL",42);
				strcpy(strTMSDetail.szReson,"GPRS NO SIGNAL");
	        }
	}else if (inType == 3){	
				inPrintLeftRight("REASON:","INVALID SERIAL NUMBER",42);
				strcpy(strTMSDetail.szReson,"INVALID SERIAL NUMBER");
    }else{
    	if (inCheckPendingReversal_for_CTMS() == 1){
			inPrintLeftRight("REASON:","PENDING REVERSAL",42);
			strcpy(strTMSDetail.szReson,"PENDING REVRSL");
		}else{
			inPrintLeftRight("REASON:","PENDING BATCH",42);
			strcpy(strTMSDetail.szReson,"PENDING BATCH");
		}
    }

//print terminal IP
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 1, 0);
	vdCTOS_PrinterFline(1);
	memset(szStr, 0x00, d_LINE_SIZE);
	
	if (strCPT.inCommunicationMode == GPRS_MODE)
		inCTOSS_SIMGetGPRSIPInfo();
	else if (strCPT.inCommunicationMode == WIFI_MODE)
		inWIFI_GetConnectConfig();
	else
	{
		if(strTCP.fDHCPEnable == 1)
			vdPrint_EthernetStatus();
		else
			strcpy(szIP,(char *)strTCP.szTerminalIP);			
	}

	inPrintLeftRight("TERMINAL IP:",szIP,42);
	
//print CTMS IP and Port
	//inPrintLeftRight("CTMS SERVER IP:",strTCT.szTMSRemoteIP,42);
	
	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));

	//sprintf(szTemp1,"%d",strTCT.usTMSRemotePort);
	
	if(strCPT.inCommunicationMode == ETHERNET_MODE)
	{
		vdDebug_LogPrintf("");
		memset(&stEth,0x00,sizeof(CTMS_EthernetInfo));
		CTOS_CTMSGetConfig(d_CTMS_ETHERNET_CONFIG, &stEth);
		strcpy(szTemp1,stEth.strRemoteIP);
		sprintf(szTemp2,"%d",stEth.usRemotePort);
	}
	else if(strCPT.inCommunicationMode == GPRS_MODE)
	{
		memset(&stgprs,0x00,sizeof(CTMS_GPRSInfo));
		CTOS_CTMSGetConfig(d_CTMS_GPRS_CONFIG, &stgprs);	
		strcpy(szTemp1,stgprs.strRemoteIP);
		sprintf(szTemp2,"%d",stgprs.usRemotePort);
	}
	else if(strCPT.inCommunicationMode == WIFI_MODE)
	{
		memset(&stWF,0x00,sizeof(CTMS_WIFIInfo));
		CTOS_CTMSGetConfig(d_CTMS_WIFI_CONFIG, &stWF);	
		strcpy(szTemp1,stWF.strRemoteIP);
		sprintf(szTemp2,"%d",stWF.usRemotePort);
	}
	
	inPrintLeftRight("CTMS SERVER IP:",szTemp1,42);
	inPrintLeftRight("CTMS SERVER PORT:",szTemp2,42);
	
	//print ADC TIME RANGE 1
	memset(szStr,0x00,sizeof(szStr));
	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));
	memset(szTemp3,0x00,sizeof(szTemp3));
	memset(szTemp4,0x00,sizeof(szTemp4));

	vdDebug_LogPrintf("szADCStartTime1 %s",strTMSDetail.szADCStartTime1);
	if(strlen(strTMSDetail.szADCStartTime1) <= 0)
	{
		inCTOSS_GetEnvDB ("ADL1START", szTemp1);
		vdFormatADLTime(szTemp1,szTemp2);
	}
	else
		vdFormatADLTime(strTMSDetail.szADCStartTime1,szTemp2);

	vdDebug_LogPrintf("szADCEndTime1 %s",strTMSDetail.szADCEndTime1);
	if(strlen(strTMSDetail.szADCEndTime1) <= 0)
	{
		inCTOSS_GetEnvDB ("ADL1END", szTemp3);

		vdFormatADLTime(szTemp3,szTemp4);
	}
	else
		vdFormatADLTime(strTMSDetail.szADCEndTime1,szTemp4);

	sprintf(szStr,"%s - %s",szTemp2,szTemp4);
	inPrintLeftRight("ADC TIME 1:",szStr,42);


//print ADC TIME RANGE 2
	memset(szStr,0x00,sizeof(szStr));
	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));
	memset(szTemp3,0x00,sizeof(szTemp3));
	memset(szTemp4,0x00,sizeof(szTemp4));

	vdDebug_LogPrintf("szADCStartTime2 %s",strTMSDetail.szADCStartTime2);
	if(strlen(strTMSDetail.szADCStartTime2) <= 0)
	{
		inCTOSS_GetEnvDB ("ADL2START", szTemp1);
		vdFormatADLTime(szTemp1,szTemp2);
	}
	else
		vdFormatADLTime(strTMSDetail.szADCStartTime2,szTemp2);

	vdDebug_LogPrintf("szADCEndTime2 %s",strTMSDetail.szADCEndTime2);
	if(strlen(strTMSDetail.szADCEndTime2) <= 0)
	{
		inCTOSS_GetEnvDB ("ADL2END", szTemp3);
		vdFormatADLTime(szTemp3,szTemp4);
	}
	else
		vdFormatADLTime(strTMSDetail.szADCEndTime2,szTemp4);
	
	sprintf(szStr,"%s - %s",szTemp2,szTemp4);
	inPrintLeftRight("ADC TIME 2:",szStr,42);


//print ADC TIME RANGE 3
	memset(szStr,0x00,sizeof(szStr));
	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));
	memset(szTemp3,0x00,sizeof(szTemp3));
	memset(szTemp4,0x00,sizeof(szTemp4));

	vdDebug_LogPrintf("szADCStartTime3 %s",strTMSDetail.szADCStartTime3);
	if(strlen(strTMSDetail.szADCStartTime3) <= 0)
	{
		inCTOSS_GetEnvDB ("ADL3START", szTemp1);
		vdFormatADLTime(szTemp1,szTemp2);
	}
	else
		vdFormatADLTime(strTMSDetail.szADCStartTime3,szTemp2);

	vdDebug_LogPrintf("szADCEndTime3 %s",strTMSDetail.szADCEndTime3);
	if(strlen(strTMSDetail.szADCEndTime3) <= 0)
	{
		inCTOSS_GetEnvDB ("ADL3END", szTemp3);
		vdFormatADLTime(szTemp3,szTemp4);
	}
	else
		vdFormatADLTime(strTMSDetail.szADCEndTime3,szTemp4);

	sprintf(szStr,"%s - %s",szTemp2,szTemp4);
	inPrintLeftRight("ADC TIME 3:",szStr,42);


//print days gap ===================================================
	memset(szTemp1,0x00,sizeof(szTemp1));
	sprintf(szTemp1,"%d",strTCT.usTMSGap);
	inPrintLeftRight("DAYS GAP:",szTemp1,42);

	vdLineFeed(srTransRec.fFooterLogo);
	
}

int inPrintADCReport(int inBodyType)
{
	
	int inNumOfLine = 8;
	//BYTE szTIDTemp[8+1] = {0};
	//BYTE szMIDTemp[15+1] = {0};
	BYTE szParaName[20];


	vdDebug_LogPrintf("*** inPrintADCReport tess 1***");
		
	CTOS_LCDTClearDisplay();
		
	if((strTCT.byTerminalType % 2) == 0)
		inNumOfLine = 16;

	CTOS_LCDTPrintXY(1, inNumOfLine, "PRINTING...");

	vdDebug_LogPrintf("*** inPrintADCReport tess 2***");

	if(fRePrintFlag == FALSE)
	{
		if(inFLGGet("fUploadADCReport"))
		{
			fERMTransaction = TRUE;
			strTCT.byERMMode = 4;
			vdDebug_LogPrintf("test set ERM mode to 4");
		}
	}
	else
	{
		strcpy(TempszTID, strTMSDetail.szTID);//Fix for blank TID and MID on reprint.
		strcpy(TempszMID, strTMSDetail.szMID);
		
		srTransRec.HDTid = BDO_HDT_INDEX;//Fix for load MMT ERR message on header function after reprint.
		srTransRec.MITid = 1;// 1st merchant
		
	}
		
	vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(4);
	
	ushCTOS_PrintHeader(TRUE);

	vdDebug_LogPrintf("*** inPrintADCReport test 3print body*** %d - %d ", fRePrintFlag, inFLGGet("fUploadADCReport"));

	
	
	if(inBodyType > 0 || (fRePrintFlag == TRUE && strTMSDetail.inDLStatus == BATCH_NOT_EMPTY))
		ushCTOS_PrintADCReportBatchNotEmpty(inBodyType);
	else	
		ushCTOS_PrintADCReportBody();
	

	if(fRePrintFlag == FALSE && inFLGGet("fUploadADCReport"))
	{

	   vdDebug_LogPrintf("test 1 print adc");
		memcpy(srTransRec.szInvoiceNo, "\x00\x00\x01", 3);
		srTransRec.ulTraceNum = 1;
		memcpy(srTransRec.szTotalAmount,"\x00\x00\x00\x00\x00\x01",6);
		inHDTRead(1);
		memcpy(srTransRec.szInvoiceNo, "\x00\x00\x01", INVOICE_BCD_SIZE);		
		memcpy(srTransRec.szBatchNo, "\x00\x00\x03", BATCH_NO_BCD_SIZE);
		//strcpy(srTransRec.szRRN, "000000001234");

		strcpy(srTransRec.szRRN, "M-SUCCESSFUL");

	    memset(g_szEmail, 0x00, sizeof(g_szEmail));
		strcpy(g_szEmail,"test lang");
		
		strcpy(srTransRec.szAuthCode, "001235");
		strcpy(srTransRec.szPAN, "0000000000001235");
		strcpy(srTransRec.szHostLabel, strHDT.szHostLabel);

#ifdef ADC_ERM
//separate TID and MID assigned to ADC Report on ERM --start--
		memset(TempszTID,0x00,sizeof(TempszTID));
		memset(TempszMID,0x00,sizeof(TempszMID));
		
		strcpy(TempszTID,srTransRec.szTID);
		strcpy(TempszMID,srTransRec.szMID);

		memset(srTransRec.szTID,0x00,sizeof(srTransRec.szTID));
		memset(srTransRec.szMID,0x00,sizeof(srTransRec.szMID));
		memset(strMMT[0].szTID,0x00,sizeof(strMMT[0].szTID));
		memset(strMMT[0].szMID,0x00,sizeof(strMMT[0].szMID));
				
		inCTOSS_GetEnvDB("CTMSERMTID",srTransRec.szTID);
		inCTOSS_GetEnvDB("CTMSERMMID",srTransRec.szMID);
		strcpy(strMMT[0].szTID,srTransRec.szTID);
		strcpy(strMMT[0].szMID,srTransRec.szMID);
		
		vdDebug_LogPrintf("CTMS srTransRec.szTID[%s]",srTransRec.szTID);
		vdDebug_LogPrintf("CTMS srTransRec.szMID[%s]",srTransRec.szMID);
//separate TID and MID assigned to ADC Report on ERM --end--
#endif

	}
		
	vdCTOSS_PrinterEnd();

	if(fRePrintFlag == FALSE)
	{
		if(inFLGGet("fUploadADCReport"))
		{
		    
			vdDebug_LogPrintf("test 2 print adc");
			
			inCTOSS_ERM_CTMSReceiptRecvVia();
			// prev --inCTOSS_ERM_Form_Receipt(0);
			inCTOSS_ERM_Form_Receipt_FOR_ADC(0);

            //deinti ERM if new apps or parameter was downloaded
			if(strTMSDetail.inDLStatus == d_CTMS_UPDATE_FINISHED  || strTCT.byERMInit !=1){
				memset(szParaName, 0x00, sizeof(szParaName));
				strcpy(szParaName,"ERM0101");
				inCTOSS_PutEnvDB(szParaName,"0");
			}
						
			inCTOSS_UploadReceiptEx(FALSE);
			fERMTransaction = FALSE;

			vdDebug_LogPrintf("test set ERM mode to 0");
			strTCT.byERMMode = 0;
			inTCTSave(1);
#ifdef ADC_ERM
//separate TID and MID assigned to ADC Report on ERM --start--
			memset(srTransRec.szTID,0x00,sizeof(srTransRec.szTID));
			memset(srTransRec.szMID,0x00,sizeof(srTransRec.szMID));
			memset(strMMT[0].szTID,0x00,sizeof(strMMT[0].szTID));
			memset(strMMT[0].szMID,0x00,sizeof(strMMT[0].szMID));
			
			strcpy(srTransRec.szTID,TempszTID);
			strcpy(srTransRec.szMID,TempszMID);
			strcpy(strMMT[0].szTID,TempszTID);
			strcpy(strMMT[0].szMID,TempszMID);
//separate TID and MID assigned to ADC Report on ERM --end--
#endif
			
		}
		
		inCTOSS_TMSBackUpReprintDetailData();//Back up data for reprint purposes.

		
        //clear tms file after uploading
		if (inCheckFileExist(TMS_DETAIL_FILE_NAME) == d_OK)
			inRemoveConfRecFile(TMS_DETAIL_FILE_NAME);
	}
	
  vdDebug_LogPrintf("exit adcprint");
	memset(&strTMSDetail,0x00,sizeof(TMS_DETAIL_DATA));
	return d_OK;
}


int inPrintDCCSingPadPacket(char *pucTitle, unsigned char *pucMessage, int inLen)
{
	char ucLineBuffer[44 + 4];
	unsigned char *pucBuff;
	int inBuffPtr = 0;
	BYTE baTemp[384 * 64];
	char szStr[44 + 4];
	

	if (inLen <= 0)
		return(ST_SUCCESS);

	
	CTOS_PrinterSetWorkTime(50000,1000);
	inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_16x16,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, 1, 2, 0, 0);
	
	memset(szStr, 0x00, sizeof(szStr));
	memset(baTemp, 0x00, sizeof(baTemp));
	sprintf(szStr,"[%s] [%d] \n", pucTitle, inLen);
	CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
	CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);

		
	CTOS_PrinterFline(12); 
	
	
	pucBuff = pucMessage + inLen;
	while (pucBuff > pucMessage)
	{
	memset(ucLineBuffer,0x00, sizeof(ucLineBuffer));
	for (inBuffPtr = 0; (inBuffPtr < 44) && (pucBuff > pucMessage); inBuffPtr += 3)
	{
	sprintf(&ucLineBuffer[inBuffPtr], "%02X ", *pucMessage);
	pucMessage++;
	}
	ucLineBuffer[44] = '\n';
	memset (baTemp, 0x00, sizeof(baTemp));		
	CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, ucLineBuffer, &stgFONT_ATTRIB);
	CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	
	} 
	CTOS_PrinterFline(12 * 2); 
	
	
	return (ST_SUCCESS);
}



int inPrintPNG(void)
{
	int inRet = d_NO;
	char szDCCSignFileName[24+1];
	long lFileSize;

	vdDebug_LogPrintf("***inPrintPNG***");


	if(inFLGGet("fSignPad") != TRUE || srTransRec.fSignPadBypassSignature == TRUE || srTransRec.byTransType == SALE_TIP)
		return d_NO;
		
	memset(szDCCSignFileName, 0x00, sizeof(szDCCSignFileName));
	vdGetDCCSignatureFilename(&szDCCSignFileName);
	lFileSize=lnGetFileSize(szDCCSignFileName);
	vdDebug_LogPrintf("szDCCSignFileName:[%s], ulFileSize:[%ld]",szDCCSignFileName, lFileSize);

	if(lFileSize > 0)
    {
    	vdDebug_LogPrintf("szDCCSignFileName found");
        vdCTOS_PrinterFline(1);
        vdCTOSS_PrinterPNGImageEx(60,0,szDCCSignFileName);
		inRet = d_OK;
    }
	else
		inRet = d_NO;	
	
	return inRet;
}


int inCurlPrintPacket(unsigned char *pucTitle,unsigned char *pucMessage, int inLen, BOOL fRequest)
{
    char ucLineBuffer[d_LINE_SIZE+4];
    unsigned char *pucBuff;
    BYTE baTemp[PAPER_X_SIZE * 64];
    char szStr[100 + 1];
	BOOL fLoop = TRUE;
	int i = 0;
	int iLimit = 48;
	BYTE ch = 0;

	//vdDebug_LogPrintf("--inPrintXMLPacket--");
	
    if (inLen <= 0)
        return(ST_SUCCESS);

	if( printCheckPaper()==-1)
	return -1;

#if 0	
	vdCTOSS_PrinterStart(100);
    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_24x24,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, NORMAL_SIZE, 0, 0);
    CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  
#endif

    vdDebug_LogPrintf("inCurlPrintPacket 1 %s %d", pucMessage, inLen);

	vdCTOSS_PrinterStart(100);
	//CTOS_PrinterSetWorkTime(50000,1000);
	inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_16x16,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 0, 0);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);  




	if (fRequest)	
		inCCTOS_PrinterBufferOutput("[REQUEST]", &stgFONT_ATTRIB, FALSE);
	else
		inCCTOS_PrinterBufferOutput("[RESPONSE]", &stgFONT_ATTRIB, FALSE);
	
    memset(szStr, 0x00, sizeof(szStr));
	memset(baTemp, 0x00, sizeof(baTemp));
    sprintf(szStr,"[%s] [%d] \n", pucTitle, inLen);
	inCCTOS_PrinterBufferOutput(szStr, &stgFONT_ATTRIB, FALSE);
	vdCTOS_PrinterFline(1);		

	do
	{
		memset(szStr, 0x00, sizeof(szStr));
		memcpy(szStr, &pucMessage[i], iLimit);
		pucMessage[i+1] = '\0';
		purge_chr(szStr, '\n');
		//vdDebug_LogPrintf("i[%d].Len[%d].szStr[%s]", i, strlen(szStr), szStr);	
		vdDebug_LogPrintf("szStr = %s", szStr);
		inCCTOS_PrinterBufferOutput(szStr, &stgFONT_ATTRIB, FALSE);
			
		i+=iLimit;
		if (i > inLen) break;

		
	}while (fLoop);	
	
	vdCTOS_PrinterFline(4);
	
    vdCTOSS_PrinterEnd();

	//vdDebug_LogPrintf("--Exit--");
	
    return d_OK;
}

short vduiPressAnyKey(void)
{
    unsigned char key;
  
    vduiClearBelow(8);
    CTOS_LCDTPrintXY(1,8,"PRESS ANY KEY");

		#if 0
    while(1)
    {
        key = struiGetchWithTimeOut();

        break;
    }
		#else
			WaitKey(5);
		#endif
		
	return;
}

