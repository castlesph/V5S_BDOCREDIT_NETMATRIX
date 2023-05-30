/* 
 * File:   display.h
 * Author: Peggy Chang
 *
 * Created on 2011�~1��12��, �U�� 8:29
 */

#ifndef ___CTOS_INPUT_H___
#define	___CTOS_INPUT_H___

#ifdef	__cplusplus
extern "C" {
#endif

#define d_DEVICE_V5         0
#define d_DEVICE_V5S        1
#define d_DEVICE_TR220      2

#define d_INPUT_TIMEOUT     100*90
#define d_MENU_TIMEOUT      100*60

#define MODE_NORMAL 0
#define MODE_AMOUNT 1
#define MODE_IPADDRESS 2
#define MODE_PASSWORD	3   
#define MODE_FOODITEM	4 
#define MODE_POINT	5


#define INPUT_AMOUNT_SIZE 12

#define BYTE	unsigned char
#define USHORT	unsigned short		// 2byte
#define ULONG	unsigned long		// 4byte


//#define  d_LCD_FONTSIZE_8x16
/**************************
 *bAttribute    0x00 Normal
 *              0x01 Reverse
 *              0x02 Right
 *              0x04 Center
 *************************/  
#ifdef d_LCD_FONTSIZE_8x16
typedef struct
{
    BYTE *sHeader;
    BYTE bHaderAttr;
    BYTE *sDetail1;
    BYTE bDetail1Attr;
    BYTE *sDetail2;
    BYTE bDetail2Attr;
    BYTE *sTail;
    BYTE bTailAttr;
}tstLCDMsg;
#else       //8x8
typedef struct
{
    BYTE isKeepDisplay;
    BYTE *sHeader;
    BYTE bHaderAttr;
    BYTE *sHeaderX;
    BYTE bHaderXAttr;
    BYTE *sDetail1;
    BYTE bDetail1Attr;
    BYTE *sDetail2;
    BYTE bDetail2Attr;
    BYTE *sDetail3;
    BYTE bDetail3Attr;
    BYTE *sDetail4;
    BYTE bDetail4Attr;
    BYTE *sTail;
    BYTE bTailAttr;
    BYTE *sTailX;
    BYTE bTailAttrX;
}tstLCDMsg;
#endif

typedef struct
{
  	BYTE bDevice;
    BYTE bDisplayMode;
    BYTE bFontMode;
    USHORT bLCDFontSize;
    BYTE bGraphicLineDot;
    BYTE bLineStrSize;
}tstInitial;



 /*******************
 *bAttr =   0x00 Normal (Left)
 *          0x02 Right
 *          0x04 Center
 ******************/
BYTE MenuDisplay(BYTE *sHeaderString, BYTE iHeaderStrLen, BYTE bHeaderAttr, BYTE iCol, BYTE center_x, BYTE *sItemsString, BYTE isReCount);
BYTE InputString(USHORT usX, USHORT usY, BYTE bInputMode,  BYTE bShowAttr, BYTE *pbaStr, USHORT *usStrLen, USHORT usMinLen, USHORT usTimeOutMS);
BYTE InputStringAlpha(USHORT usX, USHORT usY, BYTE bInputMode,  BYTE bShowAttr, BYTE *pbaStr, USHORT *usStrLen, USHORT usMinLen, USHORT usTimeOutMS);
BYTE InputAmount(USHORT usX, USHORT usY, BYTE *szCurSymbol, BYTE exponent, BYTE first_key, BYTE *baAmount, ULONG *ulAmount, USHORT usTimeOutMS, BYTE bIgnoreEnter);
void vdCTOS_LCDGShowUpDown(BYTE isUP, BYTE isDOWN);
void clearLineToLine(int iStartLine, int iStopLine);
void show_initialize(tstInitial *stInitial);

void vdCTOS_InputTMSSetting(void);
void vdCTOS_InputTMSReSet(void);
BYTE InputStringAlphaEx2(USHORT usX, USHORT usY, BYTE bInputMode,  BYTE bShowAttr, BYTE *pbaStr, USHORT *usStrLen, USHORT usMinLen, USHORT usTimeOutMS);


#ifdef	__cplusplus
}
#endif

#endif	/* _DISPLAY_H */

