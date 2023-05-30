
#ifndef _DMENU__H
#define	_DMENU__H

#ifdef	__cplusplus
extern "C" {
#endif

#include "..\Includes\POSTypedef.h"

#define DB_DYNAMICMENU		"./fs_data/DYNAMICMENU01.S3DB"

typedef int (*DMENU_FUN)(void)  ;

typedef struct tagDMENU
{
	unsigned short usButtonID;
	unsigned char szButtonItemImage[100];
	unsigned char szButtonItemLabel[100];
	unsigned char szButtonTitleLabel[100];	
	unsigned char szButtonItemFunc[100];	
	unsigned char szSubMenuName[100];	
} DMENU;

#define MAXMENUS 	1024

typedef struct tagMENU
{
	unsigned char m_COMMANDMenu[100];	
	DMENU *cmMENU;
} MENU;

typedef struct tagTouch
{
	char szImageKey[100];
	int usImageX1;
	int usImageY1;
	int usImageX2;
	int usImageY2;
	int usImageX0;
	int usImageY0;
} TOUCH;

int inF1KeyEvent(void);
int inF2KeyEvent(void);
int inF3KeyEvent(void);
int inF4KeyEvent(void);
int inEnterKeyEvent(void);
int inDynamicMenu(DMENU* cmMENU_COMMNAD);	
BYTE bGMenuDisplay(BYTE *sHeaderString, BYTE iHeaderStrLen, BYTE bHeaderAttr, BYTE iCol, BYTE center_x, BYTE *sItemsString, BYTE isReCount);


/* BDO CLG: Revised menu functions - start -- jzg */
#define MENU_RETAIL_CR_DEBIT_INST 1
#define MENU_RETAIL_CR_DEBIT 2
#define MENU_RETAIL_CR_ONLY 3
#define MENU_RESTO_CR_DEBIT_INST 4
#define MENU_RESTO_CR_DEBIT 5
#define MENU_RESTO_CR_ONLY 6
#define MENU_HOTEL_CR_DEBIT_INST 7
#define MENU_HOTEL_CR_DEBIT 8
#define MENU_HOTEL_CR_ONLY 9
/* BDO CLG: Revised menu functions - end -- jzg */


#endif	/* _DMENU__H */

