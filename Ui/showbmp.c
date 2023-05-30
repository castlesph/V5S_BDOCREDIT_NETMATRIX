#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <linux/fb.h>
#include <linux/kd.h>/*����ӵģ����ڽ���ͼ��ģʽʱioctlʹ��*/
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
/** These two files are necessary for calling CTOS API **/
#include <ctosapi.h>
#include <semaphore.h>
#include <pthread.h>

#include "..\Includes\POSTypedef.h"
#include "..\Debug\Debug.h"
#include "..\Includes\showbmp.h"
#include "..\DataBase\DataBaseFunc.h"
#include "..\Comm\V5Comm.h"

extern USHORT CTOS_LCDTTFASCIIAdjust(SHORT sHorizontalExtend, SHORT sVerticalExtend, SHORT sHorizontalOffset, SHORT sVerticalOffset);


typedef  struct 
{ 
    unsigned int x;
    unsigned int y; 
    char *path1; 
    char *path2; 
    char *path3; 
    char *path4; 
    char *path5;
}StAnimateBmp;


pthread_t ptDAB;  
pthread_attr_t attr;

pthread_t ptColdInitDAB;  
pthread_attr_t ptColdInitattr;

static pthread_t ptIdleDAB;  
static pthread_attr_t ptIdleAttr;
static int inPthreadIdleShowPic = 0;
static StAnimateBmp StAnimateIdleBmp;


static int inPthreadCommShowPic = 0;
static pthread_t ptCommDAB;  
static pthread_attr_t ptCommAttr;
static StAnimateBmp StAnimateCommBmp;


static int inPthreadPrintShowPic = 0;
static pthread_t ptPrintDAB;  
static pthread_attr_t ptPrintAttr;
static StAnimateBmp StAnimatePrintBmp;


/******************************************************************************
 *
 ******************************************************************************/

////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma pack(1) /* ���ýṹ��ı߽����Ϊ1���ֽ�,Ҳ��������������ڴ���������洢�� */
/* ͷ���ļ����͡��ļ���С�����λ�õ���Ϣ */


#pragma pack()

void displaybmpEx(unsigned int x,unsigned int y, const char *path)
{
    char szBmpfile[50+1];

    memset(szBmpfile, 0x00, sizeof(szBmpfile));
    sprintf(szBmpfile,"%s%s", PUBLIC_PATH,path);
	//Set the LCD Display is Graphic Mode //
    CTOS_LCDSelectModeEx(d_LCD_GRAPHIC_320x240_MODE, FALSE);
    CTOS_LCDGShowBMPPic(x, y, szBmpfile);
    CTOS_LCDSelectModeEx(d_LCD_TEXT_320x240_MODE, FALSE);
    
    return;
}

void displayAppbmpDataEx(unsigned int x,unsigned int y, const char *path)
{
    char szBmpfile[50+1];

    memset(szBmpfile, 0x00, sizeof(szBmpfile));
	//0826
    //sprintf(szBmpfile,"%s%s", LOCAL_PATH,path);
    sprintf(szBmpfile,"%s%s", PUBLIC_PATH,path);
	//0826
	//Set the LCD Display is Graphic Mode //
    CTOS_LCDSelectModeEx(d_LCD_GRAPHIC_320x240_MODE, FALSE);
    CTOS_LCDGShowBMPPic(x, y, szBmpfile);
    CTOS_LCDSelectModeEx(d_LCD_TEXT_320x240_MODE, FALSE);
    
    return;
}



int inSetTextMode(void)
{   

	vdDebug_LogPrintf("crash testing inSetTextmode");

    CTOS_LCDSelectMode(d_LCD_TEXT_320x240_MODE);
    CTOS_LCDTTFSelect(d_FONT_DEFAULT_TTF, 0);
    CTOS_LCDFontSelectMode(d_FONT_TTF_MODE);
    CTOS_LCDTSelectFontSize(d_FONT_16x30);
//    CTOS_LCDTTFASCIIAdjust(25,  25, 0,  0);

//    CTOS_LCDForeGndColor(RGB(255,255,255));
//    CTOS_LCDBackGndColor(RGB(77,153,211));

    CTOS_LCDForeGndColor(RGB(0,0,0));
    CTOS_LCDBackGndColor(RGB(255,255,255));

    return d_OK;
}


int inSetColorMenuMode(void)
{   
		if((strTCT.byTerminalType % 2) == 0)
		{
			CTOS_LCDForeGndColor(RGB(13, 43, 112));
			CTOS_LCDBackGndColor(RGB(255, 255, 255));
		}

    return d_OK;
}

int inSetTextModeEx(BYTE *inbuf, USHORT inlen)
{
	vdDebug_LogPrintf("inSetTextModeEx=inlen=[%d],inbuf[%s]",inlen,inbuf);

	CTOS_LCDTTFSelect(inbuf, 0);
 
	return d_OK;
}


void *pvdDisplayAnimateBmp(void *pStAnimateBmp1)
{
    StAnimateBmp *StAnimateBmp2 = pStAnimateBmp1;
 
    while(1)
    {

        if (StAnimateBmp2->path1!=NULL)
        {
            displaybmpEx(StAnimateBmp2->x, StAnimateBmp2->y, StAnimateBmp2->path1); 
        }
        
        if (StAnimateBmp2->path2!=NULL)
        {
            displaybmpEx(StAnimateBmp2->x, StAnimateBmp2->y, StAnimateBmp2->path2);     
        }

        if (StAnimateBmp2->path3!=NULL)
        {
            displaybmpEx(StAnimateBmp2->x, StAnimateBmp2->y, StAnimateBmp2->path3);     
        }

        if (StAnimateBmp2->path4!=NULL)
        {
            displaybmpEx(StAnimateBmp2->x, StAnimateBmp2->y, StAnimateBmp2->path4);     
        }
        
        if (StAnimateBmp2->path5!=NULL)
        {
            displaybmpEx(StAnimateBmp2->x, StAnimateBmp2->y, StAnimateBmp2->path5);     
        }
        
        {
            return NULL;
        }           
    }
}

void vdDisplayAnimateBmp(unsigned int x,unsigned int y, const char *path1, const char *path2, const char *path3, const char *path4, const char *path5)
{
    int inStatus;

    StAnimateBmp StAnimateBmp1;
    
    StAnimateBmp1.x = x;
    StAnimateBmp1.y = y;
    StAnimateBmp1.path1 = (char *)path1;
    StAnimateBmp1.path2 = (char *)path2;
    StAnimateBmp1.path3 = (char *)path3;
    StAnimateBmp1.path4 = (char *)path4;
    StAnimateBmp1.path5 = (char *)path5;

    pthread_attr_init(&attr);
    pthread_create(&ptDAB, &attr, pvdDisplayAnimateBmp, (void *)&StAnimateBmp1);
    pthread_attr_destroy(&attr);    
    pthread_join(ptDAB,NULL);

    return ;
}

void vdSetIdleThreadStatus(int inStatus)
{   
    inPthreadIdleShowPic = inStatus;
    CTOS_Delay(50);
}

int inGetIdleThreadStatus(void)
{
    return inPthreadIdleShowPic;
}

void vdSetCommThreadStatus(int inStatus)
{
    inPthreadCommShowPic = inStatus;

    if(1 == inStatus)
    {
        vdThreadDisplayCommBmp(0,0, "Comms1.bmp", "Comms2.bmp", "Comms3.bmp", "Comms4.bmp", NULL);
    }
}

int inGetCommThreadStatus(void)
{
    return inPthreadCommShowPic;
}

void vdSetPrintThreadStatus(int inStatus)
{
    inPthreadPrintShowPic = inStatus;

    if(1 == inStatus)
    {
		vdPrintReportDisplayBMP();
    }
}

int inGetPrintThreadStatus(void)
{
    return inPthreadPrintShowPic;
}

void *pvdDisplayIdleBmp(void *arg)
{

    pthread_detach(pthread_self());

    while(1)
    {
        if(0 == inGetIdleThreadStatus())
        {
            vdDebug_LogPrintf("pvdDisplayIdleBmp sleep1");
            CTOS_Delay(200);
            continue;
        }   
        else
        {                 
            if (StAnimateIdleBmp.path1!=NULL && 1 == inGetIdleThreadStatus())
            {
                vdDebug_LogPrintf("pvdDisplayIdleBmp path1");
                displaybmpEx(StAnimateIdleBmp.x, StAnimateIdleBmp.y, StAnimateIdleBmp.path1);
                CTOS_Delay(100);
            }

            if (StAnimateIdleBmp.path2!=NULL && 1 == inGetIdleThreadStatus())
            {
                vdDebug_LogPrintf("pvdDisplayIdleBmp path2");
                displaybmpEx(StAnimateIdleBmp.x, StAnimateIdleBmp.y, StAnimateIdleBmp.path2);
                CTOS_Delay(100);
            }

            if (StAnimateIdleBmp.path3!=NULL && 1 == inGetIdleThreadStatus())
            {
                vdDebug_LogPrintf("pvdDisplayIdleBmp path3");
                displaybmpEx(StAnimateIdleBmp.x, StAnimateIdleBmp.y, StAnimateIdleBmp.path3);
                CTOS_Delay(100);
            }

            if (StAnimateIdleBmp.path4!=NULL && 1 == inGetIdleThreadStatus())
            {
                vdDebug_LogPrintf("pvdDisplayIdleBmp path4");
                displaybmpEx(StAnimateIdleBmp.x, StAnimateIdleBmp.y, StAnimateIdleBmp.path4);
                CTOS_Delay(100);
            }

            if (StAnimateIdleBmp.path5!=NULL && 1 == inGetIdleThreadStatus())
            {
                vdDebug_LogPrintf("pvdDisplayIdleBmp path5");
                displaybmpEx(StAnimateIdleBmp.x, StAnimateIdleBmp.y, StAnimateIdleBmp.path5);
                CTOS_Delay(100);
            }
        }
                    
    }
}

void *pvdDisplayCommBmp(void *arg)
{

    pthread_detach(pthread_self());

    while(1)
    {
        if(0 == inGetCommThreadStatus())
        {
            vdDebug_LogPrintf("pvdDisplayCommBmp pthread_exit");
            pthread_exit(NULL);
        }   
        else
        {                 
            if (StAnimateCommBmp.path1!=NULL && 1 == inGetCommThreadStatus())
            {
                vdDebug_LogPrintf("pvdDisplayCommBmp path1");
                displaybmpEx(StAnimateCommBmp.x, StAnimateCommBmp.y, StAnimateCommBmp.path1);
                CTOS_Delay(100);
            }

            if (StAnimateCommBmp.path2!=NULL && 1 == inGetCommThreadStatus())
            {
                vdDebug_LogPrintf("pvdDisplayCommBmp path2");
                displaybmpEx(StAnimateCommBmp.x, StAnimateCommBmp.y, StAnimateCommBmp.path2);
                CTOS_Delay(100);
            }

            if (StAnimateCommBmp.path3!=NULL && 1 == inGetCommThreadStatus())
            {
                vdDebug_LogPrintf("pvdDisplayCommBmp path3");
                displaybmpEx(StAnimateCommBmp.x, StAnimateCommBmp.y, StAnimateCommBmp.path3);
                CTOS_Delay(100);
            }

            if (StAnimateCommBmp.path4!=NULL && 1 == inGetCommThreadStatus())
            {
                vdDebug_LogPrintf("pvdDisplayCommBmp path4");
                displaybmpEx(StAnimateCommBmp.x, StAnimateCommBmp.y, StAnimateCommBmp.path4);
                CTOS_Delay(100);
            }

            if (StAnimateCommBmp.path5!=NULL && 1 == inGetCommThreadStatus())
            {
                vdDebug_LogPrintf("pvdDisplayCommBmp path5");
                displaybmpEx(StAnimateCommBmp.x, StAnimateCommBmp.y, StAnimateCommBmp.path5);
                CTOS_Delay(100);
            }
        }
                    
    }
}


void *pvdDisplayPrintBmp(void *arg)
{         
    if (StAnimatePrintBmp.path1!=NULL)
    {
        displaybmpEx(StAnimatePrintBmp.x, StAnimatePrintBmp.y, StAnimatePrintBmp.path1);
        CTOS_Delay(100);
    }

    if (StAnimatePrintBmp.path2!=NULL)
    {
        displaybmpEx(StAnimatePrintBmp.x, StAnimatePrintBmp.y, StAnimatePrintBmp.path2);
        CTOS_Delay(100);
    }

    if (StAnimatePrintBmp.path3!=NULL)
    {
        displaybmpEx(StAnimatePrintBmp.x, StAnimatePrintBmp.y, StAnimatePrintBmp.path3);
        CTOS_Delay(100);
    }

    if (StAnimatePrintBmp.path4!=NULL)
    {
        displaybmpEx(StAnimatePrintBmp.x, StAnimatePrintBmp.y, StAnimatePrintBmp.path4);
        CTOS_Delay(100);
    }

    if (StAnimatePrintBmp.path5!=NULL)
    {
        displaybmpEx(StAnimatePrintBmp.x, StAnimatePrintBmp.y, StAnimatePrintBmp.path5);
        CTOS_Delay(100);
    }
    
    pthread_exit(NULL);
}


void vdThreadDisplayIdleBmp(unsigned int x,unsigned int y, const char *path1, const char *path2, const char *path3, const char *path4, const char *path5)
{
    int inStatus;
    int stack_size;
    void *sp = NULL;

    StAnimateIdleBmp.x = x;
    StAnimateIdleBmp.y = y;
    StAnimateIdleBmp.path1 = (char *)path1;
    StAnimateIdleBmp.path2 = (char *)path2;
    StAnimateIdleBmp.path3 = (char *)path3;
    StAnimateIdleBmp.path4 = (char *)path4;
    StAnimateIdleBmp.path5 = (char *)path5;
  
    pthread_create(&ptIdleDAB, &ptIdleAttr, pvdDisplayIdleBmp, (void*)NULL);

    pthread_attr_destroy(&ptIdleAttr);

    return ;
}

void vdThreadDisplayCommBmp(unsigned int x,unsigned int y, const char *path1, const char *path2, const char *path3, const char *path4, const char *path5)
{
    int inStatus;
    int stack_size;
    void *sp = NULL;

    StAnimateCommBmp.x = x;
    StAnimateCommBmp.y = y;
    StAnimateCommBmp.path1 = (char *)path1;
    StAnimateCommBmp.path2 = (char *)path2;
    StAnimateCommBmp.path3 = (char *)path3;
    StAnimateCommBmp.path4 = (char *)path4;
    StAnimateCommBmp.path5 = (char *)path5;

    pthread_attr_init(&ptCommAttr);
    
    pthread_attr_setdetachstate(&ptCommAttr, PTHREAD_CREATE_DETACHED);
    
    pthread_create(&ptCommDAB, &ptCommAttr, pvdDisplayCommBmp, (void*)NULL);

    pthread_attr_destroy(&ptCommAttr);
    
    return ;
}


void vdThreadDisplayPrintBmp(unsigned int x,unsigned int y, const char *path1, const char *path2, const char *path3, const char *path4, const char *path5)
{
    int inStatus;
    int stack_size;
    void *sp = NULL;

    StAnimatePrintBmp.x = x;
    StAnimatePrintBmp.y = y;
    StAnimatePrintBmp.path1 = (char *)path1;
    StAnimatePrintBmp.path2 = (char *)path2;
    StAnimatePrintBmp.path3 = (char *)path3;
    StAnimatePrintBmp.path4 = (char *)path4;
    StAnimatePrintBmp.path5 = (char *)path5;

    vdDebug_LogPrintf("vdThreadDisplayPrintBmp");


    pthread_attr_init(&ptPrintAttr);
    
    pthread_attr_setdetachstate(&ptPrintAttr, PTHREAD_CREATE_DETACHED);
   
    pthread_create(&ptPrintDAB, &ptPrintAttr, pvdDisplayPrintBmp, (void*)NULL);

    pthread_attr_destroy(&ptPrintAttr);
    
    return ;
}

void *pvdThreadRunColdInit(void *arg)
{

    inFirstInitConnectFuncPoint();
    
    pthread_exit(NULL);
}



void vdThreadRunAppColdInit(void)
{    

    vdDebug_LogPrintf("vdThreadRunAppColdInit");

    pthread_attr_init(&ptColdInitattr);
    
    pthread_attr_setdetachstate(&ptColdInitattr, PTHREAD_CREATE_DETACHED);

    pthread_create(&ptColdInitDAB, &ptColdInitattr, pvdThreadRunColdInit, (void*)NULL);

    pthread_attr_destroy(&ptColdInitattr);
    
    return ;
}


