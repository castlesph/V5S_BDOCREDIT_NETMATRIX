/** 
**	A Template for developing new terminal application
**/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
/** These two files are necessary for calling CTOS API **/
#include <ctosapi.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <signal.h>

#include "..\Debug\Debug.h"


#define MAX_BUF 2048

char gCOMDev[20]="/dev/ttyACM0";  //COM Port Device file

int fdcom;						//File descriptor for the COM port
int gCOMBaudrate = 115200; 		//COM Baudrate
int gCOMDataBit = 8;	  		//COM DataBit
int gCOMStopBit = 1;	  		//COM StopBit
int gCOMParity = 0;		  		//COM Parity
int gCOMFlowcontrol = 0;  		//COM Flowcontrol
int gCOMBaudrateIn_old , gCOMBaudrateOut_old;
struct termios newTS, oldTS;	// c_iflag, c_oflag, c_cflag, c_lflag

unsigned long TimeOutCount;

/*******************************************************************************/
// <Title>  Open COM PORT Device and set handshake states
// <Para>   strComDevice [String]: COM Port device string. (ie,"/dev/ttyS0)
// <Return> -1:Fail , >0:OK
/*******************************************************************************/
int openCOM(char *strComDevice)
{ 
	int fdcom;
	//fdcom = open(strComDevice, O_RDWR | O_NOCTTY | O_NDELAY );	//O_NONBLOCK = ASYNC mode 
        fdcom = open(strComDevice, O_RDWR | O_NOCTTY | O_NONBLOCK);
	//fdcom = open(strComDevice, O_RDWR);
	if (-1 == fdcom)
	{
		//perror("Can't Open Serial Port ");
		vdDebug_LogPrintf("Can't Open Serial Port");
		return -1;
	}

	return fdcom;	//return;
}

/*******************************************************************************/
// <Title> Close COM Port handler
// <PARA>  fdcom: COM Handler
// <Return> 0:OK
/*******************************************************************************/
int closeCOM(int fdcom)
{
	int   status;
	
	//usleep(300*1000);
	//usleep(30*1000);

	tcflush(fdcom,TCIOFLUSH);  //flush I/O Buffer

	cfsetispeed(&oldTS , gCOMBaudrateIn_old);   // Set original Baudrate  (B9600,...)
	cfsetospeed(&oldTS , gCOMBaudrateOut_old);

	status = tcsetattr(fdcom, TCSANOW, &oldTS);	// Restore original setting immediately
	if  (status != 0)
	{
		perror("setCOM(..) tcsetattr fdcom 2");
		return -1;
	}
	close(fdcom);
	return 0;
}

/*******************************************************************************/
void setRS232_Config(char *theConfigStr) //Format: Baudrate,Parity,Data-Bit
{
	char tmp[10];
	char *ptr = theConfigStr;
	int i , j;
	char cCOMParity;

	memset(tmp,0,sizeof(tmp));
	i=j=0;
	printf("%s\n",theConfigStr);
	//Get Baudrate value
	do {
		if (*ptr != ' ')
			tmp[i++] = *(ptr++);
	} while (*ptr != ',');
	tmp[i] = '\0';
	gCOMBaudrate = atoi(tmp);

	//Get Parity
	cCOMParity=*(++ptr);
	cCOMParity= (cCOMParity >= 0x61 ? cCOMParity-0x20 : cCOMParity );
	if (cCOMParity =='N')
		gCOMParity=0;
	else 	if (cCOMParity =='O')
		gCOMParity=1;
	else 	if (cCOMParity =='E')
		gCOMParity=2;

	//Get Data Bit
	ptr++;
	gCOMDataBit = *(++ptr) - 0x30;

	//Set Stop Bit = 1
	gCOMStopBit = 1;

	//Set Flow Control off
	gCOMFlowcontrol = 0;
}

/*******************************************************************************/
// <Title>  Write data to COM Port
// <PARA>   fdcom:COM Device Handler , wbuf:Writing buffer ,length:Writing length
// <Return> Actual writing length
/*******************************************************************************/
int writeToCOM(int fdcom, unsigned char *wbuf, int length)
{
	int len = 0;
	len = write(fdcom, wbuf, length);

	if (len == length)
		return len;
	else
		return -1;
}

/*******************************************************************************/
// <Title>  Read data from COM Port
// <PARA>   fdcom:COM Device Handler , rbuf:Writing buffer  ,length:read length
// <Return> Actual read length
/*******************************************************************************/
int readFromCOM(int fdcom, unsigned char *rbuf, int length)
{
	int writepos , readnum, queuelen, leftNeedData ,toReadDataNum;
	int RecLen;
	int itime,jtime;
	unsigned long TimeSet;
	
#ifdef TIMER
	struct timeb enterTime,exitTime;
#endif	

	writepos = 0;
	leftNeedData = length;
	RecLen = 0;
	#ifdef DEBUG_RS232
		printf("read COM buffer start \n");
	#endif
#ifdef TIMER
	ftime(&enterTime);
#else
	jtime = 0;
#endif
	while (1)
	{
		
		if (leftNeedData==0)
			break;
		queuelen = 0;
		ioctl(fdcom, FIONREAD, &queuelen);  //Check RX buffer is in data or not
//		usleep(10);
		CTOS_Delay(50);

		vdDebug_LogPrintf("readFromCOM queuelen[%d]", queuelen);
		if (queuelen > leftNeedData )
			toReadDataNum = leftNeedData ;
		else	// if (queuelen <= leftNeedData )
			toReadDataNum =  queuelen;
	
		if ( queuelen>0 )
		{
#ifdef TIMER
			ftime(&enterTime);
#else
			jtime = 0;
#endif

			readnum = read(fdcom, rbuf+writepos, toReadDataNum);
			leftNeedData -= readnum;
			RecLen += readnum;
			writepos += readnum;  //latest saving position
			//(TT) printf("Wait All Data in (Needed:%d, Queue:%d, nowRead:%d, LeftData:%d ).\n",length, queuelen, readnum, leftNeedData);
			vdDebug_LogPrintf("Wait All Data in (Needed:%d, Queue:%d, nowRead:%d, LeftData:%d )",length, queuelen, readnum, leftNeedData);
			TimeSet = 0;

			if (RecLen > 0)
			{
				break;
			}

		}
		else
		{
			vdDebug_LogPrintf("RecLen[%d]", RecLen);
			if (RecLen > 0)
			{
				break;
			}
		}
#ifdef TIMER
		ftime(&exitTime);
		if (TimeOut(enterTime,exitTime,5000))
		{
			TimeOutCount++;
			printf("Receive Data Time Out !!! \n");
			printf("read COM buffer end (len:%d)\n",RecLen);
			break;
		}
#else
		for(itime = 0 ; itime < 30000 ; itime++);
		
		jtime++;
                
                if(jtime == 30) break;
		
		if(jtime == 2000)
		{
			TimeOutCount++;
			printf("Receive Data Time Out !!! \n");
			printf("read COM buffer end (len:%d)\n",RecLen);
			break;
		}
#endif
	}

	//usleep(1);	//Adding this will be more stable , but get less efficience.

	#ifdef DEBUG_RS232
		printf("read COM buffer end (len:%d)\n",length);
	#endif
	
	return RecLen;
}

/*******************************************************************************/
// <Title> Setup COM PORT Configures (Baudrate, Data bit, Parity, Stop bit ,handshake states,...)
// <Return> 0:OK , non-zero:Fail
/*******************************************************************************/
int setCOM(int fdcom, int baudrate, int databit, int stopbit, int parity, int flowctrl)
{
	int   status;
	unsigned int i;
	int baudrate_bit[] = { B115200, B57600, B38400, B19200, B9600,B4800,B2400,B1200,B600,B300,B150,B110,B75,B50 ,B9600};
	int baudrate_value[] = {115200, 57600, 38400, 19200, 9600,4800,2400,1200,600,300,150,110,75,50 ,0};

	if( tcgetattr( fdcom, &newTS)  !=  0)	//get original COM setting
	{
		perror("setCOM(..) tcgetattr(..)");
		return -1;
	}
	//bzero(&oldTS,sizeof(oldTS)); //clear oldTS

	gCOMBaudrateIn_old = cfgetispeed(&newTS);
	gCOMBaudrateOut_old = cfgetospeed(&newTS);

	memcpy(&oldTS , &newTS , sizeof(struct termios) );  //Backup original Terminal Setting

    /* local mode setting */
    newTS.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG ); 	//For INPUT raw mode

    /* output mode setting */
    newTS.c_oflag &= ~OPOST;   //Set output mode with raw data output (Set ~OPOST , it will ignore all other flags)
	//newTS.c_oflag &= ~(ONLCR | OCRNL | ONLRET);   //Not change '\n' to '\r\n' ; not change '\r' to '\n' ; ...

    /* input mode setting */
	newTS.c_iflag &= ~(ICRNL | IGNCR);  //When read in <\x0D>        , not change to <\x0A>
	newTS.c_iflag &= ~IXON;	            //When read in <\x11> <\x13> , not throw them away

    //Set Raw mode (receive any character)
    //newTS.c_iflag &= ~ ( IGNBRK | IGNCR | INLCR | ICRNL | IUCLC | IXANY | IXON | IXOFF | INPCK | ISTRIP);

    /* Control mode setting */
	newTS.c_cflag |= ~CREAD;    //Make port can read

	/* Set Data Bit */
	newTS.c_cflag &= ~CSIZE; //Mask the character size bits
	switch (databit)  
	{
		case 5:
			newTS.c_cflag |= CS5;
			break;
		case 6:
			newTS.c_cflag |= CS6;
			break;
		case 7:
			newTS.c_cflag |= CS7;
			break;
		case 8:
			newTS.c_cflag |= CS8;
			break;
		default:
			fprintf(stderr,"Unsupported data size\n");
			return -1;
			break;
	}

     /* Set Stop Bit */  
	switch (stopbit)
	{
		case 1:
			newTS.c_cflag &= ~CSTOPB;
			break;
		case 2:
			newTS.c_cflag |= CSTOPB;
			break;
		default:
			fprintf(stderr,"Unsupported stop bits\n");
			return -1;
			break;
	}

	/* Set parity check */
	switch (parity)  
	{
		case 0:
			newTS.c_cflag &= ~PARENB;   // No parity check
			newTS.c_cflag &= ~CSTOPB;
			break;
		case 1:
			newTS.c_cflag |= PARENB;  	// Odd check
			newTS.c_cflag &=~PARODD;
			newTS.c_iflag |=INPCK;		// Set input parity option  (ISTRIP)
			newTS.c_iflag |=0;
			break;
		case 2:
			newTS.c_cflag |= PARENB;  	// Even check
			newTS.c_cflag |= PARODD;
			newTS.c_iflag |= INPCK;		//Set input parity option  (ISTRIP)
			newTS.c_iflag |=0;
			break; 
		default:
			fprintf(stderr,"Unsupported parity\n");
			return -1;
			break;
	}

	/* Set data flow control */
	switch (flowctrl)              
	{
		case 0:
			newTS.c_cflag &= ~CRTSCTS;   // No flow control
			break;
		case 1:
			newTS.c_cflag |= CRTSCTS;    // With hardware flow control
			break;
		case 2:
			newTS.c_cflag |= IXON|IXOFF|IXANY; // With software flow control
			break;
		default:
			fprintf(stderr,"Unsupported flow-control\n");
			return -1;
			break;
	}

	/* Set baudrate */
	for ( i= 0;  i < sizeof(baudrate_bit) / sizeof(int);  i++)
	{
		if  (baudrate == baudrate_value[i])
		{
			cfsetispeed(&newTS, baudrate_bit[i]);  //Re-set input  Baudrate
			cfsetospeed(&newTS, baudrate_bit[i]);  //Re-set output Baudrate
			break;
		}
	}

	newTS.c_cc[VTIME] = 0;		//Set timeout for wait for data (tenths of seconds). 10 = 1second
	//newTS.c_cc[VTIME] = 10;   //Set timeout for wait for data (tenths of seconds). Unit is 1/10 second
	newTS.c_cc[VMIN] = 0;		//set minimum number of characters to read

	tcflush(fdcom,TCIOFLUSH);	//Clear I/O Buffer  (TCIOFLUSH / TCIFLUSH / TCIOFLUSH)

	status = tcsetattr(fdcom, TCSANOW, &newTS);  // Update new terminal setting immediately.  (Same as ioctl(..TCSETS..) )
	  //TCSANOW: Make changes now without waiting for data to complete
	  //TCSADRAIN: Wait until everything has been transmitted
	  //TCSAFLUSH: Refresh input/output buffer , and change setting

	if  (status != 0)
	{
		perror("Failed !! setCOM() tcsetattr fdcom");
		return -1;
	}

	status = usleep(300*1000);	//delay for taking effect with COM setting

	return 0;
}


void CDCTest(void)
{
	int ret;
	int StartLoop;
	unsigned char SendBuf[MAX_BUF];
	unsigned char ReceiveBuf[MAX_BUF];
        BYTE bKey;
        BYTE ShowData[64];
	
	ret = 0;
	
	while(1)
	{
                CTOS_KBDHit(&bKey);
                if(bKey == d_KBD_CANCEL) break;
                memset(SendBuf,0x00,sizeof(SendBuf));
		memset(ReceiveBuf,0x00,sizeof(ReceiveBuf));
		fdcom = openCOM(gCOMDev);	
		if (fdcom == -1)
		{
			printf("Failed! Open COM !!\n");
			CTOS_LCDTPrintXY(1,8,"Open NG");
                        return;
		}
		/*
		ret = setCOM(fdcom, gCOMBaudrate, gCOMDataBit, gCOMStopBit, gCOMParity, gCOMFlowcontrol);
		if (ret==-1)	{
			printf("Failed! Set COM Config !! \n");
                        CTOS_LCDTPrintXY(1,8,"Set NG");
			goto EXIT;
		}
		*/
		tcflush(fdcom,TCIOFLUSH);  //flush I/O Buffer
		for(StartLoop = 0 ; StartLoop < MAX_BUF ; StartLoop++)
		{
			SendBuf[StartLoop] = StartLoop%256;
		}
		tcflush(fdcom,TCIOFLUSH);  //flush I/O Buffer	
		ret = writeToCOM(fdcom, "\x10\x02\x0A\x05\x02\x00\x00\x00\x00\x00\x01\x00\x0C\x10\x03 " , 15);
		if (ret == -1  )	{
			printf("Failed! Write data to COM !!\n");
                        CTOS_LCDTPrintXY(1,8,"Write NG");
			goto EXIT;
		}
		
		memset(ReceiveBuf , 0x00 , sizeof(ReceiveBuf));
		ret = readFromCOM(fdcom, ReceiveBuf , MAX_BUF );
		
                memset(ShowData, 0x00, sizeof(ShowData));
                sprintf(ShowData, "Rec (Len : %d)", ret);
                CTOS_LCDTPrintXY(1,3, ShowData);
		
                memset(ShowData, 0x00, sizeof(ShowData));
                sprintf(ShowData, "%02X%02X%02X%02X%02X%02X%02X%02X\n%02X%02X%02X%02X%02X%02X%02X%02X", 
                        ReceiveBuf[0], ReceiveBuf[1], ReceiveBuf[2], ReceiveBuf[3], 
                        ReceiveBuf[4], ReceiveBuf[5], ReceiveBuf[6], ReceiveBuf[7],
                        ReceiveBuf[8], ReceiveBuf[9], ReceiveBuf[10], ReceiveBuf[11],
                        ReceiveBuf[12], ReceiveBuf[13], ReceiveBuf[14], ReceiveBuf[15]);
                CTOS_LCDTPrintXY(1,5, ShowData);
		
		closeCOM(fdcom);
		
		usleep(10);
	}

EXIT:
	closeCOM(fdcom);
	return;
		
}


