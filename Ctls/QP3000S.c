#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ftw.h>
#include <unistd.h>
#include <time.h>

unsigned char debug[2048];

#define d_MAIN_ZIP_NOT_FOUND        1
#define d_MAIN_CREATE_SUB_PROCESS   2
#define d_MAIN_UNZIP_FAIL           3
#define d_MAIN_WAIT_UNZIP_FAIL      4
#define d_MAIN_OPEN_TM_FAIL         5

unsigned char baFWVer[100];
unsigned char baNewVer[100];

// Parameter Settings
#define QP_COM d_COM1
#define QP3000S_FILE "QP3000S.bin"

int inQP_InitCOM(int inBaudrate)
{
	inResult = CTOS_RS232Open(QP_COM, inBaudrate, 'N', 8, 1);
	return inResult;
}

int inQP_CloseCOM(void)
{
	CTOS_RS232Close(QP_COM);
	return d_OK;
}
int inQP_Senddata(char *szSendBuf, int inSize)
{
	int inResult;
	do
	{
		  inResult = CTOS_RS232TxReady(QP_COM);
			if (inResult == d_OK)
				break;
	}while ((CTOS_TickGet() - tick) < d_READY_TIMEOUT);

	if (ret == d_OK)
		CTOS_RS232TxData(QP_COM, szSendBuf, inSize);
	else return inResult;
	
	return inResult;
}

int inQPDownloadFirmware(char *szFileName)
{
  int inResult, len, rlen, i;
  unsigned char sbuf[1024], rbuf[1024], b;
  unsigned long tick;
	ULONG ulHandle, ulReadSize;
	
	inResult = CTOS_FileOpen(szFileName, d_STORAGE_FLASH, &ulHandle);
	if(inResult != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "Firmware not Found");
		return inResult; 
	}

	vdDebug_LogPrintf("Try VW enter download mode...");

	inResult = inQP_InitCOM(38400l);
	if(inResult != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "OPEN COM ERROR");
		return inResult; 
	}
	
	inQP_Senddata("\x02\x00\x0B\x01\x0E\x01\xFE\x00\x00\xE9\x7B\x03", 12);
	inQP_CloseCOM();

    // ======================== Get FW Version ========================
	CTOS_Delay(2)
	
 	inResult = inQP_InitCOM(57600l);
	if(inResult != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "OPEN COM ERROR");
		return inResult; 
	}

	vdDebug_LogPrintf("SULD MODE\n");
	memset(baFWVer, 0x00, sizeof(baFWVer));
	memset(rbuf, 0x00, sizeof(rbuf));
	inQP_Senddata("\x10\x02\x80\x30\x00\x00\xB0\x10\x03", 9);
	CTOS_Delay(2)
	CTOS_RS232RxData(QP_COM, rbuf, &rlen);
	if(rlen>0)
	{
		rbuf[rlen]=0;
		vdDebug_LogPrintf("FM Version:%s",rbuf);
	}	
	else
	{
		vdDisplayErrorMsg(1, 8, "GET FM VER ERROR");
		return -1; 
	}

  CTOS_Delay(1);
    
    // ======================== Switch to 115200bps ========================
	vdDebug_LogPrintf("Try to switch to 115200bps...\n");
	inQP_Senddata("\x10\x02\x80\x0E\x05\x8B\x10\x03", 8);
	CTOS_Delay(500);
	rlen = 0;
	CTOS_RS232RxData(QP_COM, rbuf, &rlen);
	inQP_CloseCOM(); 
 
	inResult = inQP_InitCOM(115200l);
	if(inResult != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "OPEN COM ERROR");
		return inResult; 
	}
	
	vdDebug_LogPrintf("Switch to 115200bps ok.\n");

	// ======================== Download Loop ========================
	vdDebug_LogPrintf("Now Downloading.....");
	while (1)
	{
		ulReadSize=2;
		inResult = CTOS_FileRead(ulHandle, sbuf, &ulReadSize);
		if(inResult != d_OK);
		{
				vdDebug_LogPrintf("Read Length Error");
				break;
		}
        // MSB -> LSB
		len = sbuf[0] * 256 + sbuf[1];

    inResult = CTOS_FileRead(ulHandle, sbuf, &len);
		if(inResult != d_OK)
		{
			vdDebug_LogPrintf("Read Data 1 Error");
			return inResult
		}
    // When the data is "\x10\x02\x63\x00\x00\x63\x10\x03",
    // please just ignore it as the send data.
    if (len == 8 && memcmp(sbuf, "\x10\x02\x63\x00\x00\x63\x10\x03", 8) == 0)
    {
			;
		}
    else
    {
    	if (len == 9 && memcmp(sbuf, "\x10\x02\x80\x31\x90\x00\x21\x10\x03", 9) == 0)
      {
      	goto ResetEnd;
      }
		}
		// Send command out
		inQP_Senddata(sbuf, len);
		len = 0;

    // Get how many data will be responsed from the reader
    len=2;
    inResult = CTOS_FileRead(ulHandle, sbuf, &len);
    if(inResult != d_OK)
		{
			vdDebug_LogPrintf("Read Len 2 Error");
			return inResult
		}

    len = sbuf[0] * 256 + sbuf[1];
		inResult = CTOS_FileRead(ulHandle, sbuf, &len);
		if(inResult != d_OK)
		{
			vdDebug_LogPrintf("Read Data 2 Error");
			return inResult
		}
		
IgnoreResp63:
		rlen = 0;

    // Add timeout in this while loop
    while(len>rlen)
    {
    	tick = GetTickSec();
			CTOS_RS232RxData(QP_COM, rbuf, &rlen);
			if (GetTickSec() - tick > 50)
    	{
				vdDebug_LogPrintf("Receive data timeout!\n");
      	return d_DW_TIMEOUT;
			}
		}
    while (len > rlen)
    {
    	
            if (IO_CC_Recv(&b) == 0)
            {
                rbuf[rlen ++] = b;
                continue;
            }
            //if (GetTickSec() - tick > 15)
            
        }

        if (memcmp(sbuf, rbuf, len) != 0)
        {
            //If receive 63 (Continue), get again for 62
            if (rlen == 8 && memcmp(rbuf, "\x10\x02\x63\x00\x00\x63\x10\x03", 8) == 0)
            {
                goto IgnoreResp63;
            }
        }

        //The file data and response data should be identical.
        if (memcmp(sbuf, rbuf, len) != 0)
        {
               return d_DAT_RESPONSE_ERR;
        }

    } // End of while(1)


ResetEnd:

    // Reset reader
    printf("Reset reader...\n");

    IO_CC_Send("\x10\x02\x80\x31\x90\x00\x21\x10\x03", 9);
    while(IO_CC_Recv(rbuf) == d_OK) ;

    IO_FF_Close();

    ret = IO_CC_Close();
    if (ret != 0)
    {
        return ret;
    }

    // ========================================================================
    // If you don't need to get new version information, you can stop here.

    //printf("Done!\n");
    //return 0;

    // ========================================================================
    // Else you want to get the new version information....continue below code.

    printf("Wait for reset.....\n");
    sleep(12); //Wait device reset


    // --------------------- VW Download Mode -----------------
    printf("Try VW enter download mode...\n");

    ret = IO_CC_Open(38400); // Welcome Mode
    if (ret != 0)
    {
        return ret;
    }

    IO_CC_Send("\x02\x00\x0B\x01\x0E\x01\xFE\x00\x00\xE9\x7B\x03", 12);

    ret = IO_CC_Close();
    if (ret != 0)
    {
        return ret;
    }

    // --------------------- Get FW Version -----------------
    sleep(2);

    ret = IO_CC_Open(57600); // SULD Mode
    if (ret != 0)
    {
        return ret;
    }

    memset(baNewVer, 0x00, sizeof(baNewVer));
    memset(rbuf, 0x00, sizeof(rbuf));
    IO_CC_Send("\x10\x02\x80\x30\x00\x00\xB0\x10\x03", 9);
    sleep(2);

    rlen = 0;
    while (IO_CC_Recv(&b) == d_OK )
    {
        rbuf[rlen ++] = b;
    }

    if ( rlen > 0)
    {
        memcpy( baNewVer, &rbuf[3], rlen-6); // 6 = DLE STX CMD ... LRC DLE ETX

        printf("FW New Version:\n");
        printf("%s\n", baNewVer);
    }
    else
    {
        printf("Get FW New Version Failed!\n");
    }

    sleep(1);

    // Reset reader
    printf("Reset reader...\n");

    IO_CC_Send("\x10\x02\x80\x31\x90\x00\x21\x10\x03", 9);
    while(IO_CC_Recv(rbuf) == d_OK) ;


    // Close COM Port
    ret = IO_CC_Close();
    if (ret != 0)
    {
        return ret;
    }

    printf("Done!\n");
    return 0;
}

int inQPLoader(void)
{
	char *p = ".";
	pid_t pid;
	int pidstatus;
	int inRetVal;

	vdDebug_LogPrintf("QP Loader");

	baFWVer[0] = 0;
	baNewVer[0] = 0;

	c
	
	CTOS_LCDTClearDisplay();
	CTOS_LCDTPrintXY(1, 1, "QP READER DOWNLOAD");

	inRetVal = inQP_InitCOM(d_COM1, 38400);
	if(inRetVal != d_OK)
	{	
		vdDisplayErrorMsg(1, 8, "Open Com Error");
		return inRetVal; 
	}
 	
 	CTOS_LCDTPrintXY(1, 5, "DOWNLOADING");

    // Start Download
	vdDebug_LogPrintf("Start download...");

	inRetVal = Download(baBINFileName);

	if(inRetVal != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "Download Firmware Err");
    return inRetVal;
	}
    
	vdDebug_LogPrintf("QP3000 Remote Loader Finished\n");

	return d_OK;    
}

