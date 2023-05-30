/*****************************************************************************
Castles Contactless Reader Loader Source Code
Released Date : 2009/01/21

This is a sample code used to illustrate the implementation of Firmware/Application
Downloader for Castles Contactless Reader (ex.. EZProx, iProx..)

All the implementations in here are at the PC Platform with the Borland C++ Builder 6.

Programmers need to replace the IO_CC_Open, IO_CC_Send, IO_CC_Recv, IO_CC_Close,
IO_FF_Open, IO_FF_Read, IO_FF_Close with the APIs in target platform.

The reader needs to enter Download Mode before calling the Download().
If the Castles defualt application is running, please do this by sending below command with current baudrate:
(If you do not change the baudrate, the default baudrate is 38400bps)
    02 00 0B 01 0E 01 FE 00 00 E9 7B 03
For the User's application in reader, please call CTOS_EnterDownloadMode() to enter download mode.

*****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#define d_OK                0
#define d_COM_OPEN_FAIL            100
#define d_COM_CLOSE_FAIL        101
#define d_COM_SET_PARA_FAIL_1        102
#define d_COM_SET_PARA_FAIL_2        103
#define d_COM_SET_PARA_FAIL_3        104
#define d_COM_READ_FAIL            105
#define d_COM_SEND_FAIL            106

#define d_FILE_OPEN_FAIL        110
#define d_FILE_READ_FAIL        111
#define d_FILE_READ_FAIL_1        112
#define d_FILE_READ_FAIL_2        113
#define d_FILE_READ_FAIL_3        114

#define d_DAT_RESPONSE_ERR        120

#define d_DW_TIMEOUT            130

#define d_INTERFACE_RS232        0

//File handle of the firmware file or application file.
FILE *FileHandle;
int COMHandle, COMPort;

extern char sCOM[128];
extern unsigned char baFWVer[64];
extern unsigned char baNewVer[64];

unsigned long GetTickSec()
{
    struct timeval tv_time;
    struct timezone tz_time;

    gettimeofday(&tv_time, &tz_time);
    return tv_time.tv_sec;
}

/////////////////////////////////////////////////////////////////////////////////////

/****************************************
API     : IO_CC_Open
Purpose : Initial the commuication interface between Reader and Download Device (Terminal or PC)
IN      : N/A
OUT     : N/A
Return  :
    0       : Initial OK
    Others  : Initial Failed
****************************************/
int IO_CC_Open(unsigned int baudrate)
{
    struct termios port;
    unsigned int ModemStatus;

    COMHandle = open(sCOM, O_RDWR);

    if (COMHandle == -1)
    {
        return d_COM_OPEN_FAIL;
    }

    if(tcgetattr(COMHandle, &port) < 0)
    {
        return d_COM_SET_PARA_FAIL_1;
    }

    port.c_cc[VMIN] = 0;
    port.c_cc[VTIME] = 2000 / 100; // in 0.1 sec
    port.c_iflag = port.c_oflag = port.c_cflag = port.c_lflag = 0;
    port.c_cflag |= CREAD | CLOCAL;
    if (baudrate == 38400)
        port.c_cflag |= B38400;
    else if (baudrate == 57600)
        port.c_cflag |= B57600;
    else if (baudrate == 115200)
        port.c_cflag |= B115200;
    port.c_cflag |= CS8;

    if (tcsetattr(COMHandle, TCSANOW, &port) < 0)
    {
        return d_COM_SET_PARA_FAIL_2;
    }
    
    // Not block the read action
    fcntl(COMHandle, F_SETFL, FNDELAY);

    // Sleep for micro seconds => sleep 700 ms
    usleep(700000);

        return d_OK;
}

/****************************************
API     : IO_CC_Send
Purpose : Send data out via the communication interface
IN      :
    buf     : Input data buffer
    len     : Input data len
OUT     : N/A
Return  :
    0       : Send OK
    Others  : Send Failed
****************************************/
int IO_CC_Send(unsigned char *buf, unsigned int len)
{
    if (write(COMHandle, buf, len) < 0)
    {
        return d_COM_SEND_FAIL;
    }

    return d_OK;
}

/****************************************
API     : IO_CC_Recv
Purpose : Receive one byte from the Contactless Reader
IN      :
    dat     : Data receives from the reader
OUT     : N/A
Return  :
    0       : Receive OK, data in the dat
    Others  : Receive Failed
****************************************/
int IO_CC_Recv(unsigned char *dat)
{
        int queuelen, readnum;
    unsigned long tick;

    tick = GetTickSec();

    while (GetTickSec() - tick < 5)        //Timeout 5 seconds
    {
        ioctl(COMHandle, FIONREAD, &queuelen);  //Check RX buffer is in data or not

        if (queuelen > 0)
        {
            read(COMHandle, dat, 1);

            return d_OK;
        }
    }

    return d_COM_READ_FAIL;
}

/****************************************
API     : IO_CC_Close
Purpose : Close the commuication interface between Reader and Download Device (Terminal or PC)
IN      : N/A
OUT     : N/A
Return  :
    0       : Close OK
    Others  : Close Failed
****************************************/
int IO_CC_Close()
{

    //Restore non-block read setting
    fcntl(COMHandle, F_SETFL, 0);

    if (close(COMHandle) < 0)
    {
        return d_COM_CLOSE_FAIL;
    }

    return d_OK;
}

/****************************************
API     : IO_FF_Open
Purpose : Initial to read firmware/application data from a media, it could be a file system or a data buffer.
IN      :
    file    : Input file naprintf("===========================FW Version(len=%d) : %s\n", rlen, baFWVer);
sleep(5);me
OUT     : N/A
Return  :
    0       : File Open OK
    Others  : File Open Failed
****************************************/
int IO_FF_Open(char *file)
{
    //Here we use the "file3rd.bin" as the filename, however, the file name could be various and may be inputed by loader application.

    if ((FileHandle = fopen(file, "rb")) == NULL)
    {
        return d_FILE_OPEN_FAIL;
    }

    return d_OK;
}

/****************************************
API     : IO_FF_Read
Purpose : Read data from the media with specified length, it could be reading data from a file or from a data buffer.
          The data pointer should be moved like a file, which means when you call this function and read 5 bytes(offset 0~4),
          the next time you call this and the data returned in the buffer will be the next 5 bytes(offset 5~9).
IN      :
    len     : Expected data length
OUT     :
    buf     : The output data buffer
Return  :
    0       : Read data ok, there are len bytes read and write to the buf.
    Others  : No data be read or the data in the buffer is not enough(less than len bytes)
****************************************/
int IO_FF_Read(unsigned char *buf, unsigned int len)
{
    int ret;
    unsigned int i;
    char ch;

    i = 0;

    do
    {
        ch = fgetc(FileHandle);

        if (feof(FileHandle) > 0)
        {
            return d_FILE_READ_FAIL;
        }

        buf[i ++] = (unsigned char)ch;
    } while (i < len);

    return d_OK;
}

/****************************************
API     : IO_FF_Close
Purpose : Finish to read the firmware/application data.
IN      : N/A
OUT     : N/A
Return  :
    0       : Finish OK
    Others  : Finish Failed
****************************************/
int IO_FF_Close()
{
    fclose(FileHandle);

    return d_OK;
}

/****************************************
Below is the main routine of the firmware/applicatoin downloader
The firmware/application data in the file is in below format :InterfaceType

    Send/Receive Block format :
        2 bytes length (MSB -> LSB)
        n bytes data

    Firmware/Application File = (Send Block + Receive Block) * m

Every command contains one Send Block and one Receive Block.

When the downloader reads a Send Block from the file, and then it needs to wait
for a Receive Block.

The data acutally received from the reader should be identified with the data read from the file,
otherwise the download is failed.

It is very important to add timeout checking in the marked place to avoid the dead lock. 
****************************************/
int Download(char *file)
{
    int ret, len, rlen, i;
    unsigned char sbuf[1024], rbuf[1024], b;
    unsigned long tick;

    ret = IO_FF_Open(file);
    if (ret != d_OK)
    {
        printf("BIN file not found : %s\n", file);
        return ret;
    }

    // ======================== Send VW enter download ========================
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

    // ======================== Get FW Version ========================
    sleep(2);

    ret = IO_CC_Open(57600); // SULD Mode
    if (ret != 0)
    {
        return ret;
    }

    memset(baFWVer, 0x00, sizeof(baFWVer));
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
        memcpy( baFWVer, &rbuf[3], rlen-6); // 6 = DLE STX CMD ... LRC DLE ETX

        printf("FW Version:\n");
        printf("%s\n", baFWVer);
    }
    else
    {
        printf("Get FW Version Failed!\n");
    }

    sleep(1);
    
    // ======================== Switch to 115200bps ========================
    printf("Try to switch to 115200bps...\n");
    IO_CC_Send("\x10\x02\x80\x0E\x05\x8B\x10\x03", 8);
    usleep(500);
    rlen = 0;
    while (IO_CC_Recv(&b) == d_OK)
    {
        rbuf[rlen ++] = b;
    }

    ret = IO_CC_Close();
    if (ret != 0)
    {
        return ret;
    }

    ret = IO_CC_Open(115200);
    if (ret != 0)
    {
        return ret;
    }

    printf("Switch to 115200bps ok.\n");



    // ======================== Download Loop ========================
    printf("Now Downloading.....\n");
    while (1)
    {
        // Read Send Block data length
        if (IO_FF_Read(sbuf, 2) != 0)
        {
            break;
        }

        // MSB -> LSB
        len = sbuf[0] * 256 + sbuf[1];

        // Read actually data length
        if (IO_FF_Read(sbuf, len) != 0)
        {
            return d_FILE_READ_FAIL_1;
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

            // Send command out
            IO_CC_Send(sbuf, len);
            len = 0;

            // Get how many data will be responsed from the reader
            if (IO_FF_Read(sbuf, 2) != 0)
            {
                return d_FILE_READ_FAIL_2;
            }

            len = sbuf[0] * 256 + sbuf[1];

            // What data should be responsed form the reader. Keep it for future comparison
            if (IO_FF_Read(sbuf, len) != 0)
            {
                return d_FILE_READ_FAIL_3;
            }
        }
      

IgnoreResp63:

        rlen = 0;

        // Add timeout in this while loop
        tick = GetTickSec();

        while (len > rlen)
        {
            if (IO_CC_Recv(&b) == 0)
            {
                rbuf[rlen ++] = b;
                continue;
            }
            //if (GetTickSec() - tick > 15)
            if (GetTickSec() - tick > 50)
            {
                printf("Receive data timeout!\n");
                return d_DW_TIMEOUT;
            }
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


