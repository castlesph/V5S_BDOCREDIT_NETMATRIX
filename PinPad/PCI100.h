

#ifndef _PCI100_H
#define	_PCI100_H

#ifdef	__cplusplus
extern "C" {
#endif

#define MK_DES_KEY	50
#define WK_DES_KEY	51

#define MK_3DES_DOUBLE_KEY	100
#define WK_3DES_DOUBLE_KEY	101

#define MK_3DES_TRIPLE_KEY	110
#define WK_3DES_TRIPLE_KEY	111



#define SEND_BUF	200
#define RECV_BUF	300

#define PCI100_DLE		0x10
#define PCI100_STX		0x02
#define PCI100_ETX		0x03


#define MINIMUM_DES_KEY	0
#define MAXIMUM_DES_KEY	99

#define MINIMUM_3DES_KEY	100
#define MAXIMUM_3DES_KEY	198


#define GET_DEVICE_INFO	0x30
#define INITTIAL_AUTHENTICATION	0x31
#define MUTUAL_AUTHENTICATION		0x32
#define	SET_SERIAL_NUMBER		0x34
#define	RESET_PINPAD		0x36
#define	CHANGE_BAUD		0x37
#define SET_BACK_LIGHT		0x69


#define	SAVE_GENERAL_MK		0x2D
#define	SAVE_GENERAL_WK		0x2E
#define	SAVE_MK_BY_TK		0x2C

#define	GET_PIN		0x44
#define	GET_MAC		0x43
#define	GET_PIN_MSG		0x45


#define	DISP_MESSAGE	0x65
#define	IDLE_MESSAGE	0x68

#define	MK_TYPE_FLAG	0x21

#define d_ERROR  (-1)  //Error 

#ifndef d_OK
#define d_OK  0x00  //Operation OK 
#endif

#define d_STAT_BAD_PARAMETER  0x01  //Parameter is invalid 
#define d_STAT_MK_NOT_LOAD  0x02  //Key is not loaded 
#define d_STAT_SAVE_RECEIPT_FORMAT_FAIL  0x03  //Save receipt format fail 
#define d_STAT_MK_BAD_CV  0x04  //Bad key check code 
#define d_STAT_PIN_TIMEOUT  0x0A  //Get PIN time out 
#define d_STAT_PIN_ABORT  0x0Bh //User abort the PIN Input 
#define d_STAT_PIN_NULLPIN  0x0C  //User does not input any digits 
#define d_STAT_DUKPT_OVERFLOW  0x0E  //DUKPT KSN is overflow 
#define d_STAT_DUKPT_FAILED  0x0F  //Get DUKPT PIN failed 
#define d_STAT_CERT_INVALID  0x11  //Certified Key Block is invalid 
#define d_STAT_PIN_BLOCK_30  0x12  //PIN is blocked by 30 seconds 
#define d_STAT_NO_PRIVILEGE  0x13  //Key is not belong to this application
#define d_STAT_KEY_TYPE_ERR  0x14  //Key type is wrong for this operation
#define d_STAT_KEY_CORRUPT  0x15 //Key  data  is  invalid  and  can’t  use anymore 
#define d_STAT_KEY_MATCH_VIOLATE  0x16 //Different  key  index  with  the  same key value 
#define d_STAT_KEY_FLAG_ERR  0x17  //Key Flag not match with Key Index
#define d_STAT_INIT_AUTH_NOT_PERFORMED  0x9h  //Initial Authentication not performed
#define d_STAT_AUTH_NOT_PERFORMED  0x20  //Mutual Authentication not performed 
#define d_STAT_DATA_INCORRECT  0x21 //Mac verified fail in encryption communication. 
#define d_STAT_AUTH_FAIL  0x22 //Authentication failed. If Term Crypto input value for Mutual Authentication command it then will get this return code. 
#define d_STAT_DEVICE_BLOCKED  0x23 //Device blocked.  If Mutual Authentication process failed is greater than or equal to 3 

#define d_STAT_WRITE_FLASH_FAIL_BK1  0x30  //Write system parameter fail 
#define d_STAT_WRITE_FLASH_FAIL_BK2  0x31  //Write DUKPT fail 
#define d_STAT_WRITE_FLASH_FAIL_BK3  0x32  //Write TDUKPT fail 
#define d_STAT_WRITE_FLASH_FAIL_BK4  0x33  //Write MK fail 
#define d_STAT_FNTFILE_FORMAT_ERROR  0x40  //Font file format error 
#define d_STAT_FNTFILE_HEADER_ERROR  0x41  //Font file header incorrect 
#define d_STAT_FNTFILE_LRC_ERROR  0x42  //Font file check sum error 
#define d_STAT_FNTFILE_BODY_ERROR  0x43  //Font file body incorrect 
#define d_STAT_FNTFILE_MID_NOT_EXIST  0x44  //Font file message ID not exist 
#define d_STAT_FNTFILE_MID_INAVALID  0x45  //Font file message ID invalid 
#define d_STAT_SERIALNUM_NOT_READY  0xFD //Serial Number not ready, needs to perform Set Serial Number first. 
#define d_COMMAND_NOT_SUPPORT  0xFE  //Command not support 
#define d_SELF_TEST_FAIL  0xFF  //System self test fail 


int inPCI100_GetPINProcess(int WKID,int TimeOut,int MaxPINlen,int MinPINlen,int NullPIN,int PANLen,char *szPAN,char *PinBlock);
int inPCI100_GetMACProcess(int WKID,char *szICV,int Datalen,char *szData,char *MacBlock);
int inPCI100_SaveMKProcess(int MKID,int Keylen,char *szMasterKey);
int inPCI100_SaveWKProcess(int MKID,int WKID,int Keylen,char *szEncWKey,char *szKCV);

int inPCI100_DisplayMessageProcess(int PositionX,int PositionY,int Displen,char *szDispMessage);
int inPCI100_SetIdleMessageProcess(int Displen,char *szDispMessage);
int inPCI100_DisplayMessage(int PositionX,int PositionY,int Displen,char *szDispMessage);
int inPCI100_SetIdleMessage(int Displen,char *szDispMessage);
int inPCI100_DisplayMessageProcessNoAuth(int PositionX,int PositionY,int Displen,char *szDispMessage);

int inPCI100_GetPIN_Message(int WKID,int TimeOut,int MaxPINlen,int MinPINlen,int NullPIN,int PANLen,char *szPAN,char *szmessage1,char *szmessage2,char *szmessage3,char *PinBlock);
int inPCI100_GetPIN_MessageProcess(int WKID,int TimeOut,int MaxPINlen,int MinPINlen,int NullPIN,int PANLen,char *szPAN,char *szmessage1,char *szmessage2,char *szmessage3,char *PinBlock);
int inPCI100_CheckMK(int MKid);
int inPCI100_CheckMKType_Flag(int MKid);


extern void vdPCIDebug_HexPrintf(char * display,char * szHexbuf,int len);
extern void vdDispTransTitle(BYTE byTransType);
	

#ifdef	__cplusplus
}
#endif

#endif	/* _PCI100_H */

