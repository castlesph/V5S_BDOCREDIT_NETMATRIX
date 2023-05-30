
#ifndef ___MULTI_SHARLS_COM___
#define ___MULTI_SHARLS_COM___

typedef enum
{
    d_IPC_CMD_COMM_INIT		        = 0x01,
	d_IPC_CMD_COMM_CONNECT		    = 0x02,
	d_IPC_CMD_COMM_SEND		        = 0x03,
    d_IPC_CMD_COMM_RECEIVE	        = 0x04,
    d_IPC_CMD_COMM_DISCONNECT		= 0x05,
    d_IPC_CMD_COMM_END		        = 0x06,
    d_IPC_CMD_GPRS_SIGNAL		    = 0x07,
	d_IPC_CMD_COMM_GETCONFIG 		= 0x08,
	d_IPC_CMD_COMM_SETCONFIG		= 0x09,
	d_IPC_CMD_GPRS_SIGNALEX		    = 0x0A,
	//d_IPC_CMD_SETFONT				= 0x99,
	
	d_IPC_CMD_COMM_CONNECT_PreConnect1			= 0x10,
	d_IPC_CMD_COMM_CONNECT_PreConnect2			= 0x11,
	d_IPC_CMD_COMM_GETGPRSIP                = 0x0F,
	d_IPC_CMD_COMM_GETGPRSPING                = 0x12,
	d_IPC_CMD_COMM_GETGPRSIPINFO		          = 0x13,

	d_IPC_CMD_COMM_INIT_CONNECTEx			= 0x19,
	d_IPC_CMD_COMM_SENDEx		        = 0x1A,
	d_IPC_CMD_COMM_RESETGPRS		= 0x20,
	d_IPC_CMD_COMM_BIND_DEVICE      = 0x21,
	
}IPC_COMM_CMD_TYPES;

#define IPC_COMM_SUCC       100
#define IPC_COMM_FAIL       101

#define NO_HEADER_LEN                0
#define HEX_EXCLUDE_LEN              1
#define BCD_EXCLUDE_LEN              2
#define HEX_INCLUDE_LEN              3
#define BCD_INCLUDE_LEN              4


int inCTOSS_COMM_Initialize(TRANS_DATA_TABLE *srTransPara,int mode);
int inCTOSS_COMM_Connect(TRANS_DATA_TABLE *srTransPara);
int inCTOSS_COMM_Send(TRANS_DATA_TABLE *srTransPara,unsigned char *uszSendData,unsigned long ulSendLen);
int inCTOSS_COMM_Receive(TRANS_DATA_TABLE *srTransPara,unsigned char *uszRecData);
int inCTOSS_COMM_Disconnect(TRANS_DATA_TABLE *srTransPara);
int inCTOSS_COMM_End(TRANS_DATA_TABLE *srTransPara);
int inCTOSS_GetGPRSSignal(unsigned short* usNetworkType, char* szNetworkName,unsigned short* usEthType);
int inCTOSS_GetGPRSSignalEx(unsigned short* usNetworkType, char* szNetworkName,unsigned short* usEthType);
int inCTOSS_COMMSetFont(char *font);
int inCTOSS_SIMGetGPRSIP(void);

#if 1
typedef struct
{
	unsigned short usGPRSNetworkType;
	char szGPRSNetworkName[20+1];
	BYTE bgGPRSSignal;
	BYTE bgGPRSType;
	BYTE usEthType;
	BYTE usWIFIType;
	BYTE szWIFISSID[50];
	BYTE usGPSType;
	BYTE usBLUETOOTHType;
	BYTE usDIALPPType;
	BYTE inReserved1;
	BYTE inReserved2;
	BYTE inReserved3;
	BYTE szReserved1[50];
	BYTE szReserved2[50];
	BYTE szReserved3[50];
	BYTE szReserved4[50];
} STRUCT_SHARLS_COM ;

typedef struct
{
	BYTE	szIP[30] ;
    BYTE	szGetWay[30] ;
    BYTE	szSubNetMask[30] ;
    BYTE	szHostDNS1[30] ;
    BYTE	szHostDNS2[30] ;
    BYTE 	szReserved1[50];
	BYTE 	szReserved2[50];
	BYTE 	szReserved3[50];
	BYTE 	szReserved4[50];

} STRUCT_IP_INFO;


int inCTOSS_COMMWIFISCAN(void);
int inCTOSS_GetGPRSSignalEx(unsigned short* usNetworkType, char* szNetworkName,unsigned short* usEthType);
int inWIFI_GetConnectConfig(void);
int inCTOSS_GPRSPing(unsigned char *strIPURL);
int inCTOSS_SIMGetGPRSIPInfo(void);
void vdPrint_EthernetStatus(void);
int inMultiAP_RunIPCCmdTypesExx(char *Appname, int IPC_EVENT_ID, BYTE *inbuf, USHORT inlen, BYTE *outbuf, USHORT *outlen);




#endif
#endif  //end ___MULTI_SHARLS_ECR___

