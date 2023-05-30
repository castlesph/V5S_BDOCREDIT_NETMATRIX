#ifndef _LIB_NMX_DEFINE_H_
#define	_LIB_NMX_DEFINE_H_


#define NMX_CARRIER_FIELD_SZ		512


#define	KID_LENGTH		    6
#define	KID_DIVIDER		90
#define	KID_PAD_CHR		33		//!



#define KEY_HEADER_SZ				4
#define APPID_SZ					2
#define KEYID_SZ					6				// KID/x where x is the key type
#define ENC_ALGO_SZ				2
#define MAC_ALGO_SZ				1
#define KYM_MANAGE_SZ				1
#define VERSION_SZ					2
#define FLAG_SZ						2	
#define	CMDCODE_SZ					2
#define TXNCOUNTER_SZ				6				// Txn Counter
#define DEVICE_MODEL_SZ           20
#define DEVICE_SERINAL_SZ         20
#define SMARTCARD_SERN_SZ         20


#define     ENCRY_ALGO_AES              "01"
#define     ENCRY_ALGO_TEA              "02"
#define     ENCRY_ALGO_TDES             "03"
#define     ENCRY_ALGO_DES              "04"

#define     KEY_MANAGE_PER_TERMINAL     '2'
#define     KEY_MANAGE_PER_TXN           '4'

#define     MAC_ALGO_ANSI_99            '1'
#define     MAC_ALGO_ANSI_919           '2'
#define     MAC_ALGO_SHA1_X99           '3'
#define     MAC_ALGO_SHA1_X919          '4'


#define     NMX_VERSION_NUMBER          "01"
#define     NMX_FLAG_NUMBER             "01"

#define     NMX_RKI_DEFAULT_KEYINDEX                0x0002
#define     NMX_RKI_DEK_DEFAULT_KEYSET              0x0060
#define     NMX_RKI_MEK_DEFAULT_KEYSET              0x0064

#define     NMX_TLE_DEFAULT_KEYINDEX                0x0002
#define     NMX_TLE_DEK_DEFAULT_KEYSET              0x0070
#define     NMX_TLE_MEK_DEFAULT_KEYSET              0x0074


typedef struct _NMX_TLED_HEADER 
{
   char szAppID[APPID_SZ + 1];                         // AppID    
   char szRKIKID[KEYID_SZ + 1];                       // RKI KeyID
   char szTLEKID[KEYID_SZ + 1];                       // TLE KeyID
   char szVersion[VERSION_SZ + 1];                    // Version Number
   char szEncAlgo[ENC_ALGO_SZ + 1];                   // Encryption Algo
   char szKeyMag[KYM_MANAGE_SZ + 1];                  // Key Management
   char szMACAlgo[MAC_ALGO_SZ + 1];                   // MAC Algo 
   char szCommandCode[CMDCODE_SZ + 1];               // Command Code
   char szDeviceMode[DEVICE_MODEL_SZ + 1];            // Device Model 
   char szDeviceSerNo[DEVICE_SERINAL_SZ + 1];        // Device Serial No
   char szFlag[FLAG_SZ+1];                            // Flag
   char szCounter[TXNCOUNTER_SZ + 1];                 // Txn Counter
   char szSensitiveFieldBMP[16 + 1];                  //ASIC field bitmap
   int inRKIDEKKeySet;
   int inRKIMEKKeySet;
   int inRKIKeyIndex;
   int inTLEDEKKeySet;   
   int inTLEMEKKeySet;
   int inTLEKeyIndex;
   int inNMXEnable;

} NMX_TLED_HEADER;


NMX_TLED_HEADER srNMXHeader;

#endif  //endif  //_LIB_NMX_DEFINE_H_

