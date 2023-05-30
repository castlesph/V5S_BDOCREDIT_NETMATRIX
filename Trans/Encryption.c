/*=========================================*       
 *             I N C L U D E S             *     
 *=========================================*/ 
#include <string.h>
#include <stdio.h>
#include <ctosapi.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <EMVAPLib.h>
#include <EMVLib.h>


#include "../Includes/POSTypedef.h"
#include "../Includes/myEZLib.h"
#include "../Includes/wub_lib.h"


#include "../FileModule/myFileFunc.h"
#include "../DataBase/DataBaseFunc.h"


void vdSHA1Generate(BYTE *szData, USHORT szDataLen, BYTE *szSHA1Result)
{          
    
    return;                                                                 
    SHA_CTX SHA_CTX;
    //Initialize the SHA_CTX structure and perpart for the SHA1 operation //                                
    CTOS_SHA1Init(&SHA_CTX);
    
    //Perform the SHA1 algorithm with the input data //                                                     
    CTOS_SHA1Update(&SHA_CTX,szData,8);                                                          
                                                                      
    //Finalize the SHA1 operation and retrun the result //                                                   
    CTOS_SHA1Final(szSHA1Result,&SHA_CTX);                                                                         
    
    return;
}


void Encrypt3Des(unsigned char *data, unsigned char *key, unsigned char *result)
{
    unsigned char tmpBuf1[9],tmpBuf2[9];

    CTOS_DES(d_ENCRYPTION,key,8,data,8,tmpBuf1);
    CTOS_DES(d_DECRYPTION,&key[8],8,tmpBuf1,8,tmpBuf2);
    CTOS_DES(d_ENCRYPTION,key,8,tmpBuf2,8,result);
 
}
 

void Decrypt3Des(unsigned char *data, unsigned char *key, unsigned char *result)
{
    unsigned char tmpBuf1[9],tmpBuf2[9];
    CTOS_DES(d_DECRYPTION,key,8,data,8,tmpBuf1);
    CTOS_DES(d_ENCRYPTION,&key[8],8,tmpBuf1,8,tmpBuf2);
    CTOS_DES(d_DECRYPTION,key,8,tmpBuf2,8,result); 
}

void Decrypt3DesCBC(unsigned char *data, unsigned char *key, unsigned char *result)
{

    unsigned char tmpBuf1[9],tmpBuf2[9], tmpBuf3[9], szFirstBlock[9];
    short usCnt;

    CTOS_DES(d_DECRYPTION,key,8,&data[8],8,tmpBuf1);
    CTOS_DES(d_ENCRYPTION,&key[8],8,tmpBuf1,8,tmpBuf2);
    CTOS_DES(d_DECRYPTION,key,8,tmpBuf2,8,tmpBuf3); 
    memcpy(&result[8], tmpBuf3, 8);

    for(usCnt = 0; usCnt < 8; usCnt++)
    {

        szFirstBlock[usCnt] = tmpBuf3[usCnt] ^ data[usCnt];
    }
     
    CTOS_DES(d_DECRYPTION,key,8, szFirstBlock,8,tmpBuf1);
    CTOS_DES(d_ENCRYPTION,&key[8],8,tmpBuf1,8,tmpBuf2);
    CTOS_DES(d_DECRYPTION,key,8,tmpBuf2,8,result); 


}

void GET_KEY( BYTE *szClearTMK , BYTE *szClearTAK)
{
    BYTE temp[17];
    BYTE strTMK[17], strZMK[17], strTAK[17];
        
    inTLERead(1);

    memcpy(strZMK,stTLE.szZMK,16);
    memcpy(strTMK,stTLE.szTMK,16);
    memcpy(strTAK,stTLE.szTAK,16);
    
    memset( temp, 0x00, 17);
    Decrypt3Des(strTMK,strZMK , temp);
    memcpy(szClearTMK, temp, 8);    
    memset( temp, 0x00, 8);
    Decrypt3Des(&strTMK[8], strZMK, temp);
    memcpy(&szClearTMK[8], temp, 8);
    
        
    memset( temp, 0x00, 17);
    Decrypt3Des(strTAK, strZMK, temp);
    memcpy(szClearTAK, temp, 8);    
    memset( temp, 0x00, 8);
    Decrypt3Des(&strTAK[8], stTLE.szZMK, temp);
    memcpy(&szClearTAK[8], temp, 8);

}

void vdTripleDES_CBC(BYTE Mode, BYTE *szMsg, BYTE szMsgLen, BYTE *DESResult)
{
    USHORT       usIndex ;
    USHORT       usCnt ;
    BYTE         temp[17], strDatakey[17];
    BYTE         szDesData[17];

    
    inTLERead(1);
    
    vdMyEZLib_LogPrintff(szMsg, szMsgLen);  
        
    memcpy(strDatakey, stTLE.szLineEncryptKey,16 );
    for(usIndex = 0; usIndex < szMsgLen; usIndex = usIndex + 8)
    {
        for(usCnt = 0; usCnt < 8; usCnt++)
        {
            if(usIndex == 0)
                szDesData[usCnt] = szMsg[usIndex + usCnt] ^ 0x00;
            else
                szDesData[usCnt] = szMsg[usIndex + usCnt] ^ DESResult[(usIndex - 8) + usCnt];
        }

        Encrypt3Des(szDesData, strDatakey, &DESResult[usIndex]);
    }
}


void vdisoOneTwo(BYTE *in, BYTE *out, short lc)
{
    BYTE tmp;
    short i,len;

    len=lc;
    for(i=0;i<len;i++)
    {
        tmp=in[i]/16;
        if(tmp<10)
            out[2*i]=tmp+'0';
        else
            out[2*i]=toupper(tmp)+'A'-0x0A;

        tmp=in[i]%16;
        if(tmp<10)
            out[2*i+1]=tmp+'0';
        else
            out[2*i+1]=toupper(tmp)+'A'-0x0A;
    }
    out[2*i]=0;
}

void vdisoTwoOne(unsigned char *in,short inInLen,unsigned char *out)
{
    unsigned char tmp;
    short i;

    for(i=0;i<inInLen;i+=2)
    {
        tmp=toupper(in[i]);
        if(tmp>='A' && tmp<='F')
            tmp=tmp-('A'-0x0A);
        else
            tmp&=0x0f;
        tmp<<=4;
        out[i/2]=tmp;

        tmp=toupper(in[i+1]);
        if(tmp>='A' && tmp<='F')
            tmp=tmp-('A'-0x0A);
        else if(!tmp)
            tmp=0x0f;
        else if(tmp == '*')
            tmp=0x0b;
        else
            tmp&=0x0f;
        out[i/2]+=tmp;
    }
}
