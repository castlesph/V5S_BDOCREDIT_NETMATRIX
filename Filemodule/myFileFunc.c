/** 
**    A Template for developing new terminal shared application
**/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
/** These two files are necessary for calling CTOS API **/
#include <ctosapi.h>
#include "../Includes/myEZLib.h"
#include "../Includes/wub_lib.h"
#include "../Includes/POSTypedef.h"

#include "../Includes/Trans.h"

#include "myFileFunc.h"
#include "../Database/DatabaseFunc.h"
#include "../Debug/Debug.h"



#define DB 1
 /*==========================================================================================*
 *   Function Name : inMyFile_RecSave                                                       
 *   input parameter :                                                                      
 *          [void *] :STRUCT_FILE_SETTING Variable pointer                                  
 *                      ex:STRUCT_FILE_SETTING *strFile                                     
 *                      @strFile->ulHandle : saved file handle                              
 *                      #strFile->szFileName : filename wanted to open;                     
 *                      #strFile->bStorageType : ex: d_STORAGE_FLASH                        
 *                      #strFile->bSeekType : d_SEEK_FROM_BEGINNING                         
 *                                            d_SEEK_FROM_CURRENT                           
 *                                            d_SEEK_FROM_EOF                               
 *                      #strFile->inSeekCnt : number of skiped Rec.                         
 *                      #strFile->ulRecSize : Rec. Size                                     
 *                      #strFile->ptrRec : Pointer of Rec wanted to be saved.               
 *                      notes: @-> means that caller did not need to assign value           
 *                             #-> caller needed to assign value                            
 *                                 before used inMyFile_RecSave func                        
 *          return:                      
 *              ST_SUCCESS ---> SUCCESS  
 *              ST_ERROR ---> Write Error
 *==========================================================================================*/
int inMyFile_RecSave(void *p1)
{
    STRUCT_FILE_SETTING *strFile = (STRUCT_FILE_SETTING *) p1; 
        
    ULONG   *ulHandle = &(strFile->ulHandle);
    char    *szFileName = strFile->szFileName;
    BYTE    bStorageType = strFile->bStorageType;
    BYTE    bSeekType = strFile->bSeekType;
    int     inSeekCnt = strFile->inSeekCnt;
    
    ULONG   ulRecSize = strFile->ulRecSize;
    BYTE    *byRec = (BYTE *)strFile->ptrRec;
    
    int     inResult;
    ULONG   ulPosition;
    BYTE    byBuffer[d_BUFF_SIZE];

    vdDebug_LogPrintf("[inMyFile_RecSave] >>> filename[%s]", szFileName);                                                                                                                                      
    if(ulRecSize == 0x00 || byRec == 0x00)
        return RC_FILE_REC_OR_RECSIZE_IS_NULL;

		// patrick add code 20141207
                inResult = inMyFile_CheckFileExist(szFileName);
		if(inResult <= 0)
		{
				inResult = CTOS_FileOpen(szFileName , bStorageType , ulHandle);		
		    //glady-removelater
		    vdDebug_LogPrintf("[Glady-CTOS_FileOpen]--->>>result - %d", inResult);		
	      if(inResult != 0)
	          CTOS_Delay(200);
		    //glady-removelater
		
		}
    
    /* Open a file and return a number called a file handle. 
    * If the specified file name does not exist , it will be created first. */   
    if(*(ulHandle) == 0x00)
    {        
        inResult = CTOS_FileOpen(szFileName , bStorageType , ulHandle);
        vdDebug_LogPrintf("[inMyFile_RecSave]---File Handle was 0x00, Created File, inResult[%d]", inResult);
    }        
    else
    {
        vdDebug_LogPrintf("[inMyFile_RecSave]---File Handle already existed");        
        inResult = d_OK;
    }
    
    if (inResult == d_OK)
    {                                                                                       
        /* Move the file pointer to a specific position. 
        * Move backward from the end of the file.        */
        inResult = CTOS_FileSeek(*ulHandle, inSeekCnt*ulRecSize, bSeekType);
        if (inResult != d_OK)
        {
            vdDebug_LogPrintf("[inMyFile_RecSave]---Rec Seek inResult[%04x]", inResult);
            CTOS_FileClose(*ulHandle);
            return ST_ERROR;                                                                        
        }

        /* Write data into this opened file */
        inResult = CTOS_FileWrite(*ulHandle ,byRec ,ulRecSize);                                         
        if (inResult != d_OK)
        {
            vdDebug_LogPrintf("[inMyFile_RecSave]---Rec Write error, inResult[%04x]", inResult);
            CTOS_FileClose(*ulHandle);
            return ST_ERROR; 
        }                                                                       
        
        vdDebug_LogPrintf("[inMyFile_RecSave]---Write finish, CurrPos[%d], inResult[%d]", inSeekCnt, inResult);
        
        /* Close the opened file */
        if(strFile->fCloseFileNow)
        {    
            if((inResult = CTOS_FileClose(*ulHandle)) != d_OK)
            {                
                vdDebug_LogPrintf("[inMyFile_RecSave]---FileClz err[%04x]", inResult);
                return ST_ERROR;
            }
            else
                *ulHandle = 0x00;

			vdDebug_LogPrintf("[inMyFile_RecSave]---User close immed.");
        }
            vdDebug_LogPrintf("[inMyFile_RecSave]---User did not close immed.");
    }


    
    return ST_SUCCESS;    
}

/*==========================================================================================*
 *   Function Name : inMyFile_RecRead                                                       
 *   input parameter :                                                                      
 *          [void *] :STRUCT_FILE_SETTING Variable pointer                                  
 *                      ex:STRUCT_FILE_SETTING *strFile                                    
 *                      @strFile->ulHandle : saved file handle                              
 *                      #strFile->szFileName : filename wanted to open;                     
 *                      #strFile->bStorageType : ex: d_STORAGE_FLASH                        
 *                      #strFile->bSeekType : d_SEEK_FROM_BEGINNING                         
 *                                            d_SEEK_FROM_CURRENT                           
 *                                            d_SEEK_FROM_EOF                               
 *                      #strFile->inSeekCnt : number of skiped Rec.                         
 *                      #strFile->ulRecSize : Rec. Size                                     
 *                      #strFile->ptrRec : Pointer of Rec.                                  
                                           read out the data to be put inside the rec.                                  *
 *                      notes: @-> means that caller did not need to assign value           
 *                             #-> caller needed to assign value                            
 *                                 before used inMyFile_RecRead func                        
 *          return:                                                                         
 *              ST_SUCCESS ---> SUCCESS                                                     
 *              RC_FILE_READ_OUT_NO_DATA --> Read File at end
 *              ST_ERROR ---> Read Error
 *==========================================================================================*/

int inMyFile_RecRead(void *p1)
{
    STRUCT_FILE_SETTING *strFile = (STRUCT_FILE_SETTING *) p1; 
    
    
    ULONG   *ulHandle = &(strFile->ulHandle);
    char    *szFileName = strFile->szFileName;
    BYTE    bStorageType = strFile->bStorageType;
    BYTE    bSeekType = strFile->bSeekType;
    int     inSeekCnt = strFile->inSeekCnt;
    
    ULONG   ulRecSize = strFile->ulRecSize;
    ULONG   ulReadOutSize;
    BYTE    *byRec = (BYTE *)strFile->ptrRec;
    
    int     inResult;
    ULONG   ulPosition;
    BYTE    byBuffer[d_BUFF_SIZE];
    
    vdDebug_LogPrintf("[inMyFile_RecRead]--->>>fileName[%s]", szFileName);    

	// patrick add code 20141207
	if((inResult = inMyFile_CheckFileExist(szFileName)) <= 0)
	{
	//vdDebug_LogPrintf("[inMyFile_inMyFile_CheckFileExist]--->>>fileName[%s][%d]", szFileName, inResult);
	
		inResult = CTOS_FileOpen(szFileName , bStorageType , ulHandle);		
	    //glady-removelater
	    
			//add for read accum error
			if (inResult != 0)
				CTOS_Delay(200);
	    vdDebug_LogPrintf("[Glady-CTOS_FileOpen]--->>>result - %d", inResult);	
	    //glady-removelater
	
	}


	//glady-removelater
	vdDebug_LogPrintf("[Glady-CTOS_FileOpen after check file exist]--->>>result - %d", inResult);	
	//glady-removelater

    /* Open a file and return a number called a file handle. 
    * If the specified file name does not exist , it will be created first. */
    if(*ulHandle == 0x00)
    {        
        inResult = CTOS_FileOpen(szFileName , bStorageType , ulHandle);
       vdDebug_LogPrintf("[inMyFile_RecRead]---File Handle was 0x00, exe Open File, inResult[%04x]", inResult);
    }
    else
        inResult = d_OK;

    if (inResult == d_OK)
    {                                                                                       
        /* Move the file pointer to a specific position. 
        * Move backward from the end of the file.        */
        inResult = CTOS_FileSeek(*ulHandle ,inSeekCnt*ulRecSize, bSeekType);
        if (inResult != d_OK)
        {
            vdDebug_LogPrintf("[inMyFile_RecRead]---File Seek Fail,inResult[%04x]",inResult);
            CTOS_FileClose(*ulHandle);
            return ST_ERROR;                                                                        
        }
                                                                            
        /* Read data into the struct*/
        ulReadOutSize = ulRecSize;
        inResult = CTOS_FileRead(*ulHandle, byRec, &ulReadOutSize);
        if (inResult != d_OK)
        {
            vdDebug_LogPrintf("[inMyFile_RecRead]---File Read Fail,inResult[%04x]",inResult);            
            CTOS_FileClose(*ulHandle);
            return ST_ERROR; 
        }
        else if(ulReadOutSize != ulRecSize)
        {                        
            if(inMyFile_feof(*ulHandle))
            {
                vdDebug_LogPrintf("[inMyFile_RecRead]--- Read File at End Of File,ulReadOutSize[%d]recsize[%d]",ulReadOutSize, ulRecSize);
                return RC_FILE_READ_OUT_NO_DATA;
            }
            else
            {
                vdDebug_LogPrintf("[inMyFile_RecRead]---File Read Size[%d] != RecSize[%d]",ulReadOutSize, ulRecSize);
                CTOS_FileClose(*ulHandle);
                return ST_ERROR;    
            }                        
        }
        vdDebug_LogPrintf("[inMyFile_RecRead]---File Read Size[%d] != RecSize[%d]",ulReadOutSize, ulRecSize);                                                                                                                                                                                                                                       
        /* Close the opened file */
        if(strFile->fCloseFileNow)
        {
            if((inResult = CTOS_FileClose(*ulHandle)) != d_OK)
            {
                vdDebug_LogPrintf("[inMyFile_RecRead]---File close Fail ,inResult[%04x]",inResult);
                return ST_ERROR;
            }
            else
                *ulHandle = 0x00;
        }
    }
    else
    {
        vdDebug_LogPrintf("[inMyFile_RecRead]---File Open Fail ,inResult[%04x]",inResult);
        return ST_ERROR;
    }
    return ST_SUCCESS;    
}

/*==========================================================================================*
 *  Function Name : inMyFile_ContinueReadRec                                                *
 *  Description : in order to reduce I/O, fCloseFileNow set FALSE, file will not close auto *
 *  input parameter :                                                                       *
 *          [void *] :STRUCT_FILE_SETTING Variable pointer                                  *
 *   return:                                                                                *
 *          ST_SUCCESS ---> SUCCESS                                                               *
 *          ST_ERROR ---> Write Error
 *          RC_FILE_READ_OUT_NO_DATA --> Read File at end                                *
 *==========================================================================================*/
int inMyFile_ContinueReadRec(void *p1)
{
    STRUCT_FILE_SETTING *strFile = (STRUCT_FILE_SETTING*)p1;
    return (inMyFile_RecRead(strFile));    
}

/*==========================================================================================*
 *  Function Name : inMyFile_BatchSave                                                
 *  input parameter :                                                                       
 *          [TRANS_DATA_TABLE *] : TRANS_DATA_TABLE Variable pointer
 *          [int]                : method of stored batch
 *                                 DF_BATCH_APPEND or 
 *                                 DF_BATCH_UPDATE
 *   return:                                                                                
 *          ST_SUCCESS ---> SUCCESS
 *          ST_ERROR ---> Write Error
 *==========================================================================================*/
int inMyFile_BatchSave(TRANS_DATA_TABLE *transData, int inStoredType)
{
    int inResult;

	inResult = inDatabase_BatchSave(transData, inStoredType);

    return inResult; 

}

/*==========================================================================================*
 *  Function Name : inMyFile_BatchDelete                                                
 *  input parameter : None               
 *                  
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          Others ---> Save Error 
 *==========================================================================================*/
int inMyFile_BatchDelete(void)
{
    int inResult;
    
	inResult = inDatabase_BatchDelete();

    return inResult; 

}

/*==========================================================================================*
 *  Function Name : inMyFile_BatchRead                                                
 *  input parameter : 
 *          [TRANS_DATA_TABLE *] : TRANS_DATA_TABLE Variable pointer
 *          [int]                : index of batch, if caller input -1 means that wanted to get last batch recor
 *                  
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Read Error
 *          RC_FILE_READ_OUT_NO_DATA ---> Read File at end 
 *          RC_FILE_FILE_NOT_FOUND ---> file not existed
 *==========================================================================================*/
int inMyFile_BatchRead(TRANS_DATA_TABLE *transData, int inSeekCnt)
{
    STRUCT_FILE_SETTING strFile;
    int inResult;
    int inBatchFileSize;
    int inReadRecResult;

    if(inSeekCnt < 0)
    { 
        strFile.inSeekCnt = strHDT.ulLastTransSavedIndex;
    }
    else    
        strFile.inSeekCnt = inSeekCnt;

	inResult = inDatabase_BatchRead(transData, strFile.inSeekCnt);

    return inResult;

}

/*==========================================================================================*
 *  Function Name : inMyFile_BatchSearch                                                
 *  input parameter :                                                                       
 *          [TRANS_DATA_TABLE *] : TRANS_DATA_TABLE Variable pointer
 *          [char*]                : BCD Format Invoice Number
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Read Error
 *          RC_FILE_READ_OUT_NO_DATA --> Read File at end 
 *==========================================================================================*/
int inMyFile_BatchSearch(TRANS_DATA_TABLE *transData, char *hexInvoiceNo)
{
    int inResult;

	inResult = inDatabase_BatchSearch(transData, hexInvoiceNo);

    return inResult;

}


/*==========================================================================================*
 *  Function Name : inMyFile_ReversalSave                                                
 *  input parameter :                                                                       
 *          [BYTE *] : Saved Reversal data 
 *          [ULONG]  : Reversal Size
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Save Error 
 *==========================================================================================*/
int inMyFile_ReversalSave(BYTE *szReversal8583Data, ULONG ulReversalSize)
{
    STRUCT_FILE_SETTING strFile;
    int inResult;
    
    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));    
    
    sprintf(strFile.szFileName, "%s%02d%02d.rev"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    strFile.bSeekType           = d_SEEK_FROM_EOF;
    strFile.bStorageType        = d_STORAGE_FLASH ;
    strFile.fCloseFileNow       = TRUE;
    strFile.ulRecSize           = ulReversalSize;
    strFile.ptrRec              = szReversal8583Data;
    strFile.inSeekCnt           = 0;//fseek 0 from end of file    

    vdDebug_LogPrintf("Save reversal [%s]", strFile.szFileName);
    if((inResult = inMyFile_CheckFileExist(strFile.szFileName)) >= 0)
    {
        vdDebug_LogPrintf("[inMyFile_ReversalSave]---Reversal already existed, why??[%d]", inResult);
        return ST_SUCCESS;
    }
    
    if((inResult = inMyFile_RecSave(&strFile)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_ReversalSave]---Reversal Batch error[%04x]", inResult);
        return ST_ERROR;
    }        
    
    return ST_SUCCESS;
}

/*==========================================================================================*
 *  Function Name : inMyFile_ReversalRead                                                
 *  input parameter :                                                                       
 *          [BYTE *] : Reversal Buffer to save data from xxx.rev file 
 *          [ULONG]  : Reversal Buffer Max Size
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Read Error
 *          RC_FILE_FILE_NOT_FOUND---> file not existed
 *==========================================================================================*/
int inMyFile_ReversalRead(BYTE *szReadOutBuffer, ULONG ulReadOutBufferSize)
{
    STRUCT_FILE_SETTING strFile;
    int inResult;
    char szFileName[d_BUFF_SIZE];
    int  inFileSize; 
    
    memset(szFileName, 0x00, sizeof(szFileName));
    sprintf(szFileName, "%s%02d%02d.rev"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);    
    
    
    if((inFileSize = inMyFile_CheckFileExist(szFileName)) < 0)
    {
        return inFileSize;                     
    }
    else if(inFileSize > ulReadOutBufferSize)
    {
        return ST_ERROR;
    }
    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));    
    strcpy(strFile.szFileName, szFileName);    
    strFile.bSeekType           = d_SEEK_FROM_BEGINNING;
    strFile.bStorageType        = d_STORAGE_FLASH ;
    strFile.fCloseFileNow       = TRUE;
    strFile.ulRecSize           = inFileSize;
    strFile.ptrRec              = szReadOutBuffer;
    strFile.inSeekCnt           = 0;//fseek 0 from end of file    
    
    if((inResult = inMyFile_RecRead(&strFile)) == ST_ERROR)
    {
        return ST_ERROR;           
    }
    
    return ST_SUCCESS;
}

int inExceedMaxTimes_ReversalDelete(void)
{
    BYTE szFileName[32];
    int inResult;
   int inDelRevVal = strHDT.inDeleteREV;
    
    memset(szFileName, 0x00, sizeof(szFileName));    
    
    sprintf(szFileName, "%s%02d%02d.rev"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
	//version16-remove- fix for powerfail on reversal
	//strHDT.inReversalTries = 0;
	 if ((inDelRevVal > 99) || (inDelRevVal == 0)) 
      {
         inDelRevVal = 3;	
      }
	 
   if(strHDT.inFailedREV >= inDelRevVal) 
    {
	    inResult = CTOS_FileDelete(szFileName);
	    if(inResult != d_OK)
	    {
	        
			inHDTSave(strHDT.inHostIndex);
	        vdDebug_LogPrintf("[inMyFile_ReversalDeletete]---Delete Reversal error[%04x][%s]", inResult,szFileName);
	        return ST_ERROR;
	    }  
	    else
	    {
	    	strHDT.inFailedREV = 0;
			inDatabase_TerminalOpenDatabase();
			inHDTSaveFailedRev(strHDT.inHostIndex);
	        vdDebug_LogPrintf("deleted successfully [%04x][%s]strHDT.inDeleteREV[%d]", inResult,szFileName,strHDT.inDeleteREV);

			strMMT[0].fPendingReversal = FALSE;
			inMMTSaveEx(strMMT[0].MMTid);
            inDatabase_TerminalCloseDatabase();
	        return ST_SUCCESS;
	    }
    }
	else
	{
	
		inHDTSave(strHDT.inHostIndex);
		return ST_SUCCESS;
	}
}


/*==========================================================================================*
 *  Function Name : inMyFile_ReversalDeletete                                                
 *  input parameter : None               
 *                  
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          Others ---> Save Error 
 *==========================================================================================*/
int inMyFile_ReversalDelete(void)
{
    BYTE szFileName[32];
    int inResult;
    


	vdDebug_LogPrintf("delete reversal %d-%d", strMMT[0].MMTid, srTransRec.MITid);
	
    memset(szFileName, 0x00, sizeof(szFileName));    
    
    sprintf(szFileName, "%s%02d%02d.rev"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    inResult = CTOS_FileDelete(szFileName);
    if(inResult != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_ReversalDeletete]---Delete Reversal error[%04x][%s]", inResult,szFileName);
        return ST_ERROR;
    }  
    else
    {
        
		//issue509-reset reversal tries
		strHDT.inFailedREV = 0; 	
		inDatabase_TerminalOpenDatabase();
		inHDTSaveFailedRev(strHDT.inHostIndex);
		//issue509
        vdDebug_LogPrintf("deleted successfully [%04x][%s]", inResult,szFileName);
	
		strMMT[0].fPendingReversal = FALSE;
		inMMTSaveEx(strMMT[0].MMTid);
		inDatabase_TerminalCloseDatabase();
		
        return ST_SUCCESS;
    }
}


// for 00144 - Asterisk “*” is missing in Clear Reversal
BOOL isReversalFileExist(char* szFileName)
{ 
	BOOL isExist = FALSE; 
	int inResult = -1; 
	
	vdDebug_LogPrintf("--isReversalFileExist--"); 
	vdDebug_LogPrintf("szFileName=[%s]", szFileName); 
	
	inResult = inMyFile_CheckFileExist(szFileName); 
	if (inResult >= 0)  
		isExist = TRUE; 
	else  
		isExist = FALSE;   
	
return isExist;
}



/*==========================================================================================*
 *  Function Name : inMyFile_AdviceSave                                                
 *  input parameter :                                                                       
 *          [TRANS_DATA_TABLE *] : TRANS_DATA_TABLE pointer
 *          [ULONG]  : byTransType, advice transType 
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Save Error 
 *  Notes:  !!!!  caller must call inMyFile_BatchSave first   !!!
 *==========================================================================================*/
int inMyFile_AdviceSave(TRANS_DATA_TABLE *transData, BYTE byTransType)
{
    
    STRUCT_FILE_SETTING strFile;
    STRUCT_ADVICE   strAdvice;
    int inResult;
    
    
    
    memset(&strAdvice, 0x00, sizeof(STRUCT_ADVICE));
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    
    memcpy(strAdvice.szInvoiceNo, transData->szInvoiceNo, INVOICE_BCD_SIZE);
    strAdvice.ulBatchIndex = transData->ulSavedIndex;//the value will geted from batchSave
    strAdvice.byTransType = byTransType;
    
    sprintf(strFile.szFileName, "%s%02d%02d.adv"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    strFile.bSeekType           = d_SEEK_FROM_EOF;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = TRUE;
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
    strFile.ptrRec              = &strAdvice;
    strFile.inSeekCnt           = 0;//fseek 0 from end of file                               
    
    vdDebug_LogPrintf("[inMyFile_AdviceSave]---FileName[%s]", strFile.szFileName);
                                                           
    if((inResult = inMyFile_RecSave(&strFile)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_AdviceSave]---Advice Save error[%d]", inResult);
        return ST_ERROR;
    }        
    
    return ST_SUCCESS;
}

/*==========================================================================================*
 *  Function Name : inMyFile_AdviceUpdate                                                
 *  input parameter :                                                                       
 *          [int]  : inSeekCnt
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Save Error 
 *==========================================================================================*/
int inMyFile_AdviceUpdate(int inSeekCnt)
{
    STRUCT_FILE_SETTING strFile;
    STRUCT_ADVICE       strAdvice;
    STRUCT_ADVICE       strAdvCanceled;
    int inResult;
    int inReadRecResult;
    memset(&strAdvice, 0x00, sizeof(STRUCT_ADVICE));    
    memset(&strAdvCanceled, 0xFF, sizeof(STRUCT_ADVICE));
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    
    sprintf(strFile.szFileName, "%s%02d%02d.adv"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    strFile.bSeekType           = d_SEEK_FROM_BEGINNING;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = FALSE;//important step  
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
    strFile.ptrRec              = &strAdvice;
    
    inReadRecResult = ST_SUCCESS;
    /*if seekCnt = -1, search advice rec. by invoice No*/
    if(inSeekCnt == -1)
    {      
        
        do
        {
            inReadRecResult = inMyFile_ContinueReadRec(&strFile);
            if(memcmp(srTransRec.szInvoiceNo, strAdvice.szInvoiceNo, INVOICE_BCD_SIZE) != 0)
            {
                //got record
                vdDebug_LogPrintf("oh!!Ya!!, Got Advice Rec, Saved Index[%d] in adviceFile", strFile.inSeekCnt);                
                break;    
            }
            else
            {              
                strFile.inSeekCnt++;
            }        
        }while(inReadRecResult == ST_SUCCESS);
    }
    else
    {        
        strFile.inSeekCnt = inSeekCnt;
    }
    
    /*Read Rec. error*/
    if(inReadRecResult != ST_SUCCESS)
    {
        //close file by self, !!!importint step!!!
        if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
        {
            vdDebug_LogPrintf("[inMyFile_AdviceRead]---Close Advice File error2[%04x]", inResult);
            return ST_ERROR;
        }
        return inReadRecResult;            
    }        
        
    strFile.ptrRec = &strAdvCanceled;
    if((inResult = inMyFile_RecSave(&strFile)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_AdviceUpdate]---Update Advice Rec. error[%04x]", inResult);
        return ST_ERROR;
    }
    
    //close file by self, !!!importint step!!!
    if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_AdviceRead]---Close Advice File error[%d]", inResult);
        return ST_ERROR;
    }
    return  ST_SUCCESS;
}

/*==========================================================================================*
 *  Function Name : inMyFile_AdviceRead                                                
 *  input parameter :                                                                       
 *          [int *] : save index of advie rec. in file
 *          [STRUCT_ADVICE*]  : pointer
 *          [TRANS_DATA_TABLE*] : pointer 
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Read Error
 *          RC_FILE_READ_OUT_NO_DATA ---> no data exist
 *==========================================================================================*/
int inMyFile_AdviceRead(int *inSeekCnt, STRUCT_ADVICE *strAdvice, TRANS_DATA_TABLE *transData)
{       
    STRUCT_FILE_SETTING strFile;
    STRUCT_ADVICE       strSendFinish;
    int inResult;
    int inReadRecResult;
    
    *inSeekCnt = -1;
    memset(strAdvice, 0x00, sizeof(STRUCT_ADVICE));
    memset(&strSendFinish, 0xFF, sizeof(STRUCT_ADVICE));    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
        
    sprintf(strFile.szFileName, "%s%02d%02d.adv"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    strFile.bSeekType           = d_SEEK_FROM_BEGINNING;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = FALSE;//important step
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
    strFile.ptrRec              = strAdvice;
    strFile.inSeekCnt           = 0;//fseek 0 from end of file                               

    vdDebug_LogPrintf("[inMyFile_AdviceRead]--Filename[%s]", strFile.szFileName);

    if((inResult = inMyFile_CheckFileExist(strFile.szFileName)) < 0)
    {
        vdDebug_LogPrintf("[inMyFile_AdviceRead]---Advice File not existed");
        return RC_FILE_READ_OUT_NO_DATA;
    }

    do
    {
        inReadRecResult = inMyFile_ContinueReadRec(&strFile);
        if(memcmp(strAdvice, &strSendFinish, strFile.ulRecSize) != 0)
        {
            //got record
            vdDebug_LogPrintf("oh!!Ya!!, Got Advice Rec, Saved Index[%d] strAdvice->ulBatchIndex[%d]", strFile.inSeekCnt, strAdvice->ulBatchIndex);
            *inSeekCnt = strFile.inSeekCnt;
            break;    
        }
        else
        {              
            strFile.inSeekCnt++;
        }
        
    }while(inReadRecResult == d_OK);

    
    //close file by self, !!!importint step!!!
    if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_AdviceRead]---Close Advice File error[%d]", inResult);
        return ST_ERROR;
    }
    else if(inReadRecResult == RC_FILE_READ_OUT_NO_DATA)
    {
        vdDebug_LogPrintf("[inMyFile_AdviceRead]---Read Advice File at END, no advice needed to send, delete Advice File");
        CTOS_FileDelete(strFile.szFileName);
        return RC_FILE_READ_OUT_NO_DATA;
    }        
    else if(inReadRecResult != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_AdviceRead]---Read Advice File error[%d]", inReadRecResult);
        return ST_ERROR;
    }    
    else if(transData != 0x00)
    {	
		inResult = inDatabase_BatchRead(transData, strAdvice->ulBatchIndex);

        DebugAddHEX("transData->szInvoiceNo", transData->szInvoiceNo, 3);
        DebugAddHEX("strAdvice->szInvoiceNo", strAdvice->szInvoiceNo, 3);
        
        /*not Found Batch, set advice rec. to 0xFF */
        if(inResult == RC_FILE_READ_OUT_NO_DATA)
        {
            vdDebug_LogPrintf("[inMyFile_AdviceRead]---error, not found batch according Advice File");
            return inMyFile_AdviceUpdate(*inSeekCnt);                
        }
        else if(inResult != ST_SUCCESS)
        {
            vdDebug_LogPrintf("[inMyFile_AdviceRead]---Read Batch error[%d]", inResult);
            return inResult;
        }
        else if(memcmp(transData->szInvoiceNo, strAdvice->szInvoiceNo, INVOICE_BCD_SIZE) != 0)
        {
            vdDebug_LogPrintf("[inMyFile_AdviceRead]---batch InvoiceNo[%02x%02x%02x] != Advice InvoiceNo[%02x%02x%02x]"
                ,transData->szInvoiceNo[0]
                ,transData->szInvoiceNo[1]
                ,transData->szInvoiceNo[2]
                ,strAdvice->szInvoiceNo[0]
                ,strAdvice->szInvoiceNo[1]
                ,strAdvice->szInvoiceNo[2]);

            return ST_ERROR;
        }
    }        
    
    return ST_SUCCESS;                                               

}


/*==========================================================================================*
 *  Function Name : inMyFile_AdviceRead                                                
 *  input parameter :                                                                       
 *          [int *] : save index of advie rec. in file
 *          [STRUCT_ADVICE*]  : pointer
 *          [TRANS_DATA_TABLE*] : pointer 
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Read Error
 *          RC_FILE_READ_OUT_NO_DATA ---> no data exist
 *==========================================================================================*/
int inMyFile_AdviceReadByIndex(int inSeekCnt, STRUCT_ADVICE *strAdvice, TRANS_DATA_TABLE *transData)
{       
    STRUCT_FILE_SETTING strFile;
    STRUCT_ADVICE       strSendFinish;
    int inResult;
    int inReadRecResult;
    
    memset(strAdvice, 0x00, sizeof(STRUCT_ADVICE));
    memset(&strSendFinish, 0xFF, sizeof(STRUCT_ADVICE));    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
        
    sprintf(strFile.szFileName, "%s%02d%02d.adv"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    strFile.bSeekType           = d_SEEK_FROM_BEGINNING;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = FALSE;//important step
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
    strFile.ptrRec              = strAdvice;
    strFile.inSeekCnt           = inSeekCnt;//fseek by Index                          

    vdDebug_LogPrintf("[inMyFile_AdviceRead]--Filename[%s]", strFile.szFileName);

    if((inResult = inMyFile_CheckFileExist(strFile.szFileName)) < 0)
    {
        vdDebug_LogPrintf("[inMyFile_AdviceRead]---Advice File not existed");
        return RC_FILE_READ_OUT_NO_DATA;
    }


    inReadRecResult = inMyFile_ContinueReadRec(&strFile);
    if(memcmp(strAdvice, &strSendFinish, strFile.ulRecSize) != 0)
    {
        //got record
        vdDebug_LogPrintf("oh!!Ya!!, Got Advice Rec, Saved Index[%d] strAdvice->ulBatchIndex[%d]", strFile.inSeekCnt, strAdvice->ulBatchIndex);
    }
    else
    {              
        return RC_FILE_NOT_EXIST;
    }
        
    //close file by self, !!!importint step!!!
    if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_AdviceRead]---Close Advice File error[%d]", inResult);
        return ST_ERROR;
    }
    else if(inReadRecResult == RC_FILE_READ_OUT_NO_DATA)
    {
        vdDebug_LogPrintf("[inMyFile_AdviceRead]---Read Advice File at END, no advice needed to send, delete Advice File");
        //CTOS_FileDelete(strFile.szFileName);
        return RC_FILE_READ_OUT_NO_DATA;
    }        
    else if(inReadRecResult != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_AdviceRead]---Read Advice File error[%d]", inReadRecResult);
        return ST_ERROR;
    }    
    else if(transData != 0x00)
    {		
		inResult = inDatabase_BatchRead(transData, strAdvice->ulBatchIndex);

        DebugAddHEX("transData->szInvoiceNo", transData->szInvoiceNo, 3);
        DebugAddHEX("strAdvice->szInvoiceNo", strAdvice->szInvoiceNo, 3);
        
        /*not Found Batch, set advice rec. to 0xFF */
        if(inResult == RC_FILE_READ_OUT_NO_DATA)
        {
            vdDebug_LogPrintf("[inMyFile_AdviceRead]---error, not found batch according Advice File");
            return inMyFile_AdviceUpdate(inSeekCnt);                
        }
        else if(inResult != ST_SUCCESS)
        {
            vdDebug_LogPrintf("[inMyFile_AdviceRead]---Read Batch error[%d]", inResult);
            return inResult;
        }
        else if(memcmp(transData->szInvoiceNo, strAdvice->szInvoiceNo, INVOICE_BCD_SIZE) != 0)
        {
            vdDebug_LogPrintf("[inMyFile_AdviceRead]---batch InvoiceNo[%02x%02x%02x] != Advice InvoiceNo[%02x%02x%02x]"
                ,transData->szInvoiceNo[0]
                ,transData->szInvoiceNo[1]
                ,transData->szInvoiceNo[2]
                ,strAdvice->szInvoiceNo[0]
                ,strAdvice->szInvoiceNo[1]
                ,strAdvice->szInvoiceNo[2]);

            return ST_ERROR;
        }
    }        
    
    return ST_SUCCESS;                                               

}


int inMyFile_AdviceDelete(void)
{
    BYTE szFileName[32];
    int inResult;
    
    
    memset(szFileName, 0x00, sizeof(szFileName));    
    
    sprintf(szFileName, "%s%02d%02d.adv"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    inResult = CTOS_FileDelete(szFileName);
    if(inResult != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_AdviceDelete]---Delete Reversal error[%04x][%s]", inResult,szFileName);
        return ST_ERROR;
    }  
    else
    {
        vdDebug_LogPrintf("deleted Advice successfully [%04x][%s]", inResult,szFileName);
        return ST_SUCCESS;
    }
}



/*==========================================================================================*
 *  Function Name : inMyFile_TCUploadFileSave                                                
 *  input parameter :                                                                       
 *          [TRANS_DATA_TABLE *] : TRANS_DATA_TABLE pointer
 *          [ULONG]  : byTransType, advice transType 
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Save Error 
 *  Notes:  !!!!  caller must call inMyFile_BatchSave first   !!!
 *==========================================================================================*/
int inMyFile_TCUploadFileSave(TRANS_DATA_TABLE *transData, BYTE byTransType)
{
    
    STRUCT_FILE_SETTING strFile;
    STRUCT_ADVICE   strAdvice;
    int inResult;
    
    
    
    memset(&strAdvice, 0x00, sizeof(STRUCT_ADVICE));
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    
    memcpy(strAdvice.szInvoiceNo, transData->szInvoiceNo, INVOICE_BCD_SIZE);
    strAdvice.ulBatchIndex = transData->ulSavedIndex;//the value will geted from batchSave
    strAdvice.byTransType = byTransType;
	strAdvice.fDCCPreAuth = transData->fDCCAuth;
	
    sprintf(strFile.szFileName, "%s%02d%02d.tcf"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    strFile.bSeekType           = d_SEEK_FROM_EOF;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = TRUE;
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
    strFile.ptrRec              = &strAdvice;
    strFile.inSeekCnt           = 0;//fseek 0 from end of file                               
    
    vdDebug_LogPrintf("[inMyFile_TCUploadFileSave]---FileName[%s]", strFile.szFileName);
                                                           
    if((inResult = inMyFile_RecSave(&strFile)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileSave]---Advice Save error[%d]", inResult);
        return ST_ERROR;
    }        
    
    return ST_SUCCESS;
}

/*==========================================================================================*
 *  Function Name : inMyFile_TCUploadFileUpdate                                                
 *  input parameter :                                                                       
 *          [int]  : inSeekCnt
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Save Error 
 *==========================================================================================*/
int inMyFile_TCUploadFileUpdate(int inSeekCnt)
{
    STRUCT_FILE_SETTING strFile;
    STRUCT_ADVICE       strAdvice;
    STRUCT_ADVICE       strAdvCanceled;
    int inResult;
    int inReadRecResult;
    memset(&strAdvice, 0x00, sizeof(STRUCT_ADVICE));    
    memset(&strAdvCanceled, 0xFF, sizeof(STRUCT_ADVICE));
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    
    sprintf(strFile.szFileName, "%s%02d%02d.tcf"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    strFile.bSeekType           = d_SEEK_FROM_BEGINNING;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = FALSE;//important step  
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
    strFile.ptrRec              = &strAdvice;
    
    inReadRecResult = ST_SUCCESS;
    /*if seekCnt = -1, search advice rec. by invoice No*/
    if(inSeekCnt == -1)
    {      
        
        do
        {
            inReadRecResult = inMyFile_ContinueReadRec(&strFile);
            if(memcmp(srTransRec.szInvoiceNo, strAdvice.szInvoiceNo, INVOICE_BCD_SIZE) != 0)
            {
                //got record
                vdDebug_LogPrintf("oh!!Ya!!, Got TC Rec, Saved Index[%d] in adviceFile", strFile.inSeekCnt);                
                break;    
            }
            else
            {              
                strFile.inSeekCnt--;
            }        
        }while(inReadRecResult == ST_SUCCESS);
    }
    else
    {        
        strFile.inSeekCnt = inSeekCnt;
    }
    
    /*Read Rec. error*/
    if(inReadRecResult != ST_SUCCESS)
    {
        //close file by self, !!!importint step!!!
        if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
        {
            vdDebug_LogPrintf("[inMyFile_TCUploadFileUpdate]---Close Advice File error2[%04x]", inResult);
            return ST_ERROR;
        }
        return inReadRecResult;            
    }        
        
    strFile.ptrRec = &strAdvCanceled;
    if((inResult = inMyFile_RecSave(&strFile)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileUpdate]---Update Advice Rec. error[%04x]", inResult);
        return ST_ERROR;
    }
    
    //close file by self, !!!importint step!!!
    if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileUpdate]---Close Advice File error[%d]", inResult);
        return ST_ERROR;
    }
    return  ST_SUCCESS;
}


/*==========================================================================================*
 *  Function Name : inMyFile_TCUploadFileRead                                                
 *  input parameter :                                                                       
 *          [int *] : save index of advie rec. in file
 *          [STRUCT_ADVICE*]  : pointer
 *          [TRANS_DATA_TABLE*] : pointer 
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Read Error
 *          RC_FILE_READ_OUT_NO_DATA ---> no data exist
 *==========================================================================================*/
int inMyFile_TCUploadFileRead(int *inSeekCnt, STRUCT_ADVICE *strAdvice, TRANS_DATA_TABLE *transData)
{       
    STRUCT_FILE_SETTING strFile;
    STRUCT_ADVICE       strSendFinish;
    int inResult;
    int inReadRecResult;
	int inNumofRecord=0;
    
    *inSeekCnt = -1;
    memset(strAdvice, 0x00, sizeof(STRUCT_ADVICE));
    memset(&strSendFinish, 0xFF, sizeof(STRUCT_ADVICE));    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
        
    sprintf(strFile.szFileName, "%s%02d%02d.tcf"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);

	
	if((inResult = inMyFile_CheckFileExist(strFile.szFileName)) < 0)
   {
	   vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---Advice File not existed");
	   return RC_FILE_READ_OUT_NO_DATA;
   }

	inNumofRecord=inResult/sizeof(STRUCT_ADVICE);
	
    inNumofRecord--;
	
    strFile.bSeekType           = d_SEEK_FROM_BEGINNING;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = FALSE;//important step
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
    strFile.ptrRec              = strAdvice;
    //strFile.inSeekCnt           = 0;//fseek 0 from end of file                               
	strFile.inSeekCnt           = inNumofRecord;
	
    vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]--Filename[%s]", strFile.szFileName);
#if 0
    if((inResult = inMyFile_CheckFileExist(strFile.szFileName)) < 0)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---Advice File not existed");
        return RC_FILE_READ_OUT_NO_DATA;
    }
#endif
    do
    {
        inReadRecResult = inMyFile_ContinueReadRec(&strFile);
        if(memcmp(strAdvice, &strSendFinish, strFile.ulRecSize) != 0 && strAdvice->fDCCPreAuth == FALSE)
        {
            //got record
            vdDebug_LogPrintf("RECORD IS NOT DCC PREAUTH");
            vdDebug_LogPrintf("oh!!Ya!!, Got TC Rec, Saved Index[%d] strAdvice->ulBatchIndex[%d]", strFile.inSeekCnt, strAdvice->ulBatchIndex);
            *inSeekCnt = strFile.inSeekCnt;
            break;    
        }
        else
        {              
            strFile.inSeekCnt--;
        }
        
    }while(inReadRecResult == d_OK);

    
    //close file by self, !!!importint step!!!
    if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---Close Advice File error[%d]", inResult);
        return ST_ERROR;
    }
    else if(inReadRecResult == RC_FILE_READ_OUT_NO_DATA)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---Read Advice File at END, no advice needed to send, delete Advice File");
        CTOS_FileDelete(strFile.szFileName);
        return RC_FILE_READ_OUT_NO_DATA;
    }        
    else if(inReadRecResult != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---Read Advice File error[%d]", inReadRecResult);
        return ST_ERROR;
    }    
    else if(transData != 0x00)
    {
	
		inResult = inDatabase_BatchRead(transData, strAdvice->ulBatchIndex);

        DebugAddHEX("transData->szInvoiceNo", transData->szInvoiceNo, 3);
        DebugAddHEX("strAdvice->szInvoiceNo", strAdvice->szInvoiceNo, 3);
        
        /*not Found Batch, set advice rec. to 0xFF */
        if(inResult == RC_FILE_READ_OUT_NO_DATA)
        {
            vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---error, not found batch according Advice File");
            return inMyFile_AdviceUpdate(*inSeekCnt);                
        }
        else if(inResult != ST_SUCCESS)
        {
            vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---Read Batch error[%d]", inResult);
            return inResult;
        }
        else if(memcmp(transData->szInvoiceNo, strAdvice->szInvoiceNo, INVOICE_BCD_SIZE) != 0)
        {
            vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---batch InvoiceNo[%02x%02x%02x] != Advice InvoiceNo[%02x%02x%02x]"
                ,transData->szInvoiceNo[0]
                ,transData->szInvoiceNo[1]
                ,transData->szInvoiceNo[2]
                ,strAdvice->szInvoiceNo[0]
                ,strAdvice->szInvoiceNo[1]
                ,strAdvice->szInvoiceNo[2]);

            return ST_ERROR;
        }
    }        
    
    return ST_SUCCESS;                                               

}

int inMyFile_TCUploadDelete(void)
{
    BYTE szFileName[32];
    int inResult;
    
    
    memset(szFileName, 0x00, sizeof(szFileName));    
    
    sprintf(szFileName, "%s%02d%02d.tcf"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    inResult = CTOS_FileDelete(szFileName);
    if(inResult != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadDelete]---Delete Reversal error[%04x][%s]", inResult,szFileName);
        return ST_ERROR;
    }  
    else
    {
        vdDebug_LogPrintf("deleted TC successfully [%04x][%s]", inResult,szFileName);
        return ST_SUCCESS;
    }
}

int inMyFile_fgets(char*szBuffer, ULONG ulMaxOneLine, ULONG ulFileHandle)
{
    int inResult;
    int inOneLineReadSize;
    int inTempLen;
    int inDelimLen;
    ULONG ulFileCurrPos;
    ULONG ulReadSize;
    char szOutBuffer[ulMaxOneLine+1];
    char *delim = "\x0D\x0A";
    char *pch;
      
    /*Get Current file pointer position */
    inResult = CTOS_FileGetPosition(ulFileHandle, (ULONG*)&ulFileCurrPos);

    /*Read Out size of ulMaxOneLine string to szOutBuffer*/        
    ulReadSize = ulMaxOneLine;         
    memset(szOutBuffer, 0x00, sizeof(szOutBuffer));
    inResult |= CTOS_FileRead(ulFileHandle, szOutBuffer, &ulReadSize);
    
            
    /*parase '\n' and get oneLine size*/
    inDelimLen = strlen(delim);
   
    if(memcmp(szOutBuffer, delim, 2) == 0)
    {      
        inOneLineReadSize = 0;  
    }
    else
    {          
        pch = strtok(szOutBuffer,delim);
        inOneLineReadSize = strlen(pch);          
        memcpy(szBuffer, pch, inOneLineReadSize);        
    }
    /*move file pointer from beginning to current (position+oneLinSize)*/        
    inResult |= CTOS_FileSeek(ulFileHandle, (ulFileCurrPos + inOneLineReadSize + inDelimLen), d_SEEK_FROM_BEGINNING);
        
               
    ulFileCurrPos = 0;
    inResult |= CTOS_FileGetPosition(ulFileHandle, (ULONG*)&ulFileCurrPos);
            
    return inResult;    
}

BOOL inMyFile_feof(ULONG ulFileHandle)
{
    
    int inResult;
    ULONG ulEndOfPosition;
    ULONG ulCurrPosition;
    
     
    inResult = CTOS_FileGetPosition(ulFileHandle, (ULONG*)&ulCurrPosition);
    inResult |= CTOS_FileSeek(ulFileHandle, 0, d_SEEK_FROM_EOF);
    
    inResult |= CTOS_FileGetPosition(ulFileHandle, (ULONG*)&ulEndOfPosition);
    
    inResult |= CTOS_FileSeek(ulFileHandle, ulCurrPosition, d_SEEK_FROM_BEGINNING);
    
    
    if(ulCurrPosition < ulEndOfPosition)            
        return FALSE;        
    
    return TRUE;
    
        
    
}

int inMyFile_GetFileLine(ULONG ulFileHandle, char *szBuffer, int inMaxOneLine)
{
    int inNumRead;

    inNumRead = 0;
    memset( szBuffer, 0x00, inMaxOneLine);
    while(1)
    {
        memset( szBuffer, 0x00, inMaxOneLine);
        if(inMyFile_fgets((char*)szBuffer, inMaxOneLine, ulFileHandle) == d_OK)
        {          
            inNumRead = strlen(szBuffer);    
            if( inNumRead != 0 && memcmp(szBuffer, "//", 2) != 0)
            {
                return(inNumRead);
            }
        }
        else
        {
            break;
        }
    }    
    return( 0);    
}

/*==========================================================================================*
 *   Function Name : inMyFile_CheckFileExist                                                *
 *   input parameter :                                                                      *
 *          [char*] szFileName Name of file                                                 *
 *          return:                                                                         *
 *              RC_FILE_FILE_NOT_FOUND ---> file not existed                                      *                     *
 *              ulFileSize             ---> file existed, return file size
 *              ST_ERROR               ---> other error
 *==========================================================================================*/
int inMyFile_CheckFileExist(char *szFileName)
{
    ULONG ulFileSize = 0;
    ULONG ulHandle;
    USHORT usResult;
        
    usResult = CTOS_FileGetSize(szFileName, &ulFileSize);                         

    if (ulFileSize > 0 || usResult == d_OK)                                                      
        return ulFileSize;
    else if(usResult == d_FS_FILE_NOT_FOUND)
        return  RC_FILE_FILE_NOT_FOUND;         
																		  
    return ST_ERROR;
}

BOOL fGetString(BYTE *szInBuffer, BYTE *szOutBuffer, int inInBufferLen)
{
    if( (szInBuffer[0] != '"') || (szInBuffer[inInBufferLen-1] != '"'))
    {
        return( FALSE);
    }
    else if(szInBuffer[inInBufferLen-2] == 'h')/*ex: "000001h"*/
    {
        inAscii2Bcd(&szInBuffer[1], szOutBuffer, (inInBufferLen-3+1)/2);
    }
    else/*ex: "000001"*/
    {
        memcpy( szOutBuffer, &szInBuffer[1], inInBufferLen-2);
    }    
    return( TRUE);
}

BOOL fGetBoolean(BYTE *szInBuffer)
{
    if ((szInBuffer[0] == 'T')||(szInBuffer[0] == '1'))
    {        
        return( TRUE);
    }
    else if ((szInBuffer[0] == 'F')||(szInBuffer[0] == '0'))
    {        
        return( FALSE);
    }

    return( TRUE);
}


BOOL fGetNumber(BYTE *szInBuffer, void *szOutBuffer, int inInBufferLen)
{
    BYTE szBuffer[16];
    int inBin;
    char *ch1Byte;
    short *sh2Byte;
    int    *in4Byte;
    int i;
    
    if( inInBufferLen == 0)
    {
        return( FALSE);
    }
    
    
    for( i=0; i<inInBufferLen; i++)
    {
        if( i==0 && szInBuffer[i] == '-')
            continue;
        if( (szInBuffer[i] > '9' || szInBuffer[i] < '0'))
        {
            return( FALSE);
        }
    }
    
    memcpy(szBuffer, szInBuffer, inInBufferLen);
    *(int*)szOutBuffer = atoi(szBuffer);    
    return( TRUE);
}



int inMyFile_HDTTraceNoAdd(BYTE byHostIndex)
{
    int inResult;
    char szBcd[TRACE_NO_BCD_SIZE+1];
    
    vdDebug_LogPrintf("Inc trace byHostIndex[%d]", byHostIndex);
    memset(szBcd, 0x00, sizeof(szBcd));
    
    memcpy(szBcd, strHDT.szTraceNo, TRACE_NO_BCD_SIZE);    
    inBcdAddOne(szBcd, strHDT.szTraceNo, TRACE_NO_BCD_SIZE);

	
    //if((inResult = inHDTSave(byHostIndex)) != ST_SUCCESS)
    if((inResult = inHDTSaveTraceNo(byHostIndex)) != ST_SUCCESS)
    {
        vdDebug_LogPrintf("[inMyFile_HDTTraceNoAdd]---Save HDT error[%d]", inResult);
        return ST_ERROR;
    }
       
    return ST_SUCCESS;
}

void vdMyFile_TotalInit(STRUCT_FILE_SETTING *strFile, TRANS_TOTAL *strTotal)
{
    sprintf(strFile->szFileName, "ACC%02d%02d.total"
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    strFile->bSeekType           = d_SEEK_FROM_BEGINNING;
    strFile->bStorageType        = d_STORAGE_FLASH ;
    strFile->fCloseFileNow       = TRUE;
    strFile->ulRecSize           = sizeof(TRANS_TOTAL);
    strFile->ptrRec              = strTotal;    
    
}

int inMyFile_TotalRead(TRANS_TOTAL *strTotal)
{
    STRUCT_FILE_SETTING strFile;
    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    memset(strTotal, 0x00, sizeof(TRANS_TOTAL));
    
    vdMyFile_TotalInit(&strFile, strTotal);

    return (inMyFile_RecRead(&strFile));    
}

int inMyFile_TotalSave(TRANS_TOTAL *strTotal)
{
    STRUCT_FILE_SETTING strFile;
    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    
    vdMyFile_TotalInit(&strFile, strTotal);

    return (inMyFile_RecSave(&strFile));    
}

/*==========================================================================================*
 *  Function Name : inMyFile_TotalDelete                                                
 *  input parameter : None               
 *                  
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          Others ---> Save Error 
 *==========================================================================================*/
int inMyFile_TotalDelete(void)
{
    BYTE szFileName[32];
    int inResult;
    
    
    memset(szFileName, 0x00, sizeof(szFileName));    
    
    sprintf(szFileName, "ACC%02d%02d.total"
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                

    if((inResult = CTOS_FileDelete(szFileName)) != d_OK)
    {
        return ST_ERROR;
    }        
    
    return ST_SUCCESS;
}


/*==========================================================================================*
 *  Function Name : inMyFile_TransLogSave                                                
 *  input parameter :                                                                       
 *          [TRANS_DATA_TABLE *] : TRANS_DATA_TABLE pointer
 *          [ULONG]  : byTransType, advice transType 
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Save Error 
 *  Notes:  !!!!  caller must call inMyFile_BatchSave first   !!!
 *==========================================================================================*/
int inMyFile_TransLogSave(TRANS_DATA_TABLE *transData, BYTE byTransType)
{
    
    STRUCT_FILE_SETTING strFile;
    STRUCT_ADVICE   strAdvice;
    int inResult;
    
    
    
    memset(&strAdvice, 0x00, sizeof(STRUCT_ADVICE));
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    
    memcpy(strAdvice.szInvoiceNo, transData->szInvoiceNo, INVOICE_BCD_SIZE);
    strAdvice.ulBatchIndex = transData->ulSavedIndex;//the value will geted from batchSave
    strAdvice.byTransType = byTransType;
    strAdvice.inPacketType = DCC_LOGGING;
		
    sprintf(strFile.szFileName, "%s%02d%02d.log"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    strFile.bSeekType           = d_SEEK_FROM_EOF;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = TRUE;
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
    strFile.ptrRec              = &strAdvice;
    strFile.inSeekCnt           = 0;//fseek 0 from end of file                               
    
    vdDebug_LogPrintf("[inMyFile_TransLogSave]---FileName[%s]", strFile.szFileName);
                                                           
    if((inResult = inMyFile_RecSave(&strFile)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TransLogSave]---Advice Save error[%d]", inResult);
        return ST_ERROR;
    }        
    
    return ST_SUCCESS;
}



/*==========================================================================================*
 *  Function Name : inMyFile_TransLogUpdate                                                
 *  input parameter :                                                                       
 *          [int]  : inSeekCnt
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Save Error 
 *==========================================================================================*/
int inMyFile_TransLogUpdate(int inSeekCnt)
{
    STRUCT_FILE_SETTING strFile;
    STRUCT_ADVICE       strAdvice;
    STRUCT_ADVICE       strAdvCanceled;
    int inResult;
    int inReadRecResult;
    memset(&strAdvice, 0x00, sizeof(STRUCT_ADVICE));    
    memset(&strAdvCanceled, 0xFF, sizeof(STRUCT_ADVICE));
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    
    sprintf(strFile.szFileName, "%s%02d%02d.log"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    strFile.bSeekType           = d_SEEK_FROM_BEGINNING;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = FALSE;//important step  
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
    strFile.ptrRec              = &strAdvice;
    
    inReadRecResult = ST_SUCCESS;
    /*if seekCnt = -1, search advice rec. by invoice No*/
    if(inSeekCnt == -1)
    {      
        
        do
        {
            inReadRecResult = inMyFile_ContinueReadRec(&strFile);
            if(memcmp(srTransRec.szInvoiceNo, strAdvice.szInvoiceNo, INVOICE_BCD_SIZE) != 0)
            {
                //got record
                vdDebug_LogPrintf("inMyFile_TransLogUpdate oh!!Ya!!, Got Trans Log Rec, Saved Index[%d] in adviceFile", strFile.inSeekCnt);                
                break;    
            }
            else
            {              
                strFile.inSeekCnt++;
            }        
        }while(inReadRecResult == ST_SUCCESS);
    }
    else
    {        
        strFile.inSeekCnt = inSeekCnt;
    }
    
    /*Read Rec. error*/
    if(inReadRecResult != ST_SUCCESS)
    {
        //close file by self, !!!importint step!!!
        if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
        {
            vdDebug_LogPrintf("[inMyFile_AdviceRead]---Close Advice File error2[%04x]", inResult);
            return ST_ERROR;
        }
        return inReadRecResult;            
    }        
        
    strFile.ptrRec = &strAdvCanceled;
    if((inResult = inMyFile_RecSave(&strFile)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TransLogUpdate]---Update Advice Rec. error[%04x]", inResult);
        return ST_ERROR;
    }
    
    //close file by self, !!!importint step!!!
    if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TransLogUpdate]---Close Advice File error[%d]", inResult);
        return ST_ERROR;
    }
    return  ST_SUCCESS;
}

/*==========================================================================================*
 *  Function Name : inMyFile_TransLogRead                                                
 *  input parameter :                                                                       
 *          [int *] : save index of advie rec. in file
 *          [STRUCT_ADVICE*]  : pointer
 *          [TRANS_DATA_TABLE*] : pointer 
 *   return:                                                                                
 *          ST_SUCCESS ---> Success
 *          ST_ERROR ---> Read Error
 *          RC_FILE_READ_OUT_NO_DATA ---> no data exist
 *==========================================================================================*/
int inMyFile_TransLogRead(int *inSeekCnt, STRUCT_ADVICE *strAdvice, TRANS_DATA_TABLE *transData)
{       
    STRUCT_FILE_SETTING strFile;
    STRUCT_ADVICE       strSendFinish;
    int inResult;
    int inReadRecResult;
    int inNumofRecord=0;
		
    *inSeekCnt = -1;
    memset(strAdvice, 0x00, sizeof(STRUCT_ADVICE));
    memset(&strSendFinish, 0xFF, sizeof(STRUCT_ADVICE));    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
        
    sprintf(strFile.szFileName, "%s%02d%02d.log"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);

    if((inResult = inMyFile_CheckFileExist(strFile.szFileName)) < 0)
    {
        vdDebug_LogPrintf("[inMyFile_TransLogRead]---Advice File not existed");
        return RC_FILE_READ_OUT_NO_DATA;
    }

    inNumofRecord=inResult/sizeof(STRUCT_ADVICE);
	
    inNumofRecord--;
	
    strFile.bSeekType           = d_SEEK_FROM_BEGINNING;; //d_SEEK_FROM_BEGINNING;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = FALSE;//important step
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
    strFile.ptrRec              = strAdvice;
    strFile.inSeekCnt           = inNumofRecord;                               

    do
    {
        inReadRecResult = inMyFile_ContinueReadRec(&strFile);
        if(memcmp(strAdvice, &strSendFinish, strFile.ulRecSize) != 0)
        {
            //got record
            vdDebug_LogPrintf("inMyFile_TransLogRead oh!!Ya!!, Got Trans Log Rec, Saved Index[%d] strAdvice->ulBatchIndex[%d]", strFile.inSeekCnt, strAdvice->ulBatchIndex);
            *inSeekCnt = strFile.inSeekCnt;
            break;    
        }
        else
        {              
            strFile.inSeekCnt--;
        }
        
    }while(inReadRecResult == d_OK);

    
    //close file by self, !!!importint step!!!
    if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TransLogRead]---Close Advice File error[%d]", inResult);
        return ST_ERROR;
    }
    else if(inReadRecResult == RC_FILE_READ_OUT_NO_DATA)
    {
        vdDebug_LogPrintf("[inMyFile_TransLogRead]---Read Advice File at END, no advice needed to send, delete Advice File");
        CTOS_FileDelete(strFile.szFileName);
        return RC_FILE_READ_OUT_NO_DATA;
    }        
    else if(inReadRecResult != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TransLogRead]---Read Advice File error[%d]", inReadRecResult);
        return ST_ERROR;
    }    
    else if(transData != 0x00)
    {	
		inResult = inDatabase_BatchRead(transData, strAdvice->ulBatchIndex);

        DebugAddHEX("transData->szInvoiceNo", transData->szInvoiceNo, 3);
        DebugAddHEX("strAdvice->szInvoiceNo", strAdvice->szInvoiceNo, 3);
        
        /*not Found Batch, set advice rec. to 0xFF */
        if(inResult == RC_FILE_READ_OUT_NO_DATA)
        {
            vdDebug_LogPrintf("[inMyFile_TransLogRead]---error, not found batch according Advice File");
            return inMyFile_TransLogUpdate(*inSeekCnt);                
        }
        else if(inResult != ST_SUCCESS)
        {
            vdDebug_LogPrintf("[inMyFile_TransLogRead]---Read Batch error[%d]", inResult);
            return inResult;
        }
        else if(memcmp(transData->szInvoiceNo, strAdvice->szInvoiceNo, INVOICE_BCD_SIZE) != 0)
        {
            vdDebug_LogPrintf("[inMyFile_TransLogRead]---batch InvoiceNo[%02x%02x%02x] != Advice InvoiceNo[%02x%02x%02x]"
                ,transData->szInvoiceNo[0]
                ,transData->szInvoiceNo[1]
                ,transData->szInvoiceNo[2]
                ,strAdvice->szInvoiceNo[0]
                ,strAdvice->szInvoiceNo[1]
                ,strAdvice->szInvoiceNo[2]);

            return ST_ERROR;
        }
    }        
    
    return ST_SUCCESS;                                               

}


int inMyFile_TransLogDelete(void)
{
    BYTE szFileName[32];
    int inResult;
    
    
    memset(szFileName, 0x00, sizeof(szFileName));    
    
    sprintf(szFileName, "%s%02d%02d.log"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    inResult = CTOS_FileDelete(szFileName);
    if(inResult != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TransLogDelete]---Delete Reversal error[%04x][%s]", inResult,szFileName);
        return ST_ERROR;
    }  
    else
    {
        vdDebug_LogPrintf("deleted Trans Log successfully [%04x][%s]", inResult,szFileName);
        return ST_SUCCESS;
    }
}

int inMyFile_TransLogUpdatePacketType(int inSeekCnt, STRUCT_ADVICE strAdvice)
{
    STRUCT_FILE_SETTING strFile;
    int inResult;

	memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    sprintf(strFile.szFileName, "%s%02d%02d.log"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    strFile.bSeekType           = d_SEEK_FROM_BEGINNING;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = FALSE;//important step  
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
	strFile.inSeekCnt = inSeekCnt;
    strFile.ptrRec = &strAdvice;
	
    if((inResult = inMyFile_RecSave(&strFile)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TransLogUpdate]---Update Advice Rec. error[%04x]", inResult);
        return ST_ERROR;
    }
    
    //close file by self, !!!importint step!!!
    if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TransLogUpdate]---Close Advice File error[%d]", inResult);
        return ST_ERROR;
    }
    return  ST_SUCCESS;
}


int inMyFile_DCCPreAuthTCUploadFileRead(int *inSeekCnt, STRUCT_ADVICE *strAdvice, TRANS_DATA_TABLE *transData)
{       
    STRUCT_FILE_SETTING strFile;
    STRUCT_ADVICE       strSendFinish;
    int inResult;
    int inReadRecResult;
	int inNumofRecord=0;
    
    *inSeekCnt = -1;
    memset(strAdvice, 0x00, sizeof(STRUCT_ADVICE));
    memset(&strSendFinish, 0xFF, sizeof(STRUCT_ADVICE));    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
        
    sprintf(strFile.szFileName, "%s%02d%02d.tcf"
                                , "BDO"
                                , 1
                                , srTransRec.MITid);

	
	if((inResult = inMyFile_CheckFileExist(strFile.szFileName)) < 0)
   {
	   vdDebug_LogPrintf("[inMyFile_DCCPreAuthTCUploadFileRead]---Advice File not existed");
	   return RC_FILE_READ_OUT_NO_DATA;
   }

	inNumofRecord=inResult/sizeof(STRUCT_ADVICE);
	
    inNumofRecord--;
	
    strFile.bSeekType           = d_SEEK_FROM_BEGINNING;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = FALSE;//important step
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
    strFile.ptrRec              = strAdvice;
    //strFile.inSeekCnt           = 0;//fseek 0 from end of file                               
	strFile.inSeekCnt           = inNumofRecord;
	
    vdDebug_LogPrintf("[inMyFile_DCCPreAuthTCUploadFileRead]--Filename[%s]", strFile.szFileName);
#if 0
    if((inResult = inMyFile_CheckFileExist(strFile.szFileName)) < 0)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---Advice File not existed");
        return RC_FILE_READ_OUT_NO_DATA;
    }
#endif
    do
    {
        inReadRecResult = inMyFile_ContinueReadRec(&strFile);
        if(memcmp(strAdvice, &strSendFinish, strFile.ulRecSize) != 0 && strAdvice->fDCCPreAuth == TRUE)//Skip record that is not DCC sending PreAuth TC Upload before settlement.
        {	
            //got record
            vdDebug_LogPrintf("RECORD IS DCC PREAUTH");
            vdDebug_LogPrintf("oh!!Ya!!, Got TC Rec, Saved Index[%d] strAdvice->ulBatchIndex[%d]", strFile.inSeekCnt, strAdvice->ulBatchIndex);
            *inSeekCnt = strFile.inSeekCnt;
            break;    
        }
        else
        {              
            strFile.inSeekCnt--;
        }
        
    }while(inReadRecResult == d_OK);

    
    //close file by self, !!!importint step!!!
    if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---Close Advice File error[%d]", inResult);
        return ST_ERROR;
    }
    else if(inReadRecResult == RC_FILE_READ_OUT_NO_DATA)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---Read Advice File at END, no advice needed to send, delete Advice File");
        CTOS_FileDelete(strFile.szFileName);
        return RC_FILE_READ_OUT_NO_DATA;
    }        
    else if(inReadRecResult != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---Read Advice File error[%d]", inReadRecResult);
        return ST_ERROR;
    }    
    else if(transData != 0x00)
    {
	
		inResult = inDatabase_BatchRead(transData, strAdvice->ulBatchIndex);

        DebugAddHEX("transData->szInvoiceNo", transData->szInvoiceNo, 3);
        DebugAddHEX("strAdvice->szInvoiceNo", strAdvice->szInvoiceNo, 3);
        
        /*not Found Batch, set advice rec. to 0xFF */
        if(inResult == RC_FILE_READ_OUT_NO_DATA)
        {
            vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---error, not found batch according Advice File");
            return inMyFile_AdviceUpdate(*inSeekCnt);                
        }
        else if(inResult != ST_SUCCESS)
        {
            vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---Read Batch error[%d]", inResult);
            return inResult;
        }
        else if(memcmp(transData->szInvoiceNo, strAdvice->szInvoiceNo, INVOICE_BCD_SIZE) != 0)
        {
            vdDebug_LogPrintf("[inMyFile_TCUploadFileRead]---batch InvoiceNo[%02x%02x%02x] != Advice InvoiceNo[%02x%02x%02x]"
                ,transData->szInvoiceNo[0]
                ,transData->szInvoiceNo[1]
                ,transData->szInvoiceNo[2]
                ,strAdvice->szInvoiceNo[0]
                ,strAdvice->szInvoiceNo[1]
                ,strAdvice->szInvoiceNo[2]);

            return ST_ERROR;
        }
    }        
    
    return ST_SUCCESS;                                               

}

int inMyFile_DCCPreAuthTCUploadFileUpdate(int inSeekCnt)
{
    STRUCT_FILE_SETTING strFile;
    STRUCT_ADVICE       strAdvice;
    STRUCT_ADVICE       strAdvCanceled;
    int inResult;
    int inReadRecResult;
    memset(&strAdvice, 0x00, sizeof(STRUCT_ADVICE));    
    memset(&strAdvCanceled, 0xFF, sizeof(STRUCT_ADVICE));
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    
    sprintf(strFile.szFileName, "%s%02d%02d.tcf"
                                , "BDO"
                                , 1
                                , srTransRec.MITid);
                                
    strFile.bSeekType           = d_SEEK_FROM_BEGINNING;
    strFile.bStorageType        = d_STORAGE_FLASH;
    strFile.fCloseFileNow       = FALSE;//important step  
    strFile.ulRecSize           = sizeof(STRUCT_ADVICE);
    strFile.ptrRec              = &strAdvice;
    
    inReadRecResult = ST_SUCCESS;
    /*if seekCnt = -1, search advice rec. by invoice No*/
    if(inSeekCnt == -1)
    {      
        
        do
        {
            inReadRecResult = inMyFile_ContinueReadRec(&strFile);
            if(memcmp(srTransRec.szInvoiceNo, strAdvice.szInvoiceNo, INVOICE_BCD_SIZE) != 0)
            {
                //got record
                vdDebug_LogPrintf("oh!!Ya!!, Got TC Rec, Saved Index[%d] in adviceFile", strFile.inSeekCnt);                
                break;    
            }
            else
            {              
                strFile.inSeekCnt--;
            }        
        }while(inReadRecResult == ST_SUCCESS);
    }
    else
    {        
        strFile.inSeekCnt = inSeekCnt;
    }
    
    /*Read Rec. error*/
    if(inReadRecResult != ST_SUCCESS)
    {
        //close file by self, !!!importint step!!!
        if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
        {
            vdDebug_LogPrintf("[inMyFile_TCUploadFileUpdate]---Close Advice File error2[%04x]", inResult);
            return ST_ERROR;
        }
        return inReadRecResult;            
    }        
        
    strFile.ptrRec = &strAdvCanceled;
    if((inResult = inMyFile_RecSave(&strFile)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileUpdate]---Update Advice Rec. error[%04x]", inResult);
        return ST_ERROR;
    }
    
    //close file by self, !!!importint step!!!
    if((inResult = CTOS_FileClose(strFile.ulHandle)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_TCUploadFileUpdate]---Close Advice File error[%d]", inResult);
        return ST_ERROR;
    }
    return  ST_SUCCESS;
}

int inMyFile_ReversalDelete2(void)
{
    BYTE szFileName[32];
    int inResult;
    
    
    memset(szFileName, 0x00, sizeof(szFileName));    
    
    sprintf(szFileName, "%s%02d%02d.rev"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    inResult = CTOS_FileDelete(szFileName);
    if(inResult != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_ReversalDeletete]---Delete Reversal error[%04x][%s]", inResult,szFileName);
        return ST_ERROR;
    }  
    else
    {
        vdDebug_LogPrintf("deleted successfully [%04x][%s]", inResult,szFileName);
        return ST_SUCCESS;
    }
}


/*the file access functions to save & read data by record in self group.
currentlly use for TMS only, for update & delect record need to be test*/
int inCheckFileExist(const char *szFileName)
{
	FILE *pFile = NULL;
	int inSize = 0;
	
	pFile = fopen(szFileName, "rb+");
	if (pFile == NULL)
		return d_NO;
	
	fseek(pFile, 0, SEEK_END);
	inSize=ftell(pFile);
	fclose(pFile);
	
	if (inSize>0)
		return d_OK;
	else
		return d_NO;
	
}

int inCheckFileExistReturnSIze(const char *szFileName)
{
	FILE *pFile = NULL;
	int inSize = 0;
	
	pFile = fopen(szFileName, "rb+");
	if (pFile == NULL)
		return d_NO;
	
	fseek(pFile, 0, SEEK_END);
	inSize=ftell(pFile);
	fclose(pFile);
	
	if (inSize>0)
		return inSize;
	else
		return d_NO;
	
}


/*-------------------------------------------------------------------------
	@func int | inGetNumberOfConfRecs | Gets number of <p inRecSize> sized records within the Gendata file <p szFileName>
	@parm char * | szFileName | Name of file to query
	@parm int | inRecSize | Size of each record in file
	@rdesc Returns the number of records in the file
	@end
--------------------------------------------------------------------------*/
int inGetNumberOfConfRecs (char *szFileName, int inRecSize)
{
	long lnSize;
        
        FILE  *fPubKey;
	long curpos,length;

	vdDebug_LogPrintf("inGetNumberOfConfRecs[%s]", szFileName);
	fPubKey = fopen( (char*)szFileName, "rb" );
	if(fPubKey == NULL)
		return -1;

	curpos=ftell(fPubKey);
	fseek(fPubKey,0L,SEEK_END);
	lnSize=ftell(fPubKey);
	fseek(fPubKey,curpos,SEEK_SET);

	fclose(fPubKey);

	//lnSize = lnGetFileSize(szFileName);
	return((int) (lnSize / inRecSize));
}

/*-------------------------------------------------------------------------
    Function:		inLoadConfRec
    Description:	Loads a record from a given table
    Parameters:		char *, int, int, char *
    Returns:		d_NO, d_OK
	Notes:
--------------------------------------------------------------------------*/
int inLoadConfRec (const char *szFileName, int inRecSize, int inRecNum, char *pchConfRec)
{
	int inResult;
	FILE *phConfFHandle = NULL;
	long lnSeekResult, lnOffset;

	phConfFHandle = fopen(szFileName, "rb+");

	if (phConfFHandle == NULL)
	{
		vdDebug_LogPrintf("Invalid index given");
		return (d_NO);
	}

	
	lnOffset = (long) (((long) inRecNum * (long) inRecSize));
	lnSeekResult = fseek(phConfFHandle, lnOffset, SEEK_SET);
	vdDebug_LogPrintf("fseek [%d]", lnSeekResult);
	#if 0
	if (lnSeekResult != lnOffset)  /* Invalid index given, return d_NO */
	{
		vdDebug_LogPrintf("Invalid index given");
		fclose(phConfFHandle);
		return (d_NO);
	}
	#endif

	inResult = fread(pchConfRec, inRecSize, 1, phConfFHandle);
	vdDebug_LogPrintf("fread [%d]", inResult);
	if (inResult == 0L)          /* End of file reached, invalid index  */
	{
		vdDebug_LogPrintf("End of file reached");
		fclose(phConfFHandle);
		return (d_NO);
	}

	fclose(phConfFHandle);

	return(d_OK);
}

int inRemoveConfRecFile(char *szFileName)
{
	if (NULL != szFileName)
		remove(szFileName);

	return d_OK;
}

/*-------------------------------------------------------------------------
	@func int | inAppendConfRec | Saves contents of specified record to end of file
	@parm char * | szFileName | Name of file to append to
	@parm int | inRecSize | Size of each record in file
	@parm char * | pchConfRec | Pointer to location to read the record data from
	@rdesc Returns VS_SUCCESS of VS_ERR
	@end
--------------------------------------------------------------------------*/

int inAppendConfRec (char *szFileName, int inRecSize, char *pchConfRec)
{
	int inResult = d_NO;
	FILE *phConfFHandle = NULL;

	if ((phConfFHandle = fopen(szFileName, "ab+")) != NULL)
	{
		/* Seek to the end of the file */
		#if 0
		if (fseek(phConfFHandle, 0L, SEEK_END) >= 0)
			if (fwrite(pchConfRec, inRecSize, 1, phConfFHandle) == 1)
				inResult = d_OK;
		#endif
		#if 1
		//inResult = fseek(phConfFHandle, 0L, SEEK_END);
		inResult = fwrite(pchConfRec, inRecSize, 1, phConfFHandle);
		fflush(phConfFHandle);
		fclose(phConfFHandle);
		if(inResult == 1)
			inResult = d_OK;
		#endif
	}
	vdDebug_LogPrintf("inAppendConfRec [%d]", inResult);
	return(inResult);
}


int inExceedMaxTimes_ReversalDelete2(void)
{
    BYTE szFileName[32];
    int inResult;
   int inDelRevVal = strHDT.inDeleteREV;
    int inTotalTries = 0;
    
    memset(szFileName, 0x00, sizeof(szFileName));    
    
    sprintf(szFileName, "%s%02d%02d.rev"
                                , strHDT.szHostLabel
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
	//version16-remove
	//strHDT.inFailedREV++;
	//strHDT.inFailedREV = strHDT.inReversalTries++;
	//strHDT.inReversalTries = 0;
	 if ((inDelRevVal > 99) || (inDelRevVal == 0)) 
      {
         inDelRevVal = 3;	
      }

    //inTotalTries = strHDT.inReversalTries+strHDT.inFailedREV;
	 
   //if(strHDT.inReversalTries > inDelRevVal) 
    if(strHDT.inFailedREV > inDelRevVal) 

    {
	    inResult = CTOS_FileDelete(szFileName);
	    if(inResult != d_OK)
	    {
	        
			inHDTSave(strHDT.inHostIndex);
	        vdDebug_LogPrintf("[inMyFile_ReversalDeletete]---Delete Reversal error[%04x][%s]", inResult,szFileName);
	        return ST_ERROR;
	    }  
	    else
	    {
	    	strHDT.inFailedREV = 0;
			inDatabase_TerminalOpenDatabase();
			inHDTSaveFailedRev(strHDT.inHostIndex);
	        vdDebug_LogPrintf("deleted successfully [%04x][%s]strHDT.inDeleteREV[%d]", inResult,szFileName,strHDT.inDeleteREV);

			strMMT[0].fPendingReversal = FALSE;
			inMMTSaveEx(strMMT[0].MMTid);
            inDatabase_TerminalCloseDatabase();
	        return ST_SUCCESS;
	    }
    }
	else
	{
	
		inHDTSave(strHDT.inHostIndex);
		return ST_SEND_REVERSAL;
	}
}

