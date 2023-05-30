/* 
 * File:   display.h
 * Author: 
 *
 * Created on 2014
 */

#ifndef ___CTOS_CFGEXPRESS_H___
#define	___CTOS_CFGEXPRESS_H___

#ifdef	__cplusplus
extern "C" {
#endif

//#define PUBLIC_PATH 				"./home/ap/pub/"
#define PUBLIC_PATH 				"/home/ap/pub/"
#define LOCAL_PATH 					"./fs_data/"

#define DATABASE_FILE_EXT 			".S3DB"
#define CASTLES_CONFIG_FILE			"parameter.prm"
    
#define CFG_ENV_FILE_EXT			"ENV.TXT"
#define CFG_ENV_BAK_FILE_EXT		"ENVBAK.TXT"
#define UNFORK_AP_FILE			"unforkap.ini"

#define DB_ENV_CFG 					"/home/ap/pub/ENV.S3DB"


typedef char DataBaseName[50+1];
typedef char TableName[50+1];
typedef char FieldData[50+1];
typedef char FieldName[50+1];
typedef char RecordNum[50+1];

int inCTOSS_ProcessCfgExpress(void);

int inCTOSS_EnvTotal(void);
int inCTOSS_GetEnvByIdx(int idx, char *tag, char *value);
int inCTOSS_GetEnvIdx(char *tag, int *idx);

int inCTOSS_GetEnv(char *tag, char *value);
int inCTOSS_PutEnv(char *tag, char *value);
int inCTOSS_DelEnv(char *tag);


int inCTOSS_EnvTotalDB(void);
int inCTOSS_GetEnvByIdxDB(int idx, char *tag, char *value);
int inCTOSS_GetEnvIdxDB(char *tag, int *idx);

int inCTOSS_GetEnvDB(char *tag, char *value);
int inCTOSS_PutEnvDB(char *tag, char *value);
int inCTOSS_DelEnvDB(char *tag);



#ifdef	__cplusplus
}
#endif

#endif	/* ___CTOS_CFGEXPRESS_H___ */

