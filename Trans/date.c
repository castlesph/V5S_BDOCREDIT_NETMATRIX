//#include "date.h"
#include <stdio.h>
#include <string.h>


#include "..\Includes\date.h"
#define M1 31  
#define M2 28  
#define M2_LEAP 29  
#define M3 31
#define M4 30
#define M5 31
#define M6 30
#define M7 31
#define M8 31
#define M9 30
#define M10 31
#define M11 30
#define M12 31

#define YEAR 365   
#define YEAR_LEAP 366   
int getRestdays(myDate *date);
int getDays(  myDate *date);
myDate newDate(  myDate *today, int d);
int isEqual(  myDate *date1,   myDate *date2);


static int preDays(int m){
	if(m == 1)
		return 0;
	else if(m == 2)
		return M1;  
	else if(m == 3)
		return M1+M2;
	else if(m == 4)
		return M1+M2+M3;
	else if(m == 5)
		return M1+M2+M3+M4;
	else if(m == 6)
		return M1+M2+M3+M4+M5;
	else if(m == 7)
		return M1+M2+M3+M4+M5+M6;
	else if(m == 8)
		return M1+M2+M3+M4+M5+M6+M7;
	else if(m == 9)
		return M1+M2+M3+M4+M5+M6+M7+M8;
	else if(m == 10)
		return M1+M2+M3+M4+M5+M6+M7+M8+M9;
	else if(m == 11)
		return M1+M2+M3+M4+M5+M6+M7+M8+M9+M10;
	else
		return M1+M2+M3+M4+M5+M6+M7+M8+M9+M10+M11;
}

int isLegal(int y, int m, int d){
	if(y < 0)
		return 0;
	switch(m){
		case 1:
		case 3:
		case 5:
		case 7:
		case 8:
		case 10:
		case 12:
			if(d < 1 || d > M1) return 0;
			break;
		case 4:
		case 6:
		case 9:
		case 11:
			if(d < 1 || d > M4) return 0;
			break;
		case 2:
			if((y % 400 == 0 ) || (y % 4 == 0 && y % 100 != 0)){
				if(d < 1 || d > M2_LEAP) return 0;
			}else{
				if(d < 1 || d > M2) return 0;
			}
			break;
		default:
			return 0;
	}
	return 1;
}

static myDate getBaseyear(myDate *date1, myDate *date2){
	if((*date1).year != (*date2).year){
		if((*date1).year < (*date2).year)
			return (*date1);
		else 
			return (*date2);
	}
	else{
		if((*date1).month != (*date2).month){
			if((*date1).month < (*date2).month)
				return (*date1);
			else 
				return (*date2);
		}
		else{
			if((*date1).day < (*date2).day)
				return (*date1);
			else 
				return (*date2);
		}
	}
}

int getDateToBase(myDate *date1, myDate *date2){
	int days = 0, i;
	myDate d2 = getBaseyear(date1,date2);
	myDate d1;
	if((*date1).year == d2.year && (*date1).month == d2.month && (*date1).day == d2.day){
		d1.year = (*date2).year;
		d1.month = (*date2).month;
		d1.day = (*date2).day;
		
	}
	else{
		d1.year = (*date1).year;
		d1.month = (*date1).month;
		d1.day = (*date1).day;
	}
	if(d1.year == d2.year){
		days = d1.day - d2.day;
	}
	else if(d1.year - d2.year == 1){
		days = getDays(&d1) + getRestdays(&d2);
	}
	else{
		for(i = d2.year + 1; i < d1.year; i++){
			if(isLeapyear(i))
				days = days + YEAR_LEAP;
			else 
				days = days + YEAR;
		}
		days = days + getRestdays(&d2) + getDays(&d1);
	}
	return days;
}

/*
��������baseDate d ���ǰ��������
*/
myDate getNewDate(  myDate *baseDate, int d){
	myDate tmpDate;
	int gapDays;
	if(d >= 0)
		return newDate(baseDate, d);
	else{
		d = -d;
		tmpDate.year = (*baseDate).year - d/YEAR_LEAP - 1;
		tmpDate.month = (*baseDate).month;
		tmpDate.day = (*baseDate).month;
		gapDays = getDateToBase(baseDate, &tmpDate) - d;  //�����������ھ���tmpDate������
		return newDate(&tmpDate, gapDays);  //gapDays >= 0, ����newDate()������������
	}
} 

/*
����·ݺ�������������ڽ����ѹ������
*/
int getDays(myDate *date){
	int day = (*date).day;
	int leapyear = isLeapyear((*date).year); //�жϵ����Ƿ�Ϊ����
	int days = 0;
	//ƽ�����
	days = preDays((*date).month) + day;
	//����
	if(leapyear && (*date).month > 2)
		days++;
	return days;
}

/*
����·ݺ�������������ڽ��껹ʣ������
*/
int getRestdays(  myDate *date){
	int leapyear = isLeapyear((*date).year);
	int restdays;
	if(leapyear)
		restdays = YEAR_LEAP - getDays(date);
	else
		restdays = YEAR - getDays(date);
    return restdays;
}

//�ж��Ƿ������꣬���򷵻���
int isLeapyear(int y){
	if((y % 400 == 0 ) || (y % 4 == 0 && y % 100 != 0))
		return 1;
	else return 0;
}

//����d�������ڣ�d>0
myDate newDate(  myDate *today, int d){
	int pastdays = getDays(today);	//today���ѹ������
	int gapDays = pastdays + d;  //���������today֮�������
	  myDate newdate;
	newdate.year = (*today).year;
	newdate.month = 1;
	newdate.day = 1;
	if(d == 0)
		return (*today);
	else{
		while(gapDays > getRestdays(&newdate) + 1){
			gapDays = gapDays - getRestdays(&newdate) - 1;
			newdate.year++;
			newdate.month = 1;
			newdate.day = 1;
		}
		//��Ϊ����
		if(isLeapyear(newdate.year)){
			if(gapDays <= preDays(2)){
				newdate.month = 1;
				newdate.day = gapDays;
			}
			else if(gapDays <= (preDays(3)+1)){
				newdate.month = 2;
				newdate.day = gapDays - preDays(2);
			}
			else if(gapDays <= (preDays(4)+1)){
				newdate.month = 3;
				newdate.day = gapDays - preDays(3) - 1;
			}
			else if(gapDays <= (preDays(5)+1)){
				newdate.month = 4;
				newdate.day = gapDays - preDays(4) - 1;
			}
			else if(gapDays <= (preDays(6)+1)){
				newdate.month = 5;
				newdate.day = gapDays - preDays(5) - 1;
			}
			else if(gapDays <= (preDays(7)+1)){
				newdate.month = 6;
				newdate.day = gapDays - preDays(6) - 1;
			}
			else if(gapDays <= (preDays(8)+1)){
				newdate.month = 7;
				newdate.day = gapDays - preDays(7) - 1;
			}
			else if(gapDays <= (preDays(9)+1)){
				newdate.month = 8;
				newdate.day = gapDays - preDays(8) - 1;
			}
			else if(gapDays <= (preDays(10)+1)){
				newdate.month = 9;
				newdate.day = gapDays - preDays(9) - 1;
			}
			else if(gapDays <= (preDays(11)+1)){
				newdate.month = 10;
				newdate.day = gapDays - preDays(10) - 1;
			}
			else if(gapDays <= (preDays(12)+1)){
				newdate.month = 11;
				newdate.day = gapDays - preDays(11) - 1;
			}
			else{
				newdate.month = 12;
				newdate.day = gapDays - preDays(12) - 1;
			}
		}
		//ƽ��
		else{
			if(gapDays <= preDays(2)){
				newdate.month = 1;
				newdate.day = gapDays;
			}
			else if(gapDays <= preDays(3)){
				newdate.month = 2;
				newdate.day = gapDays - preDays(2);
			}
			else if(gapDays <= preDays(4)){
				newdate.month = 3;
				newdate.day = gapDays - preDays(3);
			}
			else if(gapDays <= preDays(5)){
				newdate.month = 4;
				newdate.day = gapDays - preDays(4);
			}
			else if(gapDays <= preDays(6)){
				newdate.month = 5;
				newdate.day = gapDays - preDays(5);
			}
			else if(gapDays <= preDays(7)){
				newdate.month = 6;
				newdate.day = gapDays - preDays(6);
			}
			else if(gapDays <= preDays(8)){
				newdate.month = 7;
				newdate.day = gapDays - preDays(7);
			}
			else if(gapDays <= preDays(9)){
				newdate.month = 8;
				newdate.day = gapDays - preDays(8);
			}
			else if(gapDays <= preDays(10)){
				newdate.month = 9;
				newdate.day = gapDays - preDays(9);
			}
			else if(gapDays <= preDays(11)){
				newdate.month = 10;
				newdate.day = gapDays - preDays(10);
			}
			else if(gapDays <= preDays(12)){
				newdate.month = 11;
				newdate.day = gapDays - preDays(11);
			}
			else{
				newdate.month = 12;
				newdate.day = gapDays - preDays(12);
			}
		}
	}
	return newdate;
}

/*
�ж��������Ƿ���ͬ
*/
int isEqual(  myDate *date1,   myDate *date2){
	if((*date1).year == (*date2).year && (*date1).month == (*date2).month && (*date1).day == (*date2).day)
		return 1;
	else return 0;
}  

int inIsBeforeOperationEndTime(CTOS_RTC rtc, const char *szOperationEndTime)
{
    char szTime[6+1];
    
    sprintf(szTime, "%02d%02d%02d", rtc.bHour, rtc.bMinute, rtc.bSecond);
    if (strncmp(szTime, szOperationEndTime, 6) <= 0) 
        return TRUE;
    
    return FALSE;
}

void vdGetBusinessDate(CTOS_RTC rtc, const char *szOperationEndTime, char *pszBusinessDate)
{

    if (inIsBeforeOperationEndTime(rtc, szOperationEndTime))
    {
        myDate baseDate;
        baseDate.year = rtc.bYear;
        baseDate.month = rtc.bMonth;
        baseDate.day = rtc.bDay;
        
        myDate date2 = getNewDate(&baseDate, -1);
        sprintf(pszBusinessDate, "20%02d%02d%02d", date2.year, date2.month, date2.day);
    }
    else
    {
        sprintf(pszBusinessDate, "20%02d%02d%02d", rtc.bYear, rtc.bMonth, rtc.bDay);
    }

}
