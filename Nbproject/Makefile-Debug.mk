#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=arm-brcm-linux-gnueabi-gcc
CCC=arm-brcm-linux-gnueabi-g++
CXX=arm-brcm-linux-gnueabi-g++
FC=g77.exe
AS=as

# Macros
CND_PLATFORM=Gnueabi-Windows
CND_DLIB_EXT=dll
CND_CONF=Debug
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include NbMakefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/Trans/POSFleet.o \
	${OBJECTDIR}/Trans/POSDCC.o \
	${OBJECTDIR}/Main/POSMain.o \
	${OBJECTDIR}/Trans/POSSale.o \
	${OBJECTDIR}/Trans/POSAutoReport.o \
	${OBJECTDIR}/Trans/POSCashAdvance.o \
	${OBJECTDIR}/PCI100/COMMS.o \
	${OBJECTDIR}/Database/pas.o \
	${OBJECTDIR}/Database/gpt.o \
	${OBJECTDIR}/Database/dct.o \
	${OBJECTDIR}/Aptrans/MultiShareECR.o \
	${OBJECTDIR}/Ctls/POSWave.o \
	${OBJECTDIR}/Trans/POSReload.o \
	${OBJECTDIR}/Trans/POSLogon.o \
	${OBJECTDIR}/Ctls/POSCtls.o \
	${OBJECTDIR}/PinPad/debugPCI.o \
	${OBJECTDIR}/Trans/POSBinVer.o \
	${OBJECTDIR}/POWRFAIL/POSPOWRFAIL.o \
	${OBJECTDIR}/Trans/POSOffline.o \
	${OBJECTDIR}/Ctls/POSMifare.o \
	${OBJECTDIR}/UTILS/wub_lib.o \
	${OBJECTDIR}/Database/DatabaseDCCFunc.o \
	${OBJECTDIR}/Loyalty/BDOLoyalty.o \
	${OBJECTDIR}/Trans/PosSmac.o \
	${OBJECTDIR}/Trans/POSTipAdjust.o \
	${OBJECTDIR}/Iso8583/V5IsoFunc.o \
	${OBJECTDIR}/Trans/POSCashierLoyalty.o \
	${OBJECTDIR}/Database/bvt.o \
	${OBJECTDIR}/Database/DatabaseFunc.o \
	${OBJECTDIR}/Database/flt.o \
	${OBJECTDIR}/Trans/date.o \
	${OBJECTDIR}/UTILS/myEZLib.o \
	${OBJECTDIR}/UI/Display.o \
	${OBJECTDIR}/ACCUM/accum.o \
	${OBJECTDIR}/Iso8583/Iso.o \
	${OBJECTDIR}/Database/clt.o \
	${OBJECTDIR}/TMS/TMS.o \
	${OBJECTDIR}/Trans/POSVoid.o \
	${OBJECTDIR}/Trans/LocalFunc.o \
	${OBJECTDIR}/Aptrans/MultiAptrans.o \
	${OBJECTDIR}/Trans/POSRefund.o \
	${OBJECTDIR}/Database/prm.o \
	${OBJECTDIR}/Aptrans/MultiShareEMV.o \
	${OBJECTDIR}/Trans/POSInstallment.o \
	${OBJECTDIR}/NetMatrix/NMXEncode.o \
	${OBJECTDIR}/Trans/CardUtil.o \
	${OBJECTDIR}/batch/POSbatch.o \
	${OBJECTDIR}/print/Print.o \
	${OBJECTDIR}/PCI100/PCI100.o \
	${OBJECTDIR}/Functionslist/POSFunctionsList.o \
	${OBJECTDIR}/Trans/POSTrans.o \
	${OBJECTDIR}/PinPad/pinpad.o \
	${OBJECTDIR}/Trans/POSHost.o \
	${OBJECTDIR}/Aptrans/MultiShareCOM.o \
	${OBJECTDIR}/Trans/LocalAptrans.o \
	${OBJECTDIR}/PCI100/PCI100des.o \
	${OBJECTDIR}/Trans/POSSettlement.o \
	${OBJECTDIR}/Trans/POSBinRouting.o \
	${OBJECTDIR}/Erm/PosErm.o \
	${OBJECTDIR}/NetMatrix/V5SLibNetMatrix.o \
	${OBJECTDIR}/Trans/Encryption.o \
	${OBJECTDIR}/FileModule/myFileFunc.o \
	${OBJECTDIR}/Comm/V5Comm.o \
	${OBJECTDIR}/Trans/POSAuth.o \
	${OBJECTDIR}/Setting/POSSetting.o \
	${OBJECTDIR}/Trans/POSBalanceInq.o \
	${OBJECTDIR}/Database/par.o \
	${OBJECTDIR}/Trans/AES.o \
	${OBJECTDIR}/UI/showbmp.o \
	${OBJECTDIR}/NetMatrix/DebugNMX.o \
	${OBJECTDIR}/PCI100/USBComms.o \
	${OBJECTDIR}/DEBUG/debug.o


# C Compiler Flags
CFLAGS="-I${SDKV5SINC}" -fsigned-char -Wundef -Wstrict-prototypes -Wno-trigraphs -Wimplicit -Wformat 

# CC Compiler Flags
CCFLAGS="-I${SDKV5SINC}" -fsigned-char -Wundef -Wno-trigraphs -Wimplicit -Wformat 
CXXFLAGS="-I${SDKV5SINC}" -fsigned-char -Wundef -Wno-trigraphs -Wimplicit -Wformat 

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=-lcafont -lcafs -lcakms -lcalcd -lcamodem -lcapmodem -lcaprt -lcartc -lcauart -lcauldpm -lcausbh -lcagsm -lcabarcode -lpthread -ldl -lcaclvw -lcatls -lctosapi -lz -lssl -lcrypto -lcurl -lfreetype -lxml2 -lcaethernet -lv5smultiap -lv5scfgexpress -lcasqlite -lcaxml -lv5sISOEnginee -lv5sEFT -lv5sEFTNAC -lbluetooth -lcaclentry -lcaclmdl -lbluetooth -lbmp -lcaclentry -lcaclmdl -lv5spbm -lcaqrcode -lcabarcode aes.o DESFire.o -lv3_libepadso -lzint -lpng16 -lz -lv5sinput ../../VEGA_Library/NETBEANS/DMenu/Ver0003/Lib/V5S_LibDMenu.a ../../VEGA_Library/NETBEANS/DMenu/Ver0005/Lib/V5S_LibDMenu.a

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk dist/V5S/BDOCREDIT/10V5S_App/V5S_BDOCREDIT.exe

dist/V5S/BDOCREDIT/10V5S_App/V5S_BDOCREDIT.exe: aes.o

dist/V5S/BDOCREDIT/10V5S_App/V5S_BDOCREDIT.exe: DESFire.o

dist/V5S/BDOCREDIT/10V5S_App/V5S_BDOCREDIT.exe: ../../VEGA_Library/NETBEANS/DMenu/Ver0003/Lib/V5S_LibDMenu.a

dist/V5S/BDOCREDIT/10V5S_App/V5S_BDOCREDIT.exe: ../../VEGA_Library/NETBEANS/DMenu/Ver0005/Lib/V5S_LibDMenu.a

dist/V5S/BDOCREDIT/10V5S_App/V5S_BDOCREDIT.exe: ${OBJECTFILES}
	${MKDIR} -p dist/V5S/BDOCREDIT/10V5S_App
	arm-brcm-linux-gnueabi-g++ -L . "-L${SDKV5SLIB}" "-L${SDKV5SLIBN}" -o dist/V5S/BDOCREDIT/10V5S_App/V5S_BDOCREDIT  ${OBJECTFILES} ${LDLIBSOPTIONS} 

${OBJECTDIR}/Trans/POSFleet.o: Trans/POSFleet.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSFleet.o Trans/POSFleet.c

${OBJECTDIR}/Trans/POSDCC.o: Trans/POSDCC.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSDCC.o Trans/POSDCC.c

${OBJECTDIR}/Main/POSMain.o: Main/POSMain.c 
	${MKDIR} -p ${OBJECTDIR}/Main
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Main/POSMain.o Main/POSMain.c

${OBJECTDIR}/Trans/POSSale.o: Trans/POSSale.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSSale.o Trans/POSSale.c

${OBJECTDIR}/Trans/POSAutoReport.o: Trans/POSAutoReport.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSAutoReport.o Trans/POSAutoReport.c

${OBJECTDIR}/Trans/POSCashAdvance.o: Trans/POSCashAdvance.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSCashAdvance.o Trans/POSCashAdvance.c

${OBJECTDIR}/PCI100/COMMS.o: PCI100/COMMS.c 
	${MKDIR} -p ${OBJECTDIR}/PCI100
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/PCI100/COMMS.o PCI100/COMMS.c

${OBJECTDIR}/Database/pas.o: Database/pas.c 
	${MKDIR} -p ${OBJECTDIR}/Database
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Database/pas.o Database/pas.c

${OBJECTDIR}/Database/gpt.o: Database/gpt.c 
	${MKDIR} -p ${OBJECTDIR}/Database
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Database/gpt.o Database/gpt.c

${OBJECTDIR}/Database/dct.o: Database/dct.c 
	${MKDIR} -p ${OBJECTDIR}/Database
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Database/dct.o Database/dct.c

${OBJECTDIR}/Aptrans/MultiShareECR.o: Aptrans/MultiShareECR.c 
	${MKDIR} -p ${OBJECTDIR}/Aptrans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Aptrans/MultiShareECR.o Aptrans/MultiShareECR.c

${OBJECTDIR}/Ctls/POSWave.o: Ctls/POSWave.c 
	${MKDIR} -p ${OBJECTDIR}/Ctls
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Ctls/POSWave.o Ctls/POSWave.c

${OBJECTDIR}/Trans/POSReload.o: Trans/POSReload.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSReload.o Trans/POSReload.c

${OBJECTDIR}/Trans/POSLogon.o: Trans/POSLogon.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSLogon.o Trans/POSLogon.c

${OBJECTDIR}/Ctls/POSCtls.o: Ctls/POSCtls.c 
	${MKDIR} -p ${OBJECTDIR}/Ctls
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Ctls/POSCtls.o Ctls/POSCtls.c

${OBJECTDIR}/PinPad/debugPCI.o: PinPad/debugPCI.c 
	${MKDIR} -p ${OBJECTDIR}/PinPad
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/PinPad/debugPCI.o PinPad/debugPCI.c

${OBJECTDIR}/Trans/POSBinVer.o: Trans/POSBinVer.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSBinVer.o Trans/POSBinVer.c

${OBJECTDIR}/POWRFAIL/POSPOWRFAIL.o: POWRFAIL/POSPOWRFAIL.c 
	${MKDIR} -p ${OBJECTDIR}/POWRFAIL
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/POWRFAIL/POSPOWRFAIL.o POWRFAIL/POSPOWRFAIL.c

${OBJECTDIR}/Trans/POSOffline.o: Trans/POSOffline.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSOffline.o Trans/POSOffline.c

${OBJECTDIR}/Ctls/POSMifare.o: Ctls/POSMifare.c 
	${MKDIR} -p ${OBJECTDIR}/Ctls
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Ctls/POSMifare.o Ctls/POSMifare.c

${OBJECTDIR}/UTILS/wub_lib.o: UTILS/wub_lib.c 
	${MKDIR} -p ${OBJECTDIR}/UTILS
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/UTILS/wub_lib.o UTILS/wub_lib.c

${OBJECTDIR}/Database/DatabaseDCCFunc.o: Database/DatabaseDCCFunc.c 
	${MKDIR} -p ${OBJECTDIR}/Database
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Database/DatabaseDCCFunc.o Database/DatabaseDCCFunc.c

${OBJECTDIR}/Loyalty/BDOLoyalty.o: Loyalty/BDOLoyalty.c 
	${MKDIR} -p ${OBJECTDIR}/Loyalty
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Loyalty/BDOLoyalty.o Loyalty/BDOLoyalty.c

${OBJECTDIR}/Trans/PosSmac.o: Trans/PosSmac.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/PosSmac.o Trans/PosSmac.c

${OBJECTDIR}/Trans/POSTipAdjust.o: Trans/POSTipAdjust.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSTipAdjust.o Trans/POSTipAdjust.c

${OBJECTDIR}/Iso8583/V5IsoFunc.o: Iso8583/V5IsoFunc.c 
	${MKDIR} -p ${OBJECTDIR}/Iso8583
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Iso8583/V5IsoFunc.o Iso8583/V5IsoFunc.c

${OBJECTDIR}/Trans/POSCashierLoyalty.o: Trans/POSCashierLoyalty.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSCashierLoyalty.o Trans/POSCashierLoyalty.c

${OBJECTDIR}/Database/bvt.o: Database/bvt.c 
	${MKDIR} -p ${OBJECTDIR}/Database
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Database/bvt.o Database/bvt.c

${OBJECTDIR}/Database/DatabaseFunc.o: Database/DatabaseFunc.c 
	${MKDIR} -p ${OBJECTDIR}/Database
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Database/DatabaseFunc.o Database/DatabaseFunc.c

${OBJECTDIR}/Database/flt.o: Database/flt.c 
	${MKDIR} -p ${OBJECTDIR}/Database
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Database/flt.o Database/flt.c

${OBJECTDIR}/Trans/date.o: Trans/date.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/date.o Trans/date.c

${OBJECTDIR}/UTILS/myEZLib.o: UTILS/myEZLib.c 
	${MKDIR} -p ${OBJECTDIR}/UTILS
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/UTILS/myEZLib.o UTILS/myEZLib.c

${OBJECTDIR}/UI/Display.o: UI/Display.c 
	${MKDIR} -p ${OBJECTDIR}/UI
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/UI/Display.o UI/Display.c

${OBJECTDIR}/ACCUM/accum.o: ACCUM/accum.c 
	${MKDIR} -p ${OBJECTDIR}/ACCUM
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/ACCUM/accum.o ACCUM/accum.c

${OBJECTDIR}/Iso8583/Iso.o: Iso8583/Iso.c 
	${MKDIR} -p ${OBJECTDIR}/Iso8583
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Iso8583/Iso.o Iso8583/Iso.c

${OBJECTDIR}/Database/clt.o: Database/clt.c 
	${MKDIR} -p ${OBJECTDIR}/Database
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Database/clt.o Database/clt.c

${OBJECTDIR}/TMS/TMS.o: TMS/TMS.c 
	${MKDIR} -p ${OBJECTDIR}/TMS
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/TMS/TMS.o TMS/TMS.c

${OBJECTDIR}/Trans/POSVoid.o: Trans/POSVoid.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSVoid.o Trans/POSVoid.c

${OBJECTDIR}/Trans/LocalFunc.o: Trans/LocalFunc.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/LocalFunc.o Trans/LocalFunc.c

${OBJECTDIR}/Aptrans/MultiAptrans.o: Aptrans/MultiAptrans.c 
	${MKDIR} -p ${OBJECTDIR}/Aptrans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Aptrans/MultiAptrans.o Aptrans/MultiAptrans.c

${OBJECTDIR}/Trans/POSRefund.o: Trans/POSRefund.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSRefund.o Trans/POSRefund.c

${OBJECTDIR}/Database/prm.o: Database/prm.c 
	${MKDIR} -p ${OBJECTDIR}/Database
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Database/prm.o Database/prm.c

${OBJECTDIR}/Aptrans/MultiShareEMV.o: Aptrans/MultiShareEMV.c 
	${MKDIR} -p ${OBJECTDIR}/Aptrans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Aptrans/MultiShareEMV.o Aptrans/MultiShareEMV.c

${OBJECTDIR}/Trans/POSInstallment.o: Trans/POSInstallment.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSInstallment.o Trans/POSInstallment.c

${OBJECTDIR}/NetMatrix/NMXEncode.o: NetMatrix/NMXEncode.c 
	${MKDIR} -p ${OBJECTDIR}/NetMatrix
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/NetMatrix/NMXEncode.o NetMatrix/NMXEncode.c

${OBJECTDIR}/Trans/CardUtil.o: Trans/CardUtil.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/CardUtil.o Trans/CardUtil.c

${OBJECTDIR}/batch/POSbatch.o: batch/POSbatch.c 
	${MKDIR} -p ${OBJECTDIR}/batch
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/batch/POSbatch.o batch/POSbatch.c

${OBJECTDIR}/print/Print.o: print/Print.c 
	${MKDIR} -p ${OBJECTDIR}/print
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/print/Print.o print/Print.c

${OBJECTDIR}/PCI100/PCI100.o: PCI100/PCI100.c 
	${MKDIR} -p ${OBJECTDIR}/PCI100
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/PCI100/PCI100.o PCI100/PCI100.c

${OBJECTDIR}/Functionslist/POSFunctionsList.o: Functionslist/POSFunctionsList.c 
	${MKDIR} -p ${OBJECTDIR}/Functionslist
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Functionslist/POSFunctionsList.o Functionslist/POSFunctionsList.c

${OBJECTDIR}/Trans/POSTrans.o: Trans/POSTrans.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSTrans.o Trans/POSTrans.c

${OBJECTDIR}/PinPad/pinpad.o: PinPad/pinpad.c 
	${MKDIR} -p ${OBJECTDIR}/PinPad
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/PinPad/pinpad.o PinPad/pinpad.c

${OBJECTDIR}/Trans/POSHost.o: Trans/POSHost.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSHost.o Trans/POSHost.c

${OBJECTDIR}/Aptrans/MultiShareCOM.o: Aptrans/MultiShareCOM.c 
	${MKDIR} -p ${OBJECTDIR}/Aptrans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Aptrans/MultiShareCOM.o Aptrans/MultiShareCOM.c

${OBJECTDIR}/Trans/LocalAptrans.o: Trans/LocalAptrans.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/LocalAptrans.o Trans/LocalAptrans.c

${OBJECTDIR}/PCI100/PCI100des.o: PCI100/PCI100des.c 
	${MKDIR} -p ${OBJECTDIR}/PCI100
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/PCI100/PCI100des.o PCI100/PCI100des.c

${OBJECTDIR}/Trans/POSSettlement.o: Trans/POSSettlement.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSSettlement.o Trans/POSSettlement.c

${OBJECTDIR}/Trans/POSBinRouting.o: Trans/POSBinRouting.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSBinRouting.o Trans/POSBinRouting.c

${OBJECTDIR}/Erm/PosErm.o: Erm/PosErm.c 
	${MKDIR} -p ${OBJECTDIR}/Erm
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Erm/PosErm.o Erm/PosErm.c

${OBJECTDIR}/NetMatrix/V5SLibNetMatrix.o: NetMatrix/V5SLibNetMatrix.c 
	${MKDIR} -p ${OBJECTDIR}/NetMatrix
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/NetMatrix/V5SLibNetMatrix.o NetMatrix/V5SLibNetMatrix.c

${OBJECTDIR}/Trans/Encryption.o: Trans/Encryption.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/Encryption.o Trans/Encryption.c

${OBJECTDIR}/FileModule/myFileFunc.o: FileModule/myFileFunc.c 
	${MKDIR} -p ${OBJECTDIR}/FileModule
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/FileModule/myFileFunc.o FileModule/myFileFunc.c

${OBJECTDIR}/Comm/V5Comm.o: Comm/V5Comm.c 
	${MKDIR} -p ${OBJECTDIR}/Comm
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Comm/V5Comm.o Comm/V5Comm.c

${OBJECTDIR}/Trans/POSAuth.o: Trans/POSAuth.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSAuth.o Trans/POSAuth.c

${OBJECTDIR}/Setting/POSSetting.o: Setting/POSSetting.c 
	${MKDIR} -p ${OBJECTDIR}/Setting
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Setting/POSSetting.o Setting/POSSetting.c

${OBJECTDIR}/Trans/POSBalanceInq.o: Trans/POSBalanceInq.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/POSBalanceInq.o Trans/POSBalanceInq.c

${OBJECTDIR}/Database/par.o: Database/par.c 
	${MKDIR} -p ${OBJECTDIR}/Database
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Database/par.o Database/par.c

${OBJECTDIR}/Trans/AES.o: Trans/AES.c 
	${MKDIR} -p ${OBJECTDIR}/Trans
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/Trans/AES.o Trans/AES.c

${OBJECTDIR}/UI/showbmp.o: UI/showbmp.c 
	${MKDIR} -p ${OBJECTDIR}/UI
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/UI/showbmp.o UI/showbmp.c

${OBJECTDIR}/NetMatrix/DebugNMX.o: NetMatrix/DebugNMX.c 
	${MKDIR} -p ${OBJECTDIR}/NetMatrix
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/NetMatrix/DebugNMX.o NetMatrix/DebugNMX.c

${OBJECTDIR}/PCI100/USBComms.o: PCI100/USBComms.c 
	${MKDIR} -p ${OBJECTDIR}/PCI100
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/PCI100/USBComms.o PCI100/USBComms.c

${OBJECTDIR}/DEBUG/debug.o: DEBUG/debug.c 
	${MKDIR} -p ${OBJECTDIR}/DEBUG
	$(COMPILE.c) -g -I/cygdrive/C/Program\ Files/Castles/VEGA5000S/include -I/cygdrive/C/Program\ Files\ \(x86\)/Castles/VEGA5000S/include -o ${OBJECTDIR}/DEBUG/debug.o DEBUG/debug.c

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}
	${RM} dist/V5S/BDOCREDIT/10V5S_App/V5S_BDOCREDIT.exe

# Subprojects
.clean-subprojects:
