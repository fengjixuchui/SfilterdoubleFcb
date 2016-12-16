@echo on

rem
rem syntax: BuildVersion.bat winxp|win7 checked|free 32|64
rem         BuildVersion.bat all 

setlocal

rem change this MICRO according to the path of DDK

set WXP_DDK_ROOT=C:\WinDDK\7600.16385.1
set WIN7_DDK_ROOT=C:\WinDDK\7600.16385.1

rem set Target OS & Build & Architecture

set TARGET_OS=%1
set TARGET_OBJ=%2
set TARGET_BITS=%3

set OS_BITS=i386
if "%3" == "64"				set OS_BITS=amd64

if "%1" == "all" 			goto all
if "%1" == "winxp" 			goto winxp
if "%1" == "win7" 			goto win7
goto Error

rem ================= windows XP ==================

:winxp

if "%2" == "checked"    goto winxpchecked
if "%2" == "free"       goto winxpfree
goto Error

:winxpchecked
pushd \
call %WXP_DDK_ROOT%\bin\setenv.bat %WXP_DDK_ROOT% chk x86 WXP
popd
build.exe /g /w
rmdir /s /q objchk_wxp_x86
goto done

:winxpfree
pushd \
call %WXP_DDK_ROOT%\bin\setenv.bat %WXP_DDK_ROOT% fre x86 WXP
popd
build.exe /g /w
rmdir /s /q objfre_wxp_x86
goto done

rem ================= windows 7 ==================

:win7

if "%2" == "checked" 		goto win7checked
if "%2" == "free"    		goto win7free
goto Error

:win7checked
if "%3" == "64" 				goto win7checkX64
pushd \
call %WIN7_DDK_ROOT%\bin\setenv.bat %WIN7_DDK_ROOT% chk x86 WIN7
popd
build.exe /g /w
::rmdir /s /q objchk_win7_x86
goto done

:win7checkX64
pushd \
call %WIN7_DDK_ROOT%\bin\setenv.bat %WIN7_DDK_ROOT% chk x64 WIN7
popd
build.exe /g /w
::rmdir /s /q objchk_win7_amd64
goto done

:win7free
if "%3" == "64" 				goto win7freeX64
pushd \
call %WIN7_DDK_ROOT%\bin\setenv.bat %WIN7_DDK_ROOT% fre x86 WIN7
popd
build.exe /g /w
rmdir /s /q objfre_win7_x86
goto done

:win7freeX64
pushd \
call %WIN7_DDK_ROOT%\bin\setenv.bat %WIN7_DDK_ROOT% fre x64 WIN7
popd
build.exe /g /w
rmdir /s /q objfre_win7_amd64
goto done

:all

call BuildVersion.bat winxp checked
call BuildVersion.bat winxp free
call BuildVersion.bat win7 checked 32
call BuildVersion.bat win7 checked 64
call BuildVersion.bat win7 free 32
call BuildVersion.bat win7 free 64

goto end

:Error

rem Build Version Fails.

goto end

:done
del /f /s  *.log *.wrn *.err
 
:end
rem endlocal
