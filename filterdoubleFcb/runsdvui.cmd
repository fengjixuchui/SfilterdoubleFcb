cd /d "D:\Myproject\filterdoubleFcb_fuben\filterdoubleFcb" &msbuild "filterdoubleFcb.W7.vcxproj" /t:sdvViewer /p:configuration="W7XP checked" /p:platform=Win32
exit %errorlevel% 