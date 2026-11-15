@echo off
rem SysDash'i yonetici olarak baslatir (firewall logu, kural ekleme, tum surec yollari icin)
cd /d "%~dp0"
powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','\"%~dp0start.bat\"' -Verb RunAs"
