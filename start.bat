@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -c "import psutil" 2>nul || (
  echo psutil kuruluyor...
  python -m pip install --user psutil
)
title Gözcü
python sysdash.py
pause
