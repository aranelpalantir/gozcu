# Gözcü'yü tek dosyalık Gozcu.exe olarak derler (PyInstaller, yalıtılmış sanal ortamda).
# Çıktı: dist\Gozcu.exe ve dist\Gozcu.exe.sha256
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$bits = & python -c "import struct; print(struct.calcsize('P') * 8)"
if ($bits -ne '64') { throw "64-bit Python gerekli (bulunan: $bits-bit)." }

if (-not (Test-Path .build-venv)) { python -m venv .build-venv }
$py = Join-Path $PSScriptRoot '.build-venv\Scripts\python.exe'
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet -r requirements.txt pyinstaller

& $py -m PyInstaller --noconfirm --clean --onefile --noconsole --name Gozcu `
    --icon gozcu.ico --version-file version_info.txt `
    --add-data "index.html;." --add-data "gozcu.ico;." sysdash.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller başarısız oldu." }

$h = (Get-FileHash dist\Gozcu.exe -Algorithm SHA256).Hash.ToLower()
"$h  Gozcu.exe" | Set-Content -Encoding ascii dist\Gozcu.exe.sha256
"Tamam: dist\Gozcu.exe  (SHA-256: $h)"
