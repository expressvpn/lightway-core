echo off
for /f "usebackq tokens=*" %%a in (`"\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set BASE=%%a
call "%BASE%"/VC\Auxiliary\Build\vcvarsamd64_arm64.bat
echo on
echo Running: ceedling %*
ceedling %*
