@echo off
setlocal EnableExtensions
cd /d "%~dp0\..\.." || exit /b 10
echo [UCR] Windows local smoke launcher (NOT an encrypted call proof)
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (echo [ERROR] Visual Studio x64 tools missing: %VCVARS% & exit /b 11)
if not exist "C:\UCR-OpenSSL\include\openssl\ssl.h" (echo [ERROR] OpenSSL headers missing in C:\UCR-OpenSSL & exit /b 12)
set "DB=%LOCALAPPDATA%\UCR-Local-Test\runtime.sqlite"
if not exist "%DB%" (echo [ERROR] Existing SQLite database not found: %DB% & exit /b 13)
call "%VCVARS%" || exit /b 14
set "OPENSSL_DIR=C:\UCR-OpenSSL"
set "OPENSSL_STATIC=1"
set "OPENSSL_NO_VENDOR=1"
rem Rust 1.97.1 on Windows 10 1607 panicked while encoding incremental metadata.
rem Disable the incremental cache and heavy debug metadata; serialize compilation.
set "CARGO_INCREMENTAL=0"
set "CARGO_BUILD_JOBS=1"
set "CARGO_PROFILE_DEV_DEBUG=0"
echo [UCR] Compiling with incremental=off, jobs=1, debuginfo=0...
cargo build -p ucr-runtime -p ucr-realtime-web --locked
if errorlevel 1 (echo [ERROR] Rust build failed. Do not start stale executables. & exit /b 20)
if not exist "crates\ucr-realtime-web\static\endpoint-media\reference_browser_media_installer.js" (echo [ERROR] Browser media missing. Run scripts\windows\build-browser-media.ps1 first. & exit /b 21)
echo [UCR] Build succeeded. Starting existing local database, no reset.
start "UCR Runtime local smoke" cmd /k "target\debug\ucr-runtime.exe serve --database ""%DB%"" --bind 127.0.0.1:50051 --operator-bind 127.0.0.1:50052"
timeout /t 3 /nobreak >nul
start "UCR Browser gateway local smoke" cmd /k "target\debug\ucr-realtime-web.exe"
echo [UCR] Inspect both launched windows for errors.
echo [UCR] Browser: http://127.0.0.1:8080/start
echo [UCR] This smoke does not enable first-party signup, HTTPS, Join or encrypted live media.
exit /b 0
