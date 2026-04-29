@echo off
set CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe

if not exist %CSC% (
    echo [!] CSC.exe not found. Ensure .NET Framework 4.0 is installed.
    pause
    exit /b 1
)

echo [*] Compiling Unit Tests...
:: Note: MToolCore.cs is in the parent's src directory
%CSC% /nologo /target:exe /out:UnitTests.exe ..\src\MToolCore.cs UnitTests.cs

if %ERRORLEVEL% NEQ 0 (
    echo [!] Compilation failed.
    pause
    exit /b 1
)

echo [*] Running Unit Tests...
UnitTests.exe

if %ERRORLEVEL% EQU 0 (
    echo [*] Cleaning up...
    del UnitTests.exe
    echo.
    echo [+] Success: All tests passed.
) else (
    echo.
    echo [!] Failure: Some tests failed. Please check the logic.
)

pause
