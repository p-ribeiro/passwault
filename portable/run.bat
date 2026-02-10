@echo off
REM Portable launcher for Passwault (Windows)
REM Place this script in the USB drive root alongside the passwault\ folder.
"%~dp0passwault\passwault.exe" --portable %*
