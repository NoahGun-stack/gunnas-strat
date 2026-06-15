@echo off
REM ─────────────────────────────────────────────────────────────
REM  Build "Gunnas Strat.exe"  (run this ON A WINDOWS PC)
REM  Produces a double-clickable .exe in the dist\ folder.
REM ─────────────────────────────────────────────────────────────
echo ==^> Installing dependencies...
pip install -r requirements.txt

echo ==^> Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist "Gunnas Strat.spec" del /q "Gunnas Strat.spec"

echo ==^> Building app (this can take a minute)...
pyinstaller --onefile --windowed --name "Gunnas Strat" ^
  --hidden-import websocket ^
  --collect-submodules tzdata ^
  main.py

echo.
echo Done! Your .exe is at: dist\Gunnas Strat.exe
pause
