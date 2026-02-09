@echo off
echo Building single executable...

if not exist venv (
    echo No virtual environment found. Assuming dependencies are installed globally or in current env.
)

echo Building AdvHD_WS2_Toolkit (All-in-One)...
pyinstaller --noconsole --onefile --name AdvHD_WS2_Toolkit GUI_ws2.py

echo.
echo Build complete. The single executable "AdvHD_WS2_Toolkit.exe" is in the "dist" folder.
pause
