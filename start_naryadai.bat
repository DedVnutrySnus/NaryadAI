@echo off
setlocal
cd /d "%~dp0"

set "PYTHON_EXE=.venv\Scripts\python.exe"

if not exist "%PYTHON_EXE%" (
    echo [ERROR] Не найдено виртуальное окружение: %PYTHON_EXE%
    echo.
    echo Сначала подготовьте проект или переименуйте окружение в .venv
    echo.
    pause
    exit /b 1
)

echo =====================================================
echo НарядAI: запуск сервера
echo =====================================================
echo Запуск веб-сервера с поддержкой live-обновлений...

rem Open the browser after a short delay so the app is ready.
start "" cmd /c "timeout /t 5 /nobreak >nul && start "" http://localhost:8000"

call "%PYTHON_EXE%" -m uvicorn app:app --host 0.0.0.0 --port 8000 --ws websockets-sansio

if errorlevel 1 (
    echo.
    echo Сервер не запустился корректно.
    echo Проверьте Python-окружение и зависимости.
    pause
)
