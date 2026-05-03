@echo off
cd /d "%~dp0"

echo.
echo  Exposing database ports...
docker compose -f docker-compose.yml -f docker-compose.db-ports.yml up -d postgres neo4j
if %errorlevel% neq 0 (
    echo  ERROR: make sure Docker Desktop is running and you are in the project folder.
    pause
    exit /b 1
)

echo.
echo  ============================================================
echo   POSTGRESQL
echo  ============================================================
echo   GUI (pgAdmin / DBeaver / TablePlus)
echo     Host     : localhost
echo     Port     : 5432
echo     Database : adaudit
echo     User     : adaudit
echo     Password : changeme
echo.
echo   Terminal (psql inside container)
echo     docker compose exec postgres psql -U adaudit -d adaudit
echo.
echo  ============================================================
echo   NEO4J
echo  ============================================================
echo   Browser (no install needed)
echo     URL      : http://localhost:7474
echo     Bolt URL : bolt://localhost:7687
echo     User     : neo4j
echo     Password : changeme
echo.
echo  ============================================================
echo.

set /p open="Open Neo4j Browser now? (y/n): "
if /i "%open%"=="y" start http://localhost:7474

echo.
echo  Ports are open. Press any key to close this window.
pause >nul
