@echo off
chcp 65001 >nul
echo ==========================================
echo 批量上传本地插件
echo ==========================================
echo.

REM 请修改以下配置
set API_URL=http://localhost:5001
set TOKEN=your_token_here

echo API地址: %API_URL%
echo.

curl -X POST "%API_URL%/console/api/workspaces/current/plugin/upload/pkg/local" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -w "\nHTTP状态码: %%{http_code}\n" ^
  --connect-timeout 10 ^
  --max-time 300

echo.
echo ==========================================
pause
