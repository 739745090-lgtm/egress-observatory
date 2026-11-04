@echo off
cd /d "%~dp0"
echo Egress local page: http://127.0.0.1:4187/
echo Keep this window open. Press Ctrl+C to stop.
python -m http.server 4187 --bind 127.0.0.1
