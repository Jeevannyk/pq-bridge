# PQ-Bridge dev server with auto-reload.
#   Backend:  uvicorn restarts when any .py file in pqbridge/ changes.
#   Frontend: the console polls /api/status; any change in console/ reloads the browser tab.
# Usage: .\dev.ps1    then open http://127.0.0.1:8000   (server output is also written to data\dev-server.log)
Set-Location $PSScriptRoot
# OneDrive-synced folders don't deliver native file-change events reliably; poll instead.
$env:WATCHFILES_FORCE_POLLING = "true"
& .\.venv\Scripts\python.exe -m uvicorn pqbridge.api:app --host 127.0.0.1 --port 8000 --reload --reload-dir "$PSScriptRoot\pqbridge" 2>&1 |
    Tee-Object -FilePath "$PSScriptRoot\data\dev-server.log"
