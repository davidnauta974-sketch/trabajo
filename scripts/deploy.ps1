param([string]$Conftest = 'conftest')
$ErrorActionPreference='Stop'
$taskProject=Split-Path -Parent $PSScriptRoot
Push-Location $taskProject
try {
    & $Conftest test Dockerfile --policy policy/dockerfile --no-color
    if($LASTEXITCODE -ne 0){throw 'Puerta de seguridad: Dockerfile rechazado'}
    & $Conftest test docker-compose.yml --policy policy/compose --no-color
    if($LASTEXITCODE -ne 0){throw 'Puerta de seguridad: Compose rechazado'}
    if(-not(Test-Path -LiteralPath '.secrets/api_key')){throw 'Falta inicializar el secreto local mediante scripts/init-secrets.py'}
    & docker compose up --build --detach
    if($LASTEXITCODE -ne 0){throw 'Docker Compose no pudo desplegar'}
    & docker compose ps
    Write-Output 'Consultar http://127.0.0.1:8080/ y /healthz para verificar la aplicación.'
} finally {Pop-Location}
