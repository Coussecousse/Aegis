param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("check", "up", "ps", "logs", "down", "clean", "restart", "pull")]
    [string]$Action
)

$ErrorActionPreference = "Stop"

$composeFile = "docker/node1/docker-compose.yml"
$envFile = ".env"

if (-not (Test-Path $envFile)) {
    Write-Host ".env not found, using .env.example" -ForegroundColor Yellow
    $envFile = ".env.example"
}

function Invoke-Compose {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    docker compose -f $composeFile --env-file $envFile @Args
}

switch ($Action) {
    "check" { Invoke-Compose -Args @("config") }
    "up" { Invoke-Compose -Args @("up", "-d", "--no-build", "--no-recreate") }
    "ps" { Invoke-Compose -Args @("ps") }
    "logs" { Invoke-Compose -Args @("logs", "-f", "--tail=200") }
    "down" { Invoke-Compose -Args @("down") }
    "clean" { Invoke-Compose -Args @("down", "-v", "--remove-orphans") }
    "restart" {
        Invoke-Compose -Args @("stop")
        Invoke-Compose -Args @("start")
    }
    "pull" { Invoke-Compose -Args @("pull") }
}
