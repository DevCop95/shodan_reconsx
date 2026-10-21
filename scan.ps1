$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "src/recons101x.py"

if ($env:RECONS101X_PYTHON) {
    & $env:RECONS101X_PYTHON $scriptPath @args
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $scriptPath @args
} else {
    & python $scriptPath @args
}

exit $LASTEXITCODE
