$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "src/recons101x.py"

if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $scriptPath @args
} else {
    & python $scriptPath @args
}

exit $LASTEXITCODE
