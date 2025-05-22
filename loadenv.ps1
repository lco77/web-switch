# Define the path to your .env file
$envFile = ".\.env"

# Check if the file exists
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        # Skip comments and empty lines
        if ($_ -match '^\s*#') { return }
        if ($_ -match '^\s*$') { return }
        
        # Split the line into key and value parts (only on the first '=')
        $parts = $_ -split '=', 2
        if ($parts.Length -eq 2) {
            $key = $parts[0].Trim()
            $value = $parts[1].Trim()
            $value = $value.Trim('"')
            # Set the environment variable in the current session
            Set-Item -Path "Env:$key" -Value $value


        }
    }
    Write-Output "Environment variables loaded from $envFile"
} else {
    Write-Error "File $envFile not found."
}