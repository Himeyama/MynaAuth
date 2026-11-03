[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9-]+$')][string]$BundleName = 'MynaAuth-Logon',
    [switch]$SelfContained
)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$bundle = Join-Path (Join-Path $projectRoot 'artifacts') $BundleName
if (Test-Path -LiteralPath $bundle) { throw 'Use a new BundleName or remove the previous build output first.' }
$build = Join-Path $projectRoot 'artifacts\provider-build'
& cmake -S (Join-Path $projectRoot 'src\MynaAuth.CredentialProvider') -B $build -G 'Visual Studio 17 2022' -A x64
if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }
& cmake --build $build --config Release
if ($LASTEXITCODE -ne 0) { throw 'Provider build failed.' }
foreach ($project in @('MynaAuth.LogonHost','MynaAuth.Setup')) {
    $publishArguments = @()
    if ($SelfContained) { $publishArguments = @('-r', 'win-x64', '--self-contained', 'true') }
    & dotnet publish (Join-Path $projectRoot "src\$project") -c Release -o $bundle @publishArguments
    if ($LASTEXITCODE -ne 0) { throw 'Managed build failed.' }
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'New-DevelopmentAdmin.ps1') -Destination $bundle -Force
Copy-Item -LiteralPath (Join-Path $build 'Release\MynaAuthCredentialProvider.dll') -Destination $bundle -Force
foreach ($script in @('Install-LogonProvider.ps1','Uninstall-LogonProvider.ps1','Update-LogonProvider.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script) -Destination $bundle -Force
}
$entries = @(Get-ChildItem -LiteralPath $bundle -File | Where-Object { $_.Name -ne 'bundle-manifest.json' -and $_.Extension -ne '.log' } | ForEach-Object {
    [PSCustomObject]@{ Name = $_.Name; Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})
$entries | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $bundle 'bundle-manifest.json') -Encoding UTF8
Write-Output ('Bundle ready: ' + $bundle)
