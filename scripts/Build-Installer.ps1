[CmdletBinding()]
param([Parameter(Mandatory)][string]$HsisPath)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
[xml]$properties = Get-Content -LiteralPath (Join-Path $projectRoot 'Directory.Build.props')
$version = [string]$properties.Project.PropertyGroup.Version
if ($version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw 'Expected MAJOR.MINOR.PATCH version.' }
foreach ($component in $version.Split('.')) {
    if ([long]$component -gt 65535) { throw 'Version component exceeds 65535.' }
}
$bundleName = 'MynaAuth-Distribution-' + [guid]::NewGuid().ToString('N')
& (Join-Path $PSScriptRoot 'Build-LogonBundle.ps1') -BundleName $bundleName -SelfContained
$bundle = Join-Path $projectRoot "artifacts\$bundleName"
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\distribution.md') -Destination (Join-Path $bundle 'READ-ME.md')
$output = Join-Path $projectRoot ('artifacts\installer-' + [guid]::NewGuid().ToString('N'))
& $HsisPath build (Join-Path $projectRoot 'installer\MynaAuth.nsi') --output $output "-DAPP_VERSION=$version" "-DSOURCE_DIR=$bundle"
if ($LASTEXITCODE -ne 0) { throw 'HSIS build failed.' }
$installers = @(Get-ChildItem -LiteralPath $output -Recurse -Filter '*-Setup.exe')
if ($installers.Count -ne 1) { throw 'Expected exactly one installer.' }
$installer = $installers[0]
$hash = (Get-FileHash -LiteralPath $installer.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $($installer.Name)" | Set-Content -LiteralPath ($installer.FullName + '.sha256') -Encoding ascii
Write-Output ('Distribution ready: ' + $installer.DirectoryName)
