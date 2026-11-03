#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$BundlePath)
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell.' }
$source = [IO.Path]::GetFullPath($BundlePath)
$manifest = Get-Content -LiteralPath (Join-Path $source 'bundle-manifest.json') -Raw | ConvertFrom-Json
if (-not ($manifest.Name -contains 'MynaAuthCredentialProvider.dll') -or -not ($manifest.Name -contains 'MynaAuth.LogonHost.exe')) { throw 'Required files are missing.' }
foreach ($entry in $manifest) {
    if ($entry.Name -ne [IO.Path]::GetFileName($entry.Name)) { throw 'Invalid bundle path.' }
    if ((Get-FileHash -LiteralPath (Join-Path $source $entry.Name) -Algorithm SHA256).Hash -ne $entry.Sha256) { throw 'Bundle integrity check failed.' }
}
$providerId = '{37167329-B6D8-4379-90A9-0D350F82F31A}'
$providerKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\' + $providerId
$comKey = 'HKLM:\SOFTWARE\Classes\CLSID\' + $providerId + '\InprocServer32'
if (-not (Test-Path -LiteralPath $providerKey) -or -not (Test-Path -LiteralPath $comKey)) { throw 'Install the provider before updating it.' }
$root = Join-Path $env:ProgramFiles 'MynaAuthSignIn'
$versions = Join-Path $root 'Versions'
if (-not $PSCmdlet.ShouldProcess($root, 'Stage a new version and update only the MynaAuth provider path')) { return }
foreach ($directory in @($root, $versions)) {
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory | Out-Null }
    if ((Get-Item -LiteralPath $directory).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The installation directory must not be a link.' }
}
# A fresh directory avoids replacing DLLs still loaded by LogonUI.
$target = Join-Path $versions ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $target | Out-Null
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sidText in @('S-1-5-18','S-1-5-32-544')) {
    $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
$usersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($usersSid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
Set-Acl -LiteralPath $target -AclObject $acl
foreach ($entry in $manifest) {
    $destination = Join-Path $target $entry.Name
    Copy-Item -LiteralPath (Join-Path $source $entry.Name) -Destination $destination
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $entry.Sha256) { throw 'Staged file verification failed.' }
}
Copy-Item -LiteralPath (Join-Path $source 'bundle-manifest.json') -Destination $target
$com = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($comKey.Substring(6), $true)
$provider = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($providerKey.Substring(6), $true)
$previous = $com.GetValue('')
$previousLabel = $provider.GetValue('')
try {
    $com.SetValue('', (Join-Path $target 'MynaAuthCredentialProvider.dll'))
    $provider.SetValue('', 'マイナンバーカードによるログイン')
}
catch {
    $com.SetValue('', $previous)
    $provider.SetValue('', $previousLabel)
    throw
}
finally { $com.Close(); $provider.Close() }
Write-Output 'Provider updated. Enrollment and standard sign-in methods were preserved. No restart or lock was initiated.'
