#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([switch]$RemoveEnrollment)
$ErrorActionPreference = 'Stop'
$providerId = '{37167329-B6D8-4379-90A9-0D350F82F31A}'
$providerKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\' + $providerId
$comKey = 'HKLM:\SOFTWARE\Classes\CLSID\' + $providerId
if (-not $PSCmdlet.ShouldProcess('MynaAuth', 'Remove only the MynaAuth credential provider registration')) { return }
if (Test-Path -LiteralPath $providerKey) { Remove-Item -LiteralPath $providerKey -Recurse -Force }
if (Test-Path -LiteralPath $comKey) { Remove-Item -LiteralPath $comKey -Recurse -Force }
if ($RemoveEnrollment) {
    $library = Join-Path $env:ProgramFiles 'MynaAuthSignIn\MynaAuth.Windows.dll'
    if (-not (Test-Path -LiteralPath $library)) { throw 'Use the setup application to remove protected credentials.' }
    # Secret removal uses the .NET 8 setup process, never sends a password in arguments.
    $setup = Join-Path $env:ProgramFiles 'MynaAuthSignIn\MynaAuth.Setup.exe'
    $cleanupProcess = Start-Process -FilePath $setup -ArgumentList '--remove-enrollment' -PassThru -Wait -WindowStyle Hidden
    if ($cleanupProcess.ExitCode -ne 0) { throw 'Credential cleanup failed. Provider registration was removed.' }
}
Write-Host 'MynaAuth registration removed. Standard providers and recovery accounts were not changed.'
Write-Host 'Installed files are retained because LogonUI may still have the DLL loaded.'
