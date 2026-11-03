#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidatePattern('^[a-zA-Z][a-zA-Z0-9_-]{2,19}$')]
    [string]$Name = 'MynaAuthRecovery',
    [switch]$VerifyOnly
)

$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) {
    throw '64-bit PowerShell is required.'
}
if (-not $VerifyOnly -and (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue)) {
    throw 'The account already exists. No account was changed.'
}
if (-not $PSCmdlet.ShouldProcess($Name, $(if ($VerifyOnly) { 'Verify the recovery administrator' } else { 'Create and verify a local recovery administrator' }))) {
    return
}

# No passwords in arguments, files, logs or error messages.
if (-not ('MynaAuthRecoveryNative' -as [type])) { Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class MynaAuthRecoveryNative {
    [DllImport("advapi32.dll", EntryPoint="LogonUserW", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LogonUser(string user, string domain, IntPtr password, uint type, uint provider, out IntPtr token);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@
}

$recoveryPassword = Read-Host 'Recovery password (keep it outside this repository)' -AsSecureString
$passwordConfirmation = $null
$created = $false
try {
    if (-not $VerifyOnly) {
        $passwordConfirmation = Read-Host 'Enter the recovery password again' -AsSecureString
        if ($recoveryPassword.Length -lt 12) { throw 'Use a recovery password of at least 12 characters.' }
        $firstPointer = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($recoveryPassword)
        $secondPointer = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($passwordConfirmation)
        try {
            $difference = $recoveryPassword.Length -bxor $passwordConfirmation.Length
            for ($index = 0; $index -lt [Math]::Min($recoveryPassword.Length, $passwordConfirmation.Length); $index++) {
                $difference = $difference -bor ([Runtime.InteropServices.Marshal]::ReadInt16($firstPointer, $index * 2) -bxor [Runtime.InteropServices.Marshal]::ReadInt16($secondPointer, $index * 2))
            }
            if ($difference -ne 0) { throw 'The passwords do not match. No account was created.' }
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($firstPointer)
            [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($secondPointer)
        }
        New-LocalUser -Name $Name -Password $recoveryPassword -Description 'MynaAuth development recovery account' | Out-Null
        $created = $true
    }

    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
    $recoveryUser = Get-LocalUser -Name $Name
    if (-not $recoveryUser.Enabled) { throw 'The recovery account is disabled.' }
    if ($created) { Add-LocalGroupMember -Group $adminGroup -Member $recoveryUser }
    $member = Get-LocalGroupMember -Group $adminGroup | Where-Object { $_.SID.Value -eq $recoveryUser.SID.Value }
    if (-not $member) { throw 'The account is not a local administrator.' }

    $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($recoveryPassword)
    $recoveryToken = [IntPtr]::Zero
    try {
        if (-not [MynaAuthRecoveryNative]::LogonUser($Name, $env:COMPUTERNAME, $passwordPointer, 2, 0, [ref]$recoveryToken)) {
            throw 'Recovery password authentication failed. No verification marker was recorded.'
        }
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($passwordPointer)
        if ($recoveryToken -ne [IntPtr]::Zero) { [MynaAuthRecoveryNative]::CloseHandle($recoveryToken) | Out-Null }
    }

    # Record only the account SID and verification time; never record the password.
    $markerKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\MynaAuth', $true)
    try {
        $registryAcl = New-Object System.Security.AccessControl.RegistrySecurity
        $registryAcl.SetAccessRuleProtection($true, $false)
        foreach ($allowedSid in @('S-1-5-18', 'S-1-5-32-544')) {
            $identity = New-Object System.Security.Principal.SecurityIdentifier($allowedSid)
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule($identity, 'FullControl', 'ContainerInherit', 'None', 'Allow')
            $registryAcl.AddAccessRule($rule)
        }
        $markerKey.SetAccessControl($registryAcl)
        $markerKey.SetValue('RecoverySid', $recoveryUser.SID.Value)
        $markerKey.SetValue('RecoveryVerifiedUtc', [DateTimeOffset]::UtcNow.ToString('O'))
    }
    finally { $markerKey.Dispose() }
    Write-Host ('Recovery administrator ready: .\' + $Name)
    Write-Host 'Switch user and test a real password sign-in before installing the credential provider.'
    Write-Host 'Do not delete this account until logon testing is finished.'
}
catch {
    if ($created) {
        Remove-LocalUser -Name $Name
    }
    throw
}
finally {
    $recoveryPassword.Dispose()
    if ($null -ne $passwordConfirmation) { $passwordConfirmation.Dispose() }
}
