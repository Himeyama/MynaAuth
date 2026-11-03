[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('patch', 'minor', 'major')][string]$Part,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Message,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Summary,
    [switch]$Push
)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    function Invoke-Git {
        param([string[]]$Arguments)
        & git @Arguments
        if ($LASTEXITCODE -ne 0) { throw ('git failed: ' + ($Arguments -join ' ')) }
    }
    $branch = & git symbolic-ref --short HEAD
    if ($LASTEXITCODE -ne 0) { throw 'A branch must be checked out.' }
    $staged = @(& git diff --cached --name-only)
    if ($LASTEXITCODE -ne 0 -or $staged.Count -eq 0) { throw 'Stage the intended changes first.' }
    if ($staged -contains 'Directory.Build.props' -or $staged -contains 'CHANGELOG.md') {
        throw 'Version files must be clean; the script updates and stages them.'
    }
    Invoke-Git -Arguments @('diff', '--exit-code', '--', 'Directory.Build.props', 'CHANGELOG.md')
    Invoke-Git -Arguments @('diff', '--cached', '--check')
    $propertiesPath = Join-Path $PSScriptRoot 'Directory.Build.props'
    $changelogPath = Join-Path $PSScriptRoot 'CHANGELOG.md'
    $properties = [IO.File]::ReadAllText($propertiesPath)
    [xml]$document = $properties
    $current = [version][string]$document.Project.PropertyGroup.Version
    $next = switch ($Part) {
        'major' { [version]::new($current.Major + 1, 0, 0) }
        'minor' { [version]::new($current.Major, $current.Minor + 1, 0) }
        'patch' { [version]::new($current.Major, $current.Minor, $current.Build + 1) }
    }
    if ($next.Major -gt 65535 -or $next.Minor -gt 65535 -or $next.Build -gt 65535) {
        throw 'Version components must be at most 65535.'
    }
    $tag = 'v' + $next.ToString()
    $existing = @(& git tag --list $tag)
    if ($LASTEXITCODE -ne 0 -or $existing.Count -ne 0) { throw 'Target tag already exists or could not be checked.' }
    if (-not $PSCmdlet.ShouldProcess($tag, "Update version and changelog, commit and tag (push: $Push)")) { return }
    $updated = $properties.Replace("<Version>$current</Version>", "<Version>$next</Version>")
    if ($updated -eq $properties) { throw 'Could not replace the application version.' }
    $changelog = [IO.File]::ReadAllText($changelogPath)
    $heading = '# 変更履歴'
    if (-not $changelog.StartsWith($heading)) { throw 'Unexpected changelog heading.' }
    $entry = "`n`n## $tag`n`n- $Summary"
    $changelog = $heading + $entry + $changelog.Substring($heading.Length)
    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($propertiesPath, $updated, $encoding)
    [IO.File]::WriteAllText($changelogPath, $changelog, $encoding)
    Invoke-Git -Arguments @('add', '--', 'Directory.Build.props', 'CHANGELOG.md')
    Invoke-Git -Arguments @('commit', '-m', $Message)
    Invoke-Git -Arguments @('tag', '-a', $tag, '-m', $tag)
    if ($Push) {
        Invoke-Git -Arguments @('push', '--atomic', 'origin', $branch, "refs/tags/$tag")
    }
    Write-Output "Created $tag"
}
finally { Pop-Location }
