[CmdletBinding()]
param([string]$OutputDirectory = (Join-Path $PSScriptRoot 'artifacts/release'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Dotnet([string[]]$Arguments) {
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet $($Arguments[0]) failed ($LASTEXITCODE)." }
}

Push-Location $PSScriptRoot
try {
    [xml]$props = Get-Content Directory.Build.props
    $version = [string]$props.Project.PropertyGroup.Version
    if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'A stable semantic version is required.' }
    $output = [IO.Path]::GetFullPath($OutputDirectory)
    $feed = Join-Path $output $version
    New-Item -ItemType Directory -Force $feed | Out-Null
    Invoke-Dotnet @('build', 'Ai.Tlbx.Sip.slnx', '-c', 'Release')
    foreach ($framework in @('net10.0', 'net11.0')) {
        Invoke-Dotnet @('run', '--project', 'tests/Ai.Tlbx.Sip.Tests', '-c', 'Release', '-f', $framework, '--no-build')
    }
    foreach ($id in @('Ai.Tlbx.Sip', 'Ai.Tlbx.VoiceAssistant.Sip')) {
        Invoke-Dotnet @('pack', "src/$id", '-c', 'Release', '--no-build', '-o', $feed)
        $archive = [IO.Compression.ZipFile]::OpenRead((Join-Path $feed "$id.$version.nupkg"))
        try {
            $entry = @($archive.Entries | Where-Object FullName -like '*.nuspec')
            if ($entry.Count -ne 1) { throw 'Invalid package manifest count.' }
            $reader = [IO.StreamReader]::new($entry[0].Open())
            try { [xml]$manifest = $reader.ReadToEnd() } finally { $reader.Dispose() }
            if ($manifest.package.metadata.id -ne $id -or $manifest.package.metadata.version -ne $version -or
                $manifest.package.metadata.license.InnerText -ne 'MIT') { throw 'Package identity/version/license mismatch.' }
            if (-not $archive.GetEntry('README.md')) { throw 'Missing package readme.' }
            foreach ($framework in @('net10.0', 'net11.0')) {
                if (-not $archive.GetEntry("lib/$framework/$id.dll")) { throw "Missing $framework assembly." }
                if ($id -eq 'Ai.Tlbx.VoiceAssistant.Sip') {
                    $group = @($manifest.package.metadata.dependencies.group | Where-Object targetFramework -eq $framework)
                    $dependency = @($group.dependency | Where-Object id -eq 'Ai.Tlbx.Sip')
                    if ($dependency.Count -ne 1 -or $dependency[0].version.Trim([char[]]'[]() ') -ne $version) {
                        throw 'Adapter must reference this exact minimum SIP version on each target.'
                    }
                }
            }
        } finally { $archive.Dispose() }
    }
    # A package consumer outside the repository cannot inherit its build props or
    # accidentally resolve a sibling ProjectReference. Use a fresh package cache.
    $consumer = Join-Path ([IO.Path]::GetTempPath()) ('sip-package-consumer-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $consumer | Out-Null
    $project = Join-Path $consumer 'Consumer.csproj'
    @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><OutputType>Exe</OutputType><TargetFrameworks>net10.0;net11.0</TargetFrameworks><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable><TreatWarningsAsErrors>true</TreatWarningsAsErrors></PropertyGroup>
  <ItemGroup><PackageReference Include="Ai.Tlbx.VoiceAssistant.Sip" Version="[$version]" /></ItemGroup>
</Project>
"@ | Set-Content $project
    @'
using Ai.Tlbx.Sip;
using Ai.Tlbx.Sip.Media;
using Ai.Tlbx.VoiceAssistant.Interfaces;
using Ai.Tlbx.VoiceAssistant.Sip;
await using var manager = new SipClientManager();
var client = manager.CreateClient(new() { Id = "package-test", Registrar = "example.invalid", User = "test", Credentials = new() { Username = "test", Password = "test" } });
if (client.Status.State != SipClientState.Disconnected || !typeof(IAudioHardwareAccess).IsAssignableFrom(typeof(SipAudioHardwareAccess))) throw new Exception("Package API mismatch.");
if (new PcmResampler(24000, 8000).Process(new short[24000], true).Length != 8000) throw new Exception("Package resampler mismatch.");
if (!await manager.RemoveClientAsync(client.Id)) throw new Exception("Package lifecycle mismatch.");
Console.WriteLine("PASS isolated package consumer (no project references or network calls)");
'@ | Set-Content (Join-Path $consumer 'Program.cs')
    $cache = Join-Path $consumer 'packages'
    $sources = Join-Path $consumer 'NuGet.Config'
    $escapedFeed = [Security.SecurityElement]::Escape($feed)
    @"
<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear/><add key="release" value="$escapedFeed"/><add key="nuget.org" value="https://api.nuget.org/v3/index.json"/></packageSources></configuration>
"@ | Set-Content $sources
    Invoke-Dotnet @('restore', $project, '--configfile', $sources, '--packages', $cache)
    foreach ($framework in @('net10.0', 'net11.0')) {
        Invoke-Dotnet @('run', '--project', $project, '-c', 'Release', '-f', $framework, '--no-restore')
    }
    $records = @(Get-ChildItem $feed -Filter '*.nupkg' | ForEach-Object {
        [ordered]@{ file = $_.Name; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); bytes = $_.Length }
    })
    if ($records.Count -ne 2) { throw 'Expected exactly two release packages.' }
    [ordered]@{ version = $version; packages = $records; consumer = $consumer } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $feed 'verification.json')
    Write-Output "Verified release packages: $feed"
} finally { Pop-Location }
