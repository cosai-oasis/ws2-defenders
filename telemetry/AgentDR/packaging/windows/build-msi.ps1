<#
.SYNOPSIS
  Build a signed AgentDR MSI for Windows.

.DESCRIPTION
  Wraps the WiX toolset (candle + light) and signtool. Run from the repo
  root on a Windows host with the WiX 3 toolset installed
  (`dotnet tool install --global wix --version 4.*` for WiX 4 also works
  with minor argument changes).

.PARAMETER Version
  Three-part version string, e.g. 0.2.0.

.PARAMETER BinaryPath
  Path to the release adr-agent.exe (x86_64-pc-windows-msvc).

.PARAMETER SigningCertSubject
  Optional subject name of the code-signing certificate in Cert:\CurrentUser\My
  or Cert:\LocalMachine\My. When provided, the MSI is signed with signtool.

.PARAMETER TimestampUrl
  RFC 3161 timestamping URL (default DigiCert).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Version,
  [Parameter(Mandatory=$true)][string]$BinaryPath,
  [string]$SigningCertSubject = "",
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path dist | Out-Null
$out = "dist\agentdr-$Version.msi"
$config = "packaging\windows\default-config.toml"

# candle + light (WiX 3)
candle -arch x64 `
  -dVersion="$Version" `
  -dBinaryPath="$BinaryPath" `
  -dConfigPath="$config" `
  -ext WixUtilExtension `
  -o "$env:TEMP\agentdr.wixobj" `
  packaging\windows\agentdr.wxs

light -ext WixUtilExtension `
  -o $out `
  "$env:TEMP\agentdr.wixobj"

if ($SigningCertSubject) {
  signtool sign /n "$SigningCertSubject" /fd SHA256 /tr "$TimestampUrl" /td SHA256 $out
}

Write-Host "Wrote $out"
