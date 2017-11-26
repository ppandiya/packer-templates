choco install dotnet4.5 -y
choco install powershell-packagemanagement -y
choco upgrade powershell-packagemanagement -y
choco install powershell --version 5.0.10586.20151218

Get-PackageProvider -Name NuGet -Force

start-sleep -s 15

Install-Module -Name "PSDscResources" -Force
Install-Module -Name "SecurityPolicyDsc" -Force
Install-Module -Name "AuditPolicyDsc" -Force
