# Account Policy setting using powershell as AccountPolicy Resource type has a bug.

Write-Host "Setting the Password and Account Policies using secedit as per CIS guidelines"

secedit /export /cfg c:\secpol.cfg
(gc C:\secpol.cfg)| Foreach-Object {

$_ -replace "PasswordComplexity = 0", "PasswordComplexity =1" `
-replace "PasswordHistorySize = 0", "PasswordHistorySize = 24" `
-replace "LockoutDuration = 30" , "LockoutDuration = 60" `
-replace "ResetLockoutCount = 0" , "ResetLockoutCount = 30" `
-replace "MinimumPasswordLength = 0", "MinimumPasswordLength = 14" `
-replace "MinimumPasswordAge = 0" , "MinimumPasswordAge = 1" `
-replace "MaximumPasswordAge = 42" , "MaximumPasswordAge = 60" `
-replace "LockoutBadCount = 4", "LockoutBadCount = 5"

} |Set-Content  C:\secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
rm -force c:\secpol.cfg -confirm:$false

Write-Host "Password policy and account policy has been set to match CIS GuideLine"
