
Write-Host "Creating a temp directory for DSC mof file"
mkdir c:\dsc

Write-Host "Creating configuration to edit local security policies as per CIS guideline"

Configuration CIS_AC_POL {
    Import-DscResource -ModuleName SecurityPolicyDsc
    Import-DscResource -Name AccountPolicy
    Import-DscResource -ModuleName AuditPolicyDsc

   $LegalNoticeText = @'
UNAUTHORIZED ACCESS - Unauthorized access to this system will expose you to criminal prosecution and civil proceedings.
AUTHORIZED ACCESS - Authorized users must use company computer assets and services, including hardware, software, and services provided by company or company contractors, in accordance with applicable law and company policies. Any other use is prohibited and will expose the user to criminal penalties, civil proceedings, and company disciplinary action, including immediate termination, to the fullest extent not expressly prohibited by applicable law.
EXPECTATIONS OF PRIVACY - Except as otherwise provided by contract or applicable law, all information and data sent or received through, or contained in company computers, computer systems, or networks, including electronic mail and Internet usage logs, is the property of the company and is not the property, nor the private information, of the user. Subject to applicable law, the company reserves the right to access, filter, delete, monitor, intercept, inspect and disclose all information sent or received through or stored in company computer assets, at any time without prior notice, for any purpose, including compliance with law enforcement requests and applicable laws, protection of company assets, or to reduce demands on company E-Mail systems and storage capabilities.
'@


    Node "localhost"
    {

        UserRightsAssignment Access_this_computer_from_the_network {
            Identity = 'Builtin\Administrators'
            Policy   = 'Access_this_computer_from_the_network'
            Ensure   = 'Present'
        }
        UserRightsAssignment Adjust_memory_quotas_for_a_process {
            Identity = 'Builtin\Administrators'
            Policy   = 'Adjust_memory_quotas_for_a_process'
            Ensure   = 'Present'
        }
        UserRightsAssignment Allow_log_on_locally {
            Identity = 'Builtin\Administrators'
            Policy   = 'Allow_log_on_locally'
            Ensure   = 'Present'
        }
        UserRightsAssignment Allow_log_on_through_Remote_Desktop_Services {
            Identity = 'Builtin\Administrators'
            Policy   = 'Allow_log_on_through_Remote_Desktop_Services'
            Ensure   = 'Present'
        }
        UserRightsAssignment Back_up_files_and_directories {
            Identity = 'Builtin\Administrators'
            Policy   = 'Back_up_files_and_directories'
            Ensure   = 'Present'
        }
        UserRightsAssignment Bypass_traverse_checking {
            Identity = 'Builtin\Administrators'
            Policy   = 'Bypass_traverse_checking'
            Ensure   = 'Present'
        }
        UserRightsAssignment Change_the_system_time {
            Identity = 'Builtin\Administrators'
            Policy   = 'Change_the_system_time'
            Ensure   = 'Present'
        }
        UserRightsAssignment Change_the_time_zone {
            Identity = 'Builtin\Administrators'
            Policy   = 'Change_the_time_zone'
            Ensure   = 'Present'
        }
        UserRightsAssignment Create_a_pagefile {
            Identity = 'Builtin\Administrators'
            Policy   = 'Create_a_pagefile'
            Ensure   = 'Present'
        }
        UserRightsAssignment Create_global_objects {
            Identity = 'Builtin\Administrators'
            Policy   = 'Create_global_objects'
            Ensure   = 'Present'
        }
        UserRightsAssignment Create_symbolic_links {
            Identity = 'Builtin\Administrators'
            Policy   = 'Create_symbolic_links'
            Ensure   = 'Present'
        }
        UserRightsAssignment Debug_programs {
            Identity = 'Builtin\Administrators'
            Policy   = 'Debug_programs'
            Ensure   = 'Present'

        }
        UserRightsAssignment Force_shutdown_from_a_remote_system {
            Identity = 'Builtin\Administrators'
            Policy   = 'Force_shutdown_from_a_remote_system'
            Ensure   = 'Present'
        }
        UserRightsAssignment Generate_security_audits {
            Identity = '*S-1-5-20', '*S-1-5-19'
            Policy   = 'Generate_security_audits'
            Ensure   = 'Present'
        }
        UserRightsAssignment Impersonate_a_client_after_authentication {
            Identity = '*S-1-5-6', '*S-1-5-32-544', '*S-1-5-20', '*S-1-5-19'
            Policy   = 'Impersonate_a_client_after_authentication'
            Ensure   = 'Present'
        }
        UserRightsAssignment Increase_a_process_working_set {
            Identity = '*S-1-5-32-545'
            Policy   = 'Increase_a_process_working_set'
            Ensure   = 'Present'
        }
        UserRightsAssignment Increase_scheduling_priority {
            Identity = '*S-1-5-32-544'
            Policy   = 'Increase_scheduling_priority'
            Ensure   = 'Present'
        }
        UserRightsAssignment Load_and_unload_device_drivers {
            Identity = '*S-1-5-32-544'
            Policy   = 'Load_and_unload_device_drivers'
            Ensure   = 'Present'
        }
        UserRightsAssignment Log_on_as_a_batch_job {
            Identity = '*S-1-5-32-559', '*S-1-5-32-551', '*S-1-5-32-544'
            Policy   = 'Log_on_as_a_batch_job'
            Ensure   = 'Present'
        }
        UserRightsAssignment Log_on_as_a_service {
            Identity = '*S-1-5-80-0'
            Policy   = 'Log_on_as_a_service'
            Ensure   = 'Present'
        }
        UserRightsAssignment Manage_auditing_and_security_log {
            Identity = '*S-1-5-32-544'
            Policy   = 'Manage_auditing_and_security_log'
            Ensure   = 'Present'
        }
        UserRightsAssignment Modify_firmware_environment_values {
            Identity = '*S-1-5-32-544'
            Policy   = 'Modify_firmware_environment_values'
            Ensure   = 'Present'
        }
        UserRightsAssignment Perform_volume_maintenance_tasks {
            Identity = '*S-1-5-32-544'
            Policy   = 'Perform_volume_maintenance_tasks'
            Ensure   = 'Present'
        }
        UserRightsAssignment Profile_single_process {
            Identity = '*S-1-5-32-544'
            Policy   = 'Profile_single_process'
            Ensure   = 'Present'
        }
        UserRightsAssignment Profile_system_performance {
            Identity = '*S-1-5-32-544'
            Policy   = 'Profile_system_performance'
            Ensure   = 'Present'
        }
        UserRightsAssignment Remove_computer_from_docking_station {
            Identity = '*S-1-5-32-544'
            Policy   = 'Remove_computer_from_docking_station'
            Ensure   = 'Present'
        }
        UserRightsAssignment Replace_a_process_level_token {
            Identity = '*S-1-5-20', '*S-1-5-19'
            Policy   = 'Replace_a_process_level_token'
            Ensure   = 'Present'
        }
        UserRightsAssignment Restore_files_and_directories {
            Identity = '*S-1-5-32-551', '*S-1-5-32-544'
            Policy   = 'Restore_files_and_directories'
            Ensure   = 'Present'
        }
        UserRightsAssignment Shut_down_the_system {
            Identity = '*S-1-5-32-551', '*S-1-5-32-544'
            Policy   = 'Shut_down_the_system'
            Ensure   = 'Present'
        }
        UserRightsAssignment Take_ownership_of_files_or_other_objects {
            Identity = '*S-1-5-32-544'
            Policy   = 'Take_ownership_of_files_or_other_objects'
            Ensure   = 'Present'
        }
        SecurityOption 'SecurityOptions' {
            Name                                                                                                            = 'SecurityOptions'
            Accounts_Administrator_account_status                                                                           = 'Enabled'
            Accounts_Guest_account_status                                                                                   = 'Disabled'
            Accounts_Rename_administrator_account                                                                           = 'Administrator'
            Accounts_Rename_guest_account                                                                                   = 'interloper'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
            Audit_Audit_the_use_of_Backup_and_Restore_privilege                                                             = 'Enabled'
            Devices_Allow_undock_without_having_to_log_on                                                                   = 'Disabled'
            Devices_Allowed_to_format_and_eject_removable_media                                                             = 'Administrators'
            Devices_Restrict_CD_ROM_access_to_locally_logged_on_user_only                                                   = 'Disabled'
            Devices_Restrict_floppy_access_to_locally_logged_on_user_only                                                   = 'Disabled'
            Domain_controller_Allow_server_operators_to_schedule_tasks                                                      = 'Enabled'
            Domain_controller_Refuse_machine_account_password_changes                                                       = 'Disabled'
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always                                              = 'Disabled'
            Interactive_logon_Do_not_display_last_user_name                                                                 = 'Enabled'
            Interactive_logon_Message_text_for_users_attempting_to_log_on                                                   = $LegalNoticeText
            Interactive_logon_Message_title_for_users_attempting_to_log_on                                                  = 'WARNING - Private Computer System'
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available                 = '10'
            Network_access_Allow_anonymous_SID_Name_translation                                                             = 'Disabled'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts                                               = 'Enabled'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares                                    = 'Enabled'
            Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication                     = 'Enabled'
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users                                                = 'Disabled'
            Network_access_Named_Pipes_that_can_be_accessed_anonymously                                                     = ([System.String]::Empty)
            Network_access_Remotely_accessible_registry_paths                                                               = ([System.String]::Empty)
            Network_access_Remotely_accessible_registry_paths_and_subpaths                                                  = ([System.String]::Empty)
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares                                              = 'Enabled'
            Network_access_Shares_that_can_be_accessed_anonymously                                                          = ([System.String]::Empty)
            Network_access_Sharing_and_security_model_for_local_accounts                                                    = 'Classic - Local users authenticate as themselves'
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM                                           = 'Enabled'
            Network_security_Allow_LocalSystem_NULL_session_fallback                                                        = 'Disabled'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change                                    = 'Disabled'
            Network_security_LAN_Manager_authentication_level                                                               = 'Send NTLM responses only'
        }
         AuditPolicySubcategory LogonSuccess {
            Name      = "Logon"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory LogonFailure {
            Name      = "Logon"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory LogoffSuccess {
            Name      = "Logoff"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory LogoffFailure {
            Name      = "Logoff"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory AccountLockoutSuccess {
            Name      = "Account Lockout"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory AccountLockoutFailure {
            Name      = "Account Lockout"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory SystemIntegritySuccess {
            Name      = "System Integrity"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory SystemIntegrityFailure {
            Name      = "System Integrity"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory SecurityStateChangeSuccess {
            Name      = "Security State Change"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory SecurityStateChangeFailure {
            Name      = "Security State Change"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory SpecialLogonSuccess {
            Name      = "Special Logon"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory SpecialLogonFailure {
            Name      = "Special Logon"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory OtherLogonLogoffEventsSuccess {
            Name      = "Other Logon/Logoff Events"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory OtherLogonLogoffEventsFailure {
            Name      = "Other Logon/Logoff Events"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory NetworkPolicyServerSuccess {
            Name      = "Network Policy Server"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory NetworkPolicyServerFailure {
            Name      = "Network Policy Server"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory CertificationServicesSuccess {
            Name      = "Certification Services"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory CertificationServicesFailure {
            Name      = "Certification Services"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory ApplicationGeneratedSuccess {
            Name      = "Application Generated"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory ApplicationGeneratedFailure {
            Name      = "Application Generated"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory OtherPrivilegeUseEventsSuccess {
            Name      = "Other Privilege Use Events"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory OtherPrivilegeUseEventsFailure {
            Name      = "Other Privilege Use Events"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory SensitivePrivilegeUseSuccess {
            Name      = "Sensitive Privilege Use"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory SensitivePrivilegeUseFailure {
            Name      = "Sensitive Privilege Use"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory AuthenticationPolicyChangeSuccess {
            Name      = "Authentication Policy Change"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory AuthenticationPolicyChangeFailure {
            Name      = "Authentication Policy Change"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory AuthorizationPolicyChangeSuccess {
            Name      = "Authorization Policy Change"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory AuthorizationPolicyChangeFailure {
            Name      = "Authorization Policy Change"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory OtherPolicyChangeEventsSuccess {
            Name      = "Other Policy Change Events"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory OtherPolicyChangeEventsFailure {
            Name      = "Other Policy Change Events"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory AuditPolicyChangeSuccess {
            Name      = "Audit Policy Change"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory AuditPolicyChangeFailure {
            Name      = "Audit Policy Change"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory ComputerAccountManagementSuccess {
            Name      = "Computer Account Management"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory ComputerAccountManagementFailure {
            Name      = "Computer Account Management"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory SecurityGroupManagementSuccess {
            Name      = "Security Group Management"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory SecurityGroupManagementFailure {
            Name      = "Security Group Management"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory DistributionGroupManagementSuccess {
            Name      = "Distribution Group Management"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory DistributionGroupManagementFailure {
            Name      = "Distribution Group Management"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory ApplicationGroupManagementSuccess {
            Name      = "Application Group Management"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory ApplicationGroupManagementFailure {
            Name      = "Application Group Management"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory OtherAccountManagementEventsSuccess {
            Name      = "Other Account Management Events"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory OtherAccountManagementEventsFailure {
            Name      = "Other Account Management Events"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory KerberosServiceTicketOperationsSuccess {
            Name      = "Kerberos Service Ticket Operations"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory KerberosServiceTicketOperationsFailure {
            Name      = "Kerberos Service Ticket Operations"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory OtherAccountLogonEventsSuccess {
            Name      = "Other Account Logon Events"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory OtherAccountLogonEventsFailure {
            Name      = "Other Account Logon Events"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory KerberosAuthenticationServiceSuccess {
            Name      = "Kerberos Authentication Service"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory KerberosAuthenticationServiceFailure {
            Name      = "Kerberos Authentication Service"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
        AuditPolicySubcategory CredentialValidationSuccess {
            Name      = "Credential Validation"
            AuditFlag = "Success"
            Ensure    = "Present"
        }
        AuditPolicySubcategory CredentialValidationFailure {
            Name      = "Credential Validation"
            AuditFlag = "Failure"
            Ensure    = "Present"
        }
         #region Registry
        Registry WSManClient {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client"
            ValueName = "Client"
            ValueData = "*"
            ValueType = "String"
        }
        Registry AutoReboot {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl"
            ValueName = "AutoReboot"
            ValueData = "1"
            ValueType = "DWord"
        }
        Registry CrashDumpEnabled {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl"
            ValueName = "CrashDumpEnabled"
            ValueData = "3"
            ValueType = "DWord"
        }
        Registry Overwrite {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl"
            ValueName = "Overwrite"
            ValueData = "1"
            ValueType = "DWord"
        }
        Registry LogEvent {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl"
            ValueName = "LogEvent"
            ValueData = "1"
            ValueType = "DWord"
        }
        Registry MinidumpsCount {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl"
            ValueName = "MinidumpsCount"
            ValueData = "50"
            ValueType = "DWord"
        }
        Registry DumpFile {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl"
            ValueName = "DumpFile"
            ValueData = "%SystemRoot%\Minidump-Type"
            ValueType = "ExpandString"
        }
        Registry MinidumpDir {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl"
            ValueName = "MinidumpDir"
            ValueData = "%SystemRoot%\Minidump"
            ValueType = "ExpandString"
        }
        Registry SendAlert {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl"
            ValueName = "SendAlert"
            ValueData = "0"
            ValueType = "DWord"
        }
        Registry KernelDumpOnly {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl"
            ValueName = "KernelDumpOnly"
            ValueData = "0"
            ValueType = "DWord"
        }
        Registry RDSAlwaysPromptPW {
            Force = $True
            Ensure = 'Present'
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fPromptForPassword'
            ValueData = '1'
            ValueType = 'DWord'
        }
        Registry RDSDisconnectedTimeout {
            Force = $True
            Ensure = 'Present'
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MaxDisconnectionTime'
            ValueData = '1800000'
            ValueType = 'DWord'
        }
        Registry RDSIdleTimeout {
            Force = $True
            Ensure = 'Present'
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MaxIdleTime'
            ValueData = '10800000'
            ValueType = 'DWord'
        }
        Registry RDSNoActiveTimeout {
            Force = $True
            Ensure = 'Present'
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MaxConnectionTime'
            ValueData = '0'
            ValueType = 'DWord'
        }
        Registry RDSTerminateTimedOutSession {
            Force = $True
            Ensure = 'Present'
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fResetBroken'
            ValueData = '1'
            ValueType = 'DWord'
        }
        Registry RDSNoRemoteControl {
            Force = $True
            Ensure = 'Present'
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'Shadow'
            ValueData = '0'
            ValueType = 'DWord'
        }
        Registry RDSNoDriveRedirect {
            Force = $True
            Ensure = 'Present'
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableCdm'
            ValueData = '0'
            ValueType = 'DWord'
        }
        Registry RDSNoLPTRedirect {
            Force = $True
            Ensure = 'Present'
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableLPT'
            ValueData = '0'
            ValueType = 'DWord'
        }
        Registry RDSNoCOMRedirect {
            Force = $True
            Ensure = 'Present'
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableCcm'
            ValueData = '0'
            ValueType = 'DWord'
        }
        Registry RDSNoPnPRedirect {
            Force = $True
            Ensure = 'Present'
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisablePNPRedir'
            ValueData = '0'
            ValueType = 'DWord'
        }
        Registry RDSNoPrintRedirect {
            Force = $True
            Ensure = 'Present'
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableCpm'
            ValueData = '0'
            ValueType = 'DWord'
        }
        Registry ElevateNonAdmins {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            ValueName = "ElevateNonAdmins"
            ValueData = "0"
            ValueType = "dword"
        }
        Registry WUServer {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            ValueName = "WUServer"
            ValueData = "http://10.201.9.9:8530/"
            ValueType = "string"
        }
        Registry WUStatusServer {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            ValueName = "WUStatusServer"
            ValueData = "http://10.201.9.9:8530/"
            ValueType = "string"
        }
        Registry TargetGroupEnabled {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            ValueName = "TargetGroupEnabled"
            ValueData = "1"
            ValueType = "dword"
        }
        Registry TargetGroup {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            ValueName = "TargetGroup"
            ValueData = "Azure"
            ValueType = "string"
        }
        Registry NoAutoRebootWithLoggedOnUsers {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "NoAutoRebootWithLoggedOnUsers"
            ValueData = "1"
            ValueType = "dword"
        }
        Registry AutoInstallMinorUpdates {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "AutoInstallMinorUpdates"
            ValueData = "0"
            ValueType = "dword"
        }
        Registry NoAUShutdownOption {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "NoAUShutdownOption"
            ValueData = "1"
            ValueType = "dword"
        }
        Registry NoAUAsDefaultShutdownOption {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "NoAUAsDefaultShutdownOption"
            ValueData = "1"
            ValueType = "dword"
        }
        Registry RescheduleWaitTimeEnabled {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "RescheduleWaitTimeEnabled"
            ValueData = "0"
            ValueType = "dword"
        }
        Registry RebootWarningTimeoutEnabled {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "RebootWarningTimeoutEnabled"
            ValueData = "0"
            ValueType = "dword"
        }
        Registry RebootRelaunchTimeoutEnabled {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "RebootRelaunchTimeoutEnabled"
            ValueData = "1"
            ValueType = "dword"
        }
        Registry RebootRelaunchTimeout {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "RebootRelaunchTimeout"
            ValueData = "15"
            ValueType = "dword"
        }
        Registry DetectionFrequencyEnabled {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "DetectionFrequencyEnabled"
            ValueData = "1"
            ValueType = "dword"
        }
        Registry DetectionFrequency {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "DetectionFrequency"
            ValueData = "22"
            ValueType = "dword"
        }
        Registry NoAutoUpdate {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "NoAutoUpdate"
            ValueData = "0"
            ValueType = "dword"
        }
        Registry AUOptions {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "AUOptions"
            ValueData = "3"
            ValueType = "dword"
        }
        Registry ScheduledInstallDay {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "ScheduledInstallDay"
            ValueData = "0"
            ValueType = "dword"
        }
        Registry ScheduledInstallTime {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "ScheduledInstallTime"
            ValueData = "3"
            ValueType = "dword"
        }
        Registry UseWUServer {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "UseWUServer"
            ValueData = "1"
            ValueType = "dword"
        }
        Registry DisableIPv6 {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters"
            ValueName = "DisabledComponents"
            ValueData = "255"
            ValueType = "DWord"
        }
        Registry AppMaxSize {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application"
            ValueName = "MaxSize"
            ValueData = "20971520"
            ValueType = "dword"
        }
        Registry AppRetention {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application"
            ValueName = "Retention"
            ValueData = "0"
            ValueType = "dword"
        }
        Registry AppRestrictGuestAccess {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application"
            ValueName = "RestrictGuestAccess"
            ValueData = "1"
            ValueType = "dword"
        }
        Registry SecMaxSize {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security"
            ValueName = "MaxSize"
            ValueData = "20971520"
            ValueType = "dword"
        }
        Registry SecRetention {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security"
            ValueName = "Retention"
            ValueData = "0"
            ValueType = "dword"
        }
        Registry SecRestrictGuestAccess {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security"
            ValueName = "RestrictGuestAccess"
            ValueData = "1"
            ValueType = "dword"
        }
        Registry SysMaxSize {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System"
            ValueName = "MaxSize"
            ValueData = "20971520"
            ValueType = "dword"
        }
        Registry SysRetention {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System"
            ValueName = "Retention"
            ValueData = "0"
            ValueType = "dword"
        }
        Registry SysRestrictGuestAccess {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System"
            ValueName = "RestrictGuestAccess"
            ValueData = "1"
            ValueType = "dword"
        }
        Registry CDRomRemoval {
            Force     = $True
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdrom"
            ValueName = "Start"
            ValueData = "4"
            ValueType = "dword"
        }
        Registry MaxInstanceCount {
            Ensure    = "Present"
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            ValueName = "MaxInstanceCount"
            Hex       = $True
            Force     = $True
            ValueData = "ffffffff"
            ValueType = "dword"
        }
    }

    }

    CIS_AC_POL -OutputPath c:\dsc\
    Start-DscConfiguration -Path c:\dsc\ -Wait -Force -Verbose -debug
Write-Host "Security Configuration is applied"
Write-Host "Pausing for 15 seconds"
    start-sleep -s 15
Write-Host "Moving on to the password policy script"
