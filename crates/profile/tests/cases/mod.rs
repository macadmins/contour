//! The request-to-key cases, as data.
//!
//! Kept apart from the test that reads them so `contour-ask eval` can run
//! the same requests through a model. See `intent_cases.rs` for where each
//! source comes from.

/// (source, request, payload type, key path)
#[rustfmt::skip]
pub const CASES: &[(&str, &str, &str, &str)] = &[
    // Written for this file: Apple profiles and declarations.
    ("own", "turn off airdrop", "com.apple.applicationaccess", "allowAirDrop"),
    ("own", "disable the camera", "com.apple.applicationaccess", "allowCamera"),
    ("own", "block screenshots and screen recording", "com.apple.applicationaccess", "allowScreenShot"),
    ("own", "force encrypted backups", "com.apple.applicationaccess", "forceEncryptedBackup"),
    ("own", "stop documents syncing to icloud", "com.apple.applicationaccess", "allowCloudDocumentSync"),
    ("own", "do not allow installing apps", "com.apple.applicationaccess", "allowAppInstallation"),
    ("own", "hide safari", "com.apple.applicationaccess", "allowSafari"),
    ("own", "ask for the password 5 seconds after the screen saver starts", "com.apple.screensaver", "askForPasswordDelay"),
    ("own", "start the screen saver after 10 minutes idle", "com.apple.screensaver", "idleTime"),
    ("own", "turn the firewall on", "com.apple.security.firewall", "EnableFirewall"),
    ("own", "show a banner text on the login window", "com.apple.loginwindow", "LoginwindowText"),
    ("own", "allow our vendor's system extensions", "com.apple.system-extension-policy", "AllowedSystemExtensions"),
    ("own", "passcode of at least 12 characters on the legacy password policy", "com.apple.mobiledevice.passwordpolicy", "minLength"),
    ("own", "how many times a user can skip turning on filevault at login", "com.apple.MCX.FileVault2", "DeferForceAtUserLoginMaxBypassAttempts"),
    ("own", "require a passcode with a minimum length of 8", "com.apple.configuration.passcode.settings", "MinimumLength"),
    // Written for this file: Windows CSP settings.
    ("windows", "deny write access to removable disks", "Storage", "RemovableDiskDenyWriteAccess"),
    ("windows", "minimum device password length", "DeviceLock", "MinDevicePasswordLength"),
    ("windows", "limit telemetry sent to microsoft", "System", "AllowTelemetry"),
    ("windows", "block the camera", "Camera", "AllowCamera"),
    // CIS level 1 and 2 (macOS), from mSCP: rule title -> the key the rule sets.
    ("cis", "Disable iCloud Desktop and Document Folder Sync", "com.apple.applicationaccess", "allowCloudDesktopAndDocuments"), // icloud_sync_disable
    ("cis", "Disable AirDrop", "com.apple.applicationaccess", "allowAirDrop"), // os_airdrop_disable
    ("cis", "Disable Bonjour Multicast", "com.apple.mDNSResponder", "NoMulticastAdvertisements"), // os_bonjour_disable
    ("cis", "Enforce Installation of XProtect Remediator and Gatekeeper Updates Automatically", "com.apple.SoftwareUpdate", "ConfigDataInstall"), // os_config_data_install_enforce
    ("cis", "Enable Gatekeeper", "com.apple.systempolicy.control", "EnableAssessment"), // os_gatekeeper_enable
    ("cis", "Disable Apple Intelligence Mail Smart Replies", "com.apple.applicationaccess", "allowMailSmartReplies"), // os_mail_smart_reply_disable
    ("cis", "Disable Apple Intelligence Mail Summary", "com.apple.applicationaccess", "allowMailSummary"), // os_mail_summary_disable
    ("cis", "Disable the Ability for an Admin to Disable Managed Preferences", "com.apple.loginwindow", "AdminMayDisableMCX"), // os_mcx_disable_disable
    ("cis", "Disable Apple Intelligence Notes Transcription", "com.apple.applicationaccess", "allowNotesTranscription"), // os_notes_transcription_disable
    ("cis", "Disable Apple Intelligence Notes Transcription Summary", "com.apple.applicationaccess", "allowNotesTranscriptionSummary"), // os_notes_transcription_summary_disable
    ("cis", "Enforce On Device Dictation", "com.apple.applicationaccess", "forceOnDeviceOnlyDictation"), // os_on_device_dictation_enforce
    ("cis", "Disable Apple Intelligence Safari Reader Summary", "com.apple.applicationaccess", "allowSafariSummary"), // os_safari_reader_summary_disable
    ("cis", "Ensure Secure Keyboard Entry Terminal.app is Enabled", "com.apple.Terminal", "SecureKeyboardEntry"), // os_terminal_secure_keyboard_enable
    ("cis", "Disable Apple Intelligence Writing Tools", "com.apple.applicationaccess", "allowWritingTools"), // os_writing_tools_disable
    ("cis", "Limit Consecutive Failed Login Attempts to 6", "com.apple.mobiledevice.passwordpolicy", "maxFailedAttempts"), // pwpolicy_account_lockout_enforce
    ("cis", "Prohibit Password Reuse for a Minimum of 5 Generations", "com.apple.mobiledevice.passwordpolicy", "pinHistory"), // pwpolicy_history_enforce
    ("cis", "Restrict Maximum Password Lifetime to 60 Days", "com.apple.mobiledevice.passwordpolicy", "maxPINAgeInDays"), // pwpolicy_max_lifetime_enforce
    ("cis", "Require a Minimum Password Length of 6 Characters", "com.apple.mobiledevice.passwordpolicy", "minLength"), // pwpolicy_minimum_length_enforce
    ("cis", "Disable Airplay Receiver", "com.apple.applicationaccess", "allowAirPlayIncomingRequests"), // system_settings_airplay_receiver_disable
    ("cis", "Disable Content Caching Service", "com.apple.applicationaccess", "allowContentCaching"), // system_settings_content_caching_disable
    ("cis", "Disable Sending Diagnostic and Usage Data to Apple", "com.apple.SubmitDiagInfo", "AutoSubmit"), // system_settings_diagnostics_reports_disable
    ("cis", "Disable External Intelligence Integrations", "com.apple.applicationaccess", "allowExternalIntelligenceIntegrations"), // system_settings_external_intelligence_disable
    ("cis", "Disable External Intelligence Integration Sign In", "com.apple.applicationaccess", "allowExternalIntelligenceIntegrationsSignIn"), // system_settings_external_intelligence_sign_in_disable
    ("cis", "Enforce FileVault", "com.apple.MCX", "dontAllowFDEDisable"), // system_settings_filevault_enforce
    ("cis", "Enable macOS Application Firewall", "com.apple.security.firewall", "EnableFirewall"), // system_settings_firewall_enable
    ("cis", "Enable Firewall Stealth Mode", "com.apple.security.firewall", "EnableStealthMode"), // system_settings_firewall_stealth_mode_enable
    ("cis", "Disable the Guest Account", "com.apple.MCX", "DisableGuestAccount"), // system_settings_guest_account_disable
    ("cis", "Disable Improve Search Information to Apple", "com.apple.assistant.support", "Search Queries Data Sharing Status"), // system_settings_improve_search_disable
    ("cis", "Disable Improve Siri and Dictation Information to Apple", "com.apple.assistant.support", "Siri Data Sharing Opt-In Status"), // system_settings_improve_siri_dictation_disable
    ("cis", "Configure Login Window to Show A Custom Message", "com.apple.loginwindow", "LoginwindowText"), // system_settings_loginwindow_loginwindowtext_enable
    ("cis", "Configure Login Window to Prompt for Username and Password", "com.apple.loginwindow", "SHOWFULLNAME"), // system_settings_loginwindow_prompt_username_password_enforce
    ("cis", "Disable Media Sharing", "com.apple.applicationaccess", "allowMediaSharingModification"), // system_settings_media_sharing_disabled
    ("cis", "Disable Password Hints", "com.apple.loginwindow", "RetriesUntilHint"), // system_settings_password_hints_disable
    ("cis", "Disable Personalized Advertising", "com.apple.applicationaccess", "allowApplePersonalizedAdvertising"), // system_settings_personalized_advertising_disable
    ("cis", "Enforce Session Lock After Screen Saver is Started", "com.apple.screensaver", "askForPasswordDelay"), // system_settings_screensaver_ask_for_password_delay_enforce
    ("cis", "Enforce Screen Saver Password", "com.apple.screensaver", "askForPassword"), // system_settings_screensaver_password_enforce
    ("cis", "Enforce Screen Saver Timeout", "com.apple.screensaver", "idleTime"), // system_settings_screensaver_timeout_enforce
    ("cis", "Disable Siri", "com.apple.applicationaccess", "allowAssistant"), // system_settings_siri_disable
    ("cis", "Enforce Software Update App Update Updates Automatically", "com.apple.SoftwareUpdate", "AutomaticallyInstallAppUpdates"), // system_settings_software_update_app_update_enforce
    ("cis", "Enforce Software Update Downloads Updates Automatically", "com.apple.SoftwareUpdate", "AutomaticDownload"), // system_settings_software_update_download_enforce
    ("cis", "Configure Time Machine for Automatic Backups", "com.apple.TimeMachine", "AutoBackup"), // system_settings_time_machine_auto_backup_enable
    ("cis", "Configure macOS to Use an Authorized Time Server", "com.apple.MCX", "timeServer"), // system_settings_time_server_configure
    // NIST 800-53r5 moderate and high (macOS) rules that are not also CIS.
    ("800-53", "Allow Smartcard Authentication", "com.apple.security.smartcard", "allowSmartCard"), // auth_smartcard_allow
    ("800-53", "Set Smartcard Certificate Trust to High", "com.apple.security.smartcard", "checkCertificateTrust"), // auth_smartcard_certificate_trust_enforce_high
    ("800-53", "Enforce Smartcard Authentication", "com.apple.security.smartcard", "enforceSmartCard"), // auth_smartcard_enforce
    ("800-53", "Disable iCloud Address Book", "com.apple.applicationaccess", "allowCloudAddressBook"), // icloud_addressbook_disable
    ("800-53", "Disable the System Setting for Apple ID", "com.apple.systempreferences", "DisabledSystemSettings"), // icloud_appleid_system_settings_disable
    ("800-53", "Disable iCloud Bookmarks", "com.apple.applicationaccess", "allowCloudBookmarks"), // icloud_bookmarks_disable
    ("800-53", "Disable the iCloud Calendar Services", "com.apple.applicationaccess", "allowCloudCalendar"), // icloud_calendar_disable
    ("800-53", "Disable iCloud Document Sync", "com.apple.applicationaccess", "allowCloudDocumentSync"), // icloud_drive_disable
    ("800-53", "Disable the iCloud Freeform Services", "com.apple.applicationaccess", "allowCloudFreeform"), // icloud_freeform_disable
    ("800-53", "Disable iCloud Game Center", "com.apple.applicationaccess", "allowGameCenter"), // icloud_game_center_disable
    ("800-53", "Disable iCloud Keychain Sync", "com.apple.applicationaccess", "allowCloudKeychainSync"), // icloud_keychain_disable
    ("800-53", "Disable iCloud Mail", "com.apple.applicationaccess", "allowCloudMail"), // icloud_mail_disable
    ("800-53", "Disable iCloud Notes", "com.apple.applicationaccess", "allowCloudNotes"), // icloud_notes_disable
    ("800-53", "Disable iCloud Photo Library", "com.apple.applicationaccess", "allowCloudPhotoLibrary"), // icloud_photos_disable
    ("800-53", "Disable iCloud Private Relay", "com.apple.applicationaccess", "allowCloudPrivateRelay"), // icloud_private_relay_disable
    ("800-53", "Disable iCloud Reminders", "com.apple.applicationaccess", "allowCloudReminders"), // icloud_reminders_disable
    ("800-53", "Disable AppleID and Internet Account Modifications", "com.apple.applicationaccess", "allowAccountModification"), // os_account_modification_disable
    ("800-53", "Disable Apple ID Setup during Setup Assistant", "com.apple.SetupAssistant.managed", "SkipSetupItems"), // os_appleid_prompt_disable
    ("800-53", "Bluetooth Status Modification Disabled", "com.apple.applicationaccess", "allowBluetoothModification"), // os_bluetooth_modification_disable
    ("800-53", "Disable Call Recording", "com.apple.applicationaccess", "allowCallRecording"), // os_call_recording_disable
    ("800-53", "Disable Definition Lookup on the Device", "com.apple.applicationaccess", "allowDefinitionLookup"), // os_definition_lookup_disable
    ("800-53", "Disable Dictation", "com.apple.applicationaccess", "allowDictation"), // os_dictation_disable
    ("800-53", "Ensure Allow Erase All Content and Settings is set to Disabled", "com.apple.applicationaccess", "allowEraseContentAndSettings"), // os_erase_contents_and_settings_disable
    ("800-53", "Disable FileVault Automatic Login", "com.apple.loginwindow", "DisableFDEAutoLogin"), // os_filevault_autologin_disable
    ("800-53", "Disable Genmoji AI Creation", "com.apple.applicationaccess", "allowGenmoji"), // os_genmoji_disable
    ("800-53", "Disable Handoff", "com.apple.applicationaccess", "allowActivityContinuation"), // os_handoff_disable
    ("800-53", "Disable Apple Intelligence Image Playground", "com.apple.applicationaccess", "allowImagePlayground"), // os_image_playground_disable
    ("800-53", "Ensure Allow Installing Configuration Profiles is Set to Disabled", "com.apple.applicationaccess", "allowUIConfigurationProfileInstallation"), // os_install_configuration_profile_disable
    ("800-53", "Disable iPhone Mirroring", "com.apple.applicationaccess", "allowiPhoneMirroring"), // os_iphone_mirroring_disable
    ("800-53", "Disable Password Autofill", "com.apple.applicationaccess", "allowPasswordAutoFill"), // os_password_autofill_disable
    ("800-53", "Disable Proximity Based Password Sharing Requests", "com.apple.applicationaccess", "allowPasswordProximityRequests"), // os_password_proximity_disable
    ("800-53", "Disable Password Sharing", "com.apple.applicationaccess", "allowPasswordSharing"), // os_password_sharing_disable
    ("800-53", "Enforce Screen Saver at Login Window", "com.apple.screensaver", "moduleName"), // os_screensaver_loginwindow_enforce
    ("800-53", "Ensure Allow Screenshots and Screen Recording is Set to Disabled", "com.apple.applicationaccess", "allowScreenShot"), // os_screenshots_disable
    ("800-53", "Enforce FileVault in Setup Assistant", "com.apple.MCX.FileVault2", "Enable"), // os_setup_assistant_filevault_enforce
    ("800-53", "Set Account Lockout Time to 15 Minutes", "com.apple.mobiledevice.passwordpolicy", "minutesUntilFailedLoginReset"), // pwpolicy_account_lockout_timeout_enforce
    ("800-53", "Require Passwords Contain a Minimum of One Numeric Character", "com.apple.mobiledevice.passwordpolicy", "requireAlphanumeric"), // pwpolicy_alpha_numeric_enforce
    ("800-53", "Require Passwords to Match the Defined Custom Regular Expression", "com.apple.mobiledevice.passwordpolicy", "customRegex"), // pwpolicy_custom_regex_enforce
    ("800-53", "Prohibit Repeating, Ascending, and Descending Character Sequences", "com.apple.mobiledevice.passwordpolicy", "allowSimple"), // pwpolicy_simple_sequence_disable
    ("800-53", "Require Passwords Contain a Minimum of One Special Character", "com.apple.mobiledevice.passwordpolicy", "minComplexChars"), // pwpolicy_special_character_enforce
    ("800-53", "Prevent Apple Watch from Terminating a Session Lock", "com.apple.applicationaccess", "allowAutoUnlock"), // system_settings_apple_watch_unlock_disable
    ("800-53", "Enforce Auto Logout After 86400 Seconds of Inactivity", ".GlobalPreferences", "com.apple.autologout.AutoLogOutDelay"), // system_settings_automatic_logout_enforce
    ("800-53", "Disable TouchID/OpticID for Unlocking the Device", "com.apple.applicationaccess", "allowFingerprintForUnlock"), // system_settings_biometric_disable
    ("800-53", "Disable Find My Service", "com.apple.applicationaccess", "allowFindMyDevice"), // system_settings_find_my_disable
    ("800-53", "Apply Gatekeeper Settings to Block Applications from Unidentified Developers", "com.apple.systempolicy.control", "AllowIdentifiedDevelopers"), // system_settings_gatekeeper_identified_developers_allowed
    ("800-53", "Configure Gatekeeper to Disallow End User Override", "com.apple.systempolicy.managed", "DisableOverride"), // system_settings_gatekeeper_override_disallow
    ("800-53", "Configure User Session Lock When a Smart Token is Removed", "com.apple.security.smartcard", "tokenRemovalAction"), // system_settings_token_removal_enforce
    ("800-53", "USB Devices Must be Authorized Before Allowing", "com.apple.applicationaccess", "allowUSBRestrictedMode"), // system_settings_usb_restricted_mode
    // SAP Privileges.
    ("privileges", "revoke admin rights when the user logs in", "corp.sap.privileges", "RevokePrivilegesAtLogin"),
    ("privileges", "take admin rights away when the screen locks", "corp.sap.privileges", "RevokePrivilegesOnScreenLock"),
    ("privileges", "revoke admin rights if someone changes the system clock", "corp.sap.privileges", "RevokePrivilegesAfterSystemTimeChange"),
    ("privileges", "admin rights expire after 20 minutes", "corp.sap.privileges", "ExpirationInterval"),
    ("privileges", "let users choose a duration up to a maximum of 60 minutes", "corp.sap.privileges", "ExpirationIntervalMax"),
    ("privileges", "let users renew expiring admin rights", "corp.sap.privileges", "AllowPrivilegeRenewal"),
    ("privileges", "users must give a reason for requesting administrator privileges", "corp.sap.privileges", "ReasonRequired"),
    ("privileges", "the reason must be at least 20 characters", "corp.sap.privileges", "ReasonMinLength"),
    ("privileges", "offer a preset list of reasons to choose from", "corp.sap.privileges", "ReasonPresetList"),
    ("privileges", "require Touch ID to become admin", "corp.sap.privileges", "RequireBiometricAuthentication"),
    ("privileges", "require the account password to get administrator privileges", "corp.sap.privileges", "RequireAuthentication"),
    ("privileges", "allow smart cards for Privileges authentication", "corp.sap.privileges", "EnableSmartCardSupport"),
    ("privileges", "only these users may use Privileges", "corp.sap.privileges", "LimitToUser"),
    ("privileges", "restrict Privileges to members of a group", "corp.sap.privileges", "LimitToGroup"),
    ("privileges", "run a script whenever privileges change", "corp.sap.privileges", "PostChangeExecutablePath"),
    ("privileges", "send privilege changes to our syslog server", "corp.sap.privileges", "RemoteLogging.ServerAddress"),
    ("privileges", "hide the settings button in the Privileges app", "corp.sap.privileges", "HideSettingsButton"),
    ("privileges", "show the remaining admin time in the menu bar", "corp.sap.privileges", "ShowRemainingTimeInMenuBar"),
    ("privileges", "show a usage policy the user must accept", "corp.sap.privileges", "UsagePolicy"),
    ("privileges", "turn on the Privileges system extension", "corp.sap.privileges", "EnableSystemExtension"),
    // Claude Code managed settings.
    ("claude-code", "stop users from bypassing permission prompts", "com.anthropic.claudecode", "permissions.disableBypassPermissionsMode"),
    ("claude-code", "only allow MCP servers from managed settings", "com.anthropic.claudecode", "allowManagedMcpServersOnly"),
    ("claude-code", "enterprise allowlist of MCP servers", "com.anthropic.claudecode", "allowedMcpServers"),
    ("claude-code", "block specific MCP servers", "com.anthropic.claudecode", "deniedMcpServers"),
    ("claude-code", "only managed hooks may run", "com.anthropic.claudecode", "allowManagedHooksOnly"),
    ("claude-code", "disable all hooks", "com.anthropic.claudecode", "disableAllHooks"),
    ("claude-code", "restrict which models users can select", "com.anthropic.claudecode", "availableModels"),
    ("claude-code", "force login with Claude.ai accounts only", "com.anthropic.claudecode", "forceLoginMethod"),
    ("claude-code", "lock login to our organization", "com.anthropic.claudecode", "forceLoginOrgUUID"),
    ("claude-code", "turn on sandboxed bash", "com.anthropic.claudecode", "sandbox.enabled"),
    ("claude-code", "do not let commands run outside the sandbox", "com.anthropic.claudecode", "sandbox.allowUnsandboxedCommands"),
    ("claude-code", "deny rules for tool permissions", "com.anthropic.claudecode", "permissions.deny"),
    ("claude-code", "require a minimum Claude Code version to start", "com.anthropic.claudecode", "requiredMinimumVersion"),
    ("claude-code", "disable remote control", "com.anthropic.claudecode", "disableRemoteControl"),
    ("claude-code", "users cannot define their own permission rules", "com.anthropic.claudecode", "allowManagedPermissionRulesOnly"),
    ("claude-code", "block plugin marketplaces", "com.anthropic.claudecode", "blockedMarketplaces"),
    ("claude-code", "organization instructions injected as managed memory", "com.anthropic.claudecode", "claudeMd"),
    ("claude-code", "reject the plugin-dir and mcp-config command line flags", "com.anthropic.claudecode", "disableSideloadFlags"),
    ("claude-code", "turn off background agents", "com.anthropic.claudecode", "disableAgentView"),
    ("claude-code", "disable claude.ai connectors", "com.anthropic.claudecode", "disableClaudeAiConnectors"),
];

/// Requests no profile or declaration can meet: (request, mSCP rule id).
///
/// CIS items that mSCP enforces with a script. The search still returns keys
/// for these words, because it ranks whatever shares them, so a caller that
/// turns requests into documents needs this half as its test for declining.
/// What is pinned here is the ground truth: contour's mSCP data must go on
/// saying a profile cannot do it, or the case has moved to [`CASES`].
#[rustfmt::skip]
pub const NOT_BY_PROFILE: &[(&str, &str)] = &[
    ("disable SSH remote login", "system_settings_ssh_disable"),
    ("make sure System Integrity Protection is on", "os_sip_enable"),
    ("set the sudo timeout to zero", "os_sudo_timeout_configure"),
    ("log sudo events", "os_sudo_log_enforce"),
    ("disable the root account", "os_root_disable"),
    ("disable screen sharing", "system_settings_screen_sharing_disable"),
    ("turn off printer sharing", "system_settings_printer_sharing_disable"),
    ("disable remote management", "system_settings_remote_management_disable"),
    ("disable remote Apple events", "system_settings_rae_disable"),
    ("disable SMB file sharing", "system_settings_smbd_disable"),
    ("disable Bluetooth sharing", "system_settings_bluetooth_sharing_disable"),
    ("disable the built-in web server", "os_httpd_disable"),
    ("disable NFS", "os_nfsd_disable"),
    ("enable security auditing", "audit_auditd_enabled"),
    ("keep audit logs for seven days", "audit_retention_configure"),
    ("remove password hints from user accounts", "os_password_hint_remove"),
    ("secure users' home folders", "os_home_folders_secure"),
    ("turn on location services", "system_settings_location_services_enable"),
    ("disable wake for network access", "system_settings_wake_network_access_disable"),
    ("enable authenticated root", "os_authenticated_root_enable"),
];
