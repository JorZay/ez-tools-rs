//! Well-known SIDs (Helpers.SidTypeEnum and GetSidTypeFromSidString in the MFT library), generated from its source.

/// The description of a SID's well-known type, or None for an unknown or user SID
pub fn sid_description(sid: &str) -> Option<&'static str> {
    let name = sid_type(sid);
    if name == "UnknownOrUserSid" {
        return None;
    }
    Some(DESCRIPTIONS.iter().find(|(n, _)| *n == name).map(|(_, d)| *d).unwrap_or(name))
}

/// The SidTypeEnum member name for a SID
pub fn sid_type(sid: &str) -> &'static str {
    let t = match sid {
        "S-1-0-0" => "Null",
        "S-1-1-0" => "Everyone",
        "S-1-2-0" => "Local",
        "S-1-2-1" => "ConsoleLogon",
        "S-1-3-0" => "CreatorOwner",
        "S-1-3-1" => "CreatorGroup",
        "S-1-3-2" => "OwnerServer",
        "S-1-3-3" => "GroupServer",
        "S-1-3-4" => "OwnerServer",
        "S-1-5-1" => "Dialup",
        "S-1-5-2" => "Network",
        "S-1-5-3" => "Batch",
        "S-1-5-4" => "Interactive",
        "S-1-5-6" => "Service",
        "S-1-5-7" => "Anonymous",
        "S-1-5-8" => "Proxy",
        "S-1-5-9" => "EnterpriseDomainControllers",
        "S-1-5-10" => "PrincipalSelf",
        "S-1-5-11" => "AuthenticatedUsers",
        "S-1-5-12" => "RestrictedCode",
        "S-1-5-13" => "TerminalServerUser",
        "S-1-5-14" => "RemoteInteractiveLogon",
        "S-1-5-15" => "ThisOrganization",
        "S-1-5-17" => "Iusr",
        "S-1-5-18" => "LocalSystem",
        "S-1-5-19" => "LocalService",
        "S-1-5-20" => "NetworkService",
        "S-1-5-21-0-0-0-496" => "CompoundedAuthentication",
        "S-1-5-21-0-0-0-497" => "ClaimsValid",
        "S-1-5-32-544" => "BuiltinAdministrators",
        "S-1-5-32-545" => "BuiltinUsers",
        "S-1-5-32-546" => "BuiltinGuests",
        "S-1-5-32-547" => "PowerUsers",
        "S-1-5-32-548" => "AccountOperators",
        "S-1-5-32-549" => "ServerOperators",
        "S-1-5-32-550" => "PrinterOperators",
        "S-1-5-32-551" => "BackupOperators",
        "S-1-5-32-552" => "Replicator",
        "S-1-5-32-554" => "AliasPrew2Kcompacc",
        "S-1-5-32-555" => "RemoteDesktop",
        "S-1-5-32-556" => "NetworkConfigurationOps",
        "S-1-5-32-557" => "IncomingForestTrustBuilders",
        "S-1-5-32-558" => "PerfmonUsers",
        "S-1-5-32-559" => "PerflogUsers",
        "S-1-5-32-560" => "WindowsAuthorizationAccessGroup",
        "S-1-5-32-561" => "TerminalServerLicenseServers",
        "S-1-5-32-562" => "DistributedComUsers",
        "S-1-5-32-568" => "IisIusrs",
        "S-1-5-32-569" => "CryptographicOperators",
        "S-1-5-32-573" => "EventLogReaders",
        "S-1-5-32-574" => "CertificateServiceDcomAccess",
        "S-1-5-32-575" => "RdsRemoteAccessServers",
        "S-1-5-32-576" => "RdsEndpointServers",
        "S-1-5-32-577" => "RdsManagementServers",
        "S-1-5-32-578" => "HyperVAdmins",
        "S-1-5-32-579" => "AccessControlAssistanceOps",
        "S-1-5-32-580" => "RemoteManagementUsers",
        "S-1-5-33" => "WriteRestrictedCode",
        "S-1-5-64-10" => "NtlmAuthentication",
        "S-1-5-64-14" => "SchannelAuthentication",
        "S-1-5-64-21" => "DigestAuthentication",
        "S-1-5-65-1" => "ThisOrganizationCertificate",
        "S-1-5-80" => "NtService",
        "S-1-5-84-0-0-0-0-0" => "UserModeDrivers",
        "S-1-5-113" => "LocalAccount",
        "S-1-5-114" => "LocalAccountAndMemberOfAdministratorsGroup",
        "S-1-5-1000" => "OtherOrganization",
        "S-1-15-2-1" => "AllAppPackages",
        "S-1-16-0" => "MlUntrusted",
        "S-1-16-4096" => "MlLow",
        "S-1-16-8192" => "MlMedium",
        "S-1-16-8448" => "MlMediumPlus",
        "S-1-16-12288" => "MlHigh",
        "S-1-16-16384" => "MlSystem",
        "S-1-16-20480" => "MlProtectedProcess",
        "S-1-18-1" => "AuthenticationAuthorityAssertedIdentity",
        "S-1-18-2" => "ServiceAssertedIdentity",
        _ => "UnknownOrUserSid",
    };
    if t != "UnknownOrUserSid" {
        return t;
    }
    let mut t = t;
    if sid.starts_with("S-1-5-5-") {
        t = "LogonId";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-498") {
        t = "EnterpriseDomainControllers";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-500") {
        t = "Administrator";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-501") {
        t = "Guest";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-512") {
        t = "DomainAdmins";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-513") {
        t = "DomainUsers";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-514") {
        t = "DomainGuests";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-515") {
        t = "DomainComputers";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-516") {
        t = "DomainDomainControllers";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-517") {
        t = "CertPublishers";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-518") {
        t = "SchemaAdministrators";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-519") {
        t = "EnterpriseAdmins";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-520") {
        t = "GroupPolicyCreatorOwners";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-521") {
        t = "ReadonlyDomainControllers";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-522") {
        t = "CloneableControllers";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-525") {
        t = "ProtectedUsers";
    }
    if sid.starts_with("S-1-5-21-") && sid.ends_with("-553") {
        t = "RasServers";
    }
    t
}

const DESCRIPTIONS: &[(&str, &str)] = &[
    ("UnknownOrUserSid", "SID does not map to a common SID or this is a user SID"),
    ("Null", "S-1-0-0: No Security principal."),
    ("Everyone", "S-1-1-0: A group that includes all users."),
    ("Local", "S-1-2-0: A group that includes all users who have logged on locally."),
    ("ConsoleLogon", "S-1-2-1: A group that includes users who are logged on to the physical console. This SID can be used to implement security policies that grant different rights based on whether a user has been granted physical access to the console."),
    ("CreatorOwner", "S-1-3-0: A placeholder in an inheritable access control entry (ACE). When the ACE is inherited, the system replaces this SID with the SID for the object's creator."),
    ("CreatorGroup", "S-1-3-1: A placeholder in an inheritable ACE. When the ACE is inherited, the system replaces this SID with the SID for the primary group of the object's creator."),
    ("OwnerServer", "S-1-3-2: A placeholder in an inheritable ACE. When the ACE is inherited, the system replaces this SID with the SID for the object's owner server."),
    ("GroupServer", "S-1-3-3: A placeholder in an inheritable ACE. When the ACE is inherited, the system replaces this SID with the SID for the object's group server."),
    ("OwnerRights", "S-1-3-4: A group that represents the current owner of the object. When an ACE that carries this SID is applied to an object, the system ignores the implicit READ_CONTROL and WRITE_DAC permissions for the object owner."),
    ("NtAuthority", "S-1-5: A SID containing only the SECURITY_NT_AUTHORITY identifier authority."),
    ("Dialup", "S-1-5-1: A group that includes all users who have logged on through a dial-up connection."),
    ("Network", "S-1-5-2: A group that includes all users who have logged on through a network connection."),
    ("Batch", "S-1-5-3: A group that includes all users who have logged on through a batch queue facility."),
    ("Interactive", "S-1-5-4: A group that includes all users who have logged on interactively."),
    ("LogonId", "S-1-5-5-x-y: A logon session. The X and Y values for these SIDs are different for each logon session and are recycled when the operating system is restarted."),
    ("Service", "S-1-5-6: A group that includes all security principals that have logged on as a service."),
    ("Anonymous", "S-1-5-7: A group that represents an anonymous logon."),
    ("Proxy", "S-1-5-8: Identifies a SECURITY_NT_AUTHORITY Proxy."),
    ("EnterpriseDomainControllers", "S-1-5-9: A group that includes all domain controllers in a forest that uses an Active Directory directory service."),
    ("PrincipalSelf", "S-1-5-10: A placeholder in an inheritable ACE on an account object or group object in Active Directory. When the ACE is inherited, the system replaces this SID with the SID for the security principal that holds the account."),
    ("AuthenticatedUsers", "S-1-5-11: A group that includes all users whose identities were authenticated when they logged on."),
    ("RestrictedCode", "S-1-5-12: This SID is used to control access by untrusted code. ACL validation against tokens with RC consists of two checks, one against the token's normal list of SIDs and one against a second list (typically containing RC - the RESTRICTED_CODE token - and a subset of the original token SIDs). Access is granted only if a token passes both tests. Any ACL that specifies RC must also specify WD - the EVERYONE token. When RC is paired with WD in an ACL, a superset of EVERYONE, including untrusted code, is described."),
    ("TerminalServerUser", "S-1-5-13: A group that includes all users who have logged on to a Terminal Services server."),
    ("RemoteInteractiveLogon", "S-1-5-14: A group that includes all users who have logged on through a terminal services logon."),
    ("ThisOrganization", "S-1-5-15: A group that includes all users from the same organization."),
    ("OtherOrganization", "S-1-5-1000: A group that includes all users and computers from another organization. "),
    ("Iusr", "S-1-5-17: An account that is used by the default Internet Information Services (IIS) user."),
    ("LocalSystem", "S-1-5-18: An account that is used by the operating system."),
    ("LocalService", "S-1-5-19: A local service account."),
    ("NetworkService", "S-1-5-20: A network service account."),
    ("EnterpriseReadonlyDomainControllers", "S-1-5-21-<root domain>-498: A universal group containing all read-only domain controllers in a forest."),
    ("CompoundedAuthentication", "S-1-5-21-0-0-0-496: Device identity is included in the Kerberos service ticket. If a forest boundary was crossed, then claims transformation occurred."),
    ("ClaimsValid", "S-1-5-21-0-0-0-497: Claims were queried for in the account's domain, and if a forest boundary was crossed, then claims transformation occurred."),
    ("Administrator", "S-1-5-21-<machine>-500: A user account for the system administrator. By default, it is the only user account that is given full control over the system."),
    ("Guest", "S-1-5-21-<machine>-501: A user account for people who do not have individual accounts. This user account does not require a password. By default, the Guest account is disabled."),
    ("DomainAdmins", "S-1-5-21-<domain>-512: A global group whose members are authorized to administer the domain. By default, the DOMAIN_ADMINS group is a member of the Administrators group on all computers that have joined a domain, including the domain controllers. DOMAIN_ADMINS is the default owner of any object that is created by any member of the group."),
    ("DomainUsers", "S-1-5-21-<domain>-513: A global group that includes all user accounts in a domain."),
    ("DomainGuests", "S-1-5-21-<domain>-514: A global group that has only one member, which is the built-in Guest account of the domain."),
    ("DomainComputers", "S-1-5-21-<domain>-515: A global group that includes all clients and servers that have joined the domain."),
    ("DomainDomainControllers", "S-1-5-21-<domain>-516: A global group that includes all domain controllers in the domain."),
    ("CertPublishers", "S-1-5-21-<domain>-517: A global group that includes all computers that are running an enterprise certification authority. Cert Publishers are authorized to publish certificates for User objects in Active Directory."),
    ("SchemaAdministrators", "S-1-5-21-<root-domain>-518: A universal group in a native-mode domain, or a global group in a mixed-mode domain. The group is authorized to make schema changes in Active Directory."),
    ("EnterpriseAdmins", "S-1-5-21-<root-domain>-519: A universal group in a native-mode domain, or a global group in a mixed-mode domain. The group is authorized to make forestwide changes in Active Directory, such as adding child domains."),
    ("GroupPolicyCreatorOwners", "S-1-5-21-<domain>-520: A global group that is authorized to create new Group Policy Objects in Active Directory."),
    ("ReadonlyDomainControllers", "S-1-5-21-<domain>-521: A global group that includes all read-only domain controllers."),
    ("CloneableControllers", "S-1-5-21-<domain>-522: A global group that includes all domain controllers in the domain that may be cloned."),
    ("ProtectedUsers", "S-1-5-21-<domain>-525: A global group that are afforded additional protections against authentication security threats. For more information, see [MS-APDS] and [MS-KILE]."),
    ("RasServers", "S-1-5-21-<domain>-553: A domain local group for Remote Access Services (RAS) servers. Servers in this group have Read Account Restrictions and Read Logon Information access to User objects in the Active Directory domain local group."),
    ("BuiltinAdministrators", "S-1-5-32-544: A built-in group. After the initial installation of the operating system, the only member of the group is the Administrator account. When a computer joins a domain, the Domain Administrators group is added to the Administrators group. When a server becomes a domain controller, the Enterprise Administrators group also is added to the Administrators group."),
    ("BuiltinUsers", "S-1-5-32-545: A built-in group. After the initial installation of the operating system, the only member is the Authenticated Users group. When a computer joins a domain, the Domain Users group is added to the Users group on the computer."),
    ("BuiltinGuests", "S-1-5-32-546: A built-in group. The Guests group allows users to log on with limited privileges to a computer's built-in Guest account."),
    ("PowerUsers", "S-1-5-32-547: A built-in group. Power users can perform the following actions: Create local users and groups, Modify and delete accounts that they have created, Remove users from the Power Users, Users, and Guests groups, Install programs, Create, manage, and delete local printers, Create and delete file shares."),
    ("AccountOperators", "S-1-5-32-548: A built-in group that exists only on domain controllers. Account Operators have permission to create, modify, and delete accounts for users, groups, and computers in all containers and organizational units of Active Directory except the Built-in container and the Domain Controllers OU. Account Operators do not have permission to modify the Administrators and Domain Administrators groups, nor do they have permission to modify the accounts for members of those groups."),
    ("ServerOperators", "S-1-5-32-549: A built-in group that exists only on domain controllers. Server Operators can perform the following actions: Log on to a server interactively, Create and delete network shares, Start and stop services, Back up and restore files, Format the hard disk of a computer, Shut down the computer"),
    ("PrinterOperators", "S-1-5-32-550: A built-in group that exists only on domain controllers. Print Operators can manage printers and document queues."),
    ("BackupOperators", "S-1-5-32-551: A built-in group. Backup Operators can back up and restore all files on a computer, regardless of the permissions that protect those files."),
    ("Replicator", "S-1-5-32-552: A built-in group that is used by the File Replication Service (FRS) on domain controllers."),
    ("AliasPrew2Kcompacc", "S-1-5-32-554: A backward compatibility group that allows read access on all users and groups in the domain."),
    ("RemoteDesktop", "S-1-5-32-555: An alias. Members of this group are granted the right to log on remotely."),
    ("NetworkConfigurationOps", "S-1-5-32-556: An alias. Members of this group can have some administrative privileges to manage configuration of networking features."),
    ("IncomingForestTrustBuilders", "S-1-5-32-557: An alias. Members of this group can create incoming, one-way trusts to this forest."),
    ("PerfmonUsers", "S-1-5-32-558: An alias. Members of this group have remote access to monitor this computer."),
    ("PerflogUsers", "S-1-5-32-559: An alias. Members of this group have remote access to schedule the logging of performance counters on this computer."),
    ("WindowsAuthorizationAccessGroup", "S-1-5-32-560: An alias. Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects."),
    ("TerminalServerLicenseServers", "S-1-5-32-561: An alias. A group for Terminal Server License Servers."),
    ("DistributedComUsers", "S-1-5-32-562: An alias. A group for COM to provide computer-wide access controls that govern access to all call, activation, or launch requests on the computer."),
    ("IisIusrs", "S-1-5-32-568: A built-in group account for IIS users."),
    ("CryptographicOperators", "S-1-5-32-569: A built-in group account for cryptographic operators."),
    ("EventLogReaders", "S-1-5-32-573: A built-in local group. Members of this group can read event logs from the local machine."),
    ("CertificateServiceDcomAccess", "S-1-5-32-574: A built-in local group. Members of this group are allowed to connect to Certification Authorities in the enterprise."),
    ("RdsRemoteAccessServers", "S-1-5-32-575: A group that allows members use of Remote Application Services resources."),
    ("RdsManagementServers", "S-1-5-32-577: A group that allows members to access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service)."),
    ("HyperVAdmins", "S-1-5-32-578: A group that gives members access to all administrative features of Hyper-V."),
    ("AccessControlAssistanceOps", "S-1-5-32-579: A local group that allows members to remotely query authorization attributes and permissions for resources on the local computer."),
    ("RemoteManagementUsers", "S-1-5-32-580: Members of this group can access Windows Management Instrumentation (WMI) resources over management protocols (such as WS-Management [DMTF-DSP0226]). This applies only to WMI namespaces that grant access to the user."),
    ("WriteRestrictedCode", "S-1-5-33: A SID that allows objects to have an ACL that lets any service process with a write-restricted token to write to the object."),
    ("NtlmAuthentication", "S-1-5-64-10: A SID that is used when the NTLM authentication package authenticated the client."),
    ("SchannelAuthentication", "S-1-5-64-14: A SID that is used when the SChannel authentication package authenticated the client."),
    ("DigestAuthentication", "S-1-5-64-21: A SID that is used when the Digest authentication package authenticated the client."),
    ("ThisOrganizationCertificate", "S-1-5-65-1: A SID that indicates that the client's Kerberos service ticket's PAC contained a NTLM_SUPPLEMENTAL_CREDENTIAL structure (as specified in [MS-PAC] section 2.6.4)."),
    ("NtService", "S-1-5-80: An NT Service account prefix."),
    ("UserModeDrivers", "S-1-5-84-0-0-0-0-0: Identifies a user-mode driver process."),
    ("LocalAccount", "S-1-5-113: A group that includes all users who are local accounts."),
    ("LocalAccountAndMemberOfAdministratorsGroup", "S-1-5-114: A group that includes all users who are local accounts and members of the administrators group."),
    ("AllAppPackages", "S-1-15-2-1: All applications running in an app package context."),
    ("MlUntrusted", "S-1-16-0: An untrusted integrity level."),
    ("MlLow", "S-1-16-4096: A low integrity level."),
    ("MlMedium", "S-1-16-8192: A medium integrity level."),
    ("MlMediumPlus", "S-1-16-8448: A medium-plus integrity level."),
    ("MlHigh", "S-1-16-12288: A high integrity level."),
    ("MlSystem", "S-1-16-16384: A system integrity level."),
    ("MlProtectedProcess", "S-1-16-20480: A protected-process integrity level."),
    ("AuthenticationAuthorityAssertedIdentity", "S-1-18-1: A SID that means the client's identity is asserted by an authentication authority based on proof of possession of client credentials."),
    ("ServiceAssertedIdentity", "S-1-18-2: A SID that means the client's identity is asserted by a service."),
];
