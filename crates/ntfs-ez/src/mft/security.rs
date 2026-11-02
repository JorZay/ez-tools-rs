//! Security descriptors (self-relative SECURITY_DESCRIPTOR), as in $SECURITY_DESCRIPTOR attributes and $Secure:$SDS.

use ez_common::net::{NetResult, u32_at};

pub const CONTROL_NAMES: &[(&str, i64)] = &[
    ("SeDaclAutoInherited", 0x0400),
    ("SeDaclAutoInheritReq", 0x0100),
    ("SeDaclDefaulted", 0x0008),
    ("SeDaclPresent", 0x0004),
    ("SeDaclProtected", 0x1000),
    ("SeGroupDefaulted", 0x0002),
    ("SeOwnerDefaulted", 0x0001),
    ("SeServerSecurity", 0x0080),
    ("SeDaclUntrusted", 0x0040),
    ("SeRmControlValid", 0x4000),
    ("SeSaclAutoInherited", 0x0800),
    ("SeSaclAutoInheritReq", 0x0200),
    ("SeSaclDefaulted", 0x0020),
    ("SeSaclPresent", 0x0010),
    ("SeSaclProtected", 0x2000),
    ("SeSelfRelative", 0x8000),
];

const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SACL_PRESENT: u16 = 0x0010;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclType {
    Security,
    Discretionary,
}

#[derive(Debug, Clone)]
pub struct SkSecurityDescriptor {
    pub raw: Vec<u8>,
    size_sacl: u32,
    size_dacl: u32,
    size_owner: u32,
    size_group: u32,
}

impl SkSecurityDescriptor {
    /// The reads the constructor makes, which throw on a short descriptor
    pub fn check(raw: &[u8]) -> NetResult<()> {
        u32_at(raw, 0x0c)?;
        u32_at(raw, 0x10)?;
        u32_at(raw, 0x04)?;
        u32_at(raw, 0x08)?;
        Ok(())
    }

    pub fn new(raw: Vec<u8>) -> NetResult<SkSecurityDescriptor> {
        Self::check(&raw)?;
        let mut d = SkSecurityDescriptor { raw, size_sacl: 0, size_dacl: 0, size_owner: 0, size_group: 0 };
        d.size_sacl = d.acl_size(d.sacl_offset());
        d.size_dacl = d.acl_size(d.dacl_offset());
        d.size_owner = d.sid_size(d.owner_offset());
        d.size_group = d.sid_size(d.group_offset());
        Ok(d)
    }

    fn u32(&self, o: usize) -> u32 {
        u32::from_le_bytes(self.raw[o..o + 4].try_into().unwrap())
    }

    fn acl_size(&self, offset: u32) -> u32 {
        let len = self.raw.len() as i64;
        if offset == 0 || len < 0x14 || offset as i64 > len - 4 {
            return 0;
        }
        let o = offset as usize;
        (u16::from_le_bytes([self.raw[o + 2], self.raw[o + 3]]) as u32).min((len - offset as i64) as u32)
    }

    fn sid_size(&self, offset: u32) -> u32 {
        let len = self.raw.len() as i64;
        if offset == 0 || len < 0x14 || offset as i64 > len - 8 {
            return 0;
        }
        (8 + 4 * self.raw[offset as usize + 1] as u32).min((len - offset as i64) as u32)
    }

    pub fn revision(&self) -> u8 {
        self.raw[0]
    }
    pub fn control(&self) -> u16 {
        u16::from_le_bytes([self.raw[2], self.raw[3]])
    }
    pub fn owner_offset(&self) -> u32 {
        self.u32(0x04)
    }
    pub fn group_offset(&self) -> u32 {
        self.u32(0x08)
    }
    pub fn sacl_offset(&self) -> u32 {
        self.u32(0x0c)
    }
    pub fn dacl_offset(&self) -> u32 {
        self.u32(0x10)
    }

    pub fn owner_sid(&self) -> String {
        sid_string(&self.slice(self.owner_offset(), self.size_owner))
    }

    pub fn group_sid(&self) -> String {
        sid_string(&self.slice(self.group_offset(), self.size_group))
    }

    fn slice(&self, offset: u32, size: u32) -> Vec<u8> {
        if size == 0 {
            return Vec::new();
        }
        self.raw[offset as usize..(offset + size) as usize].to_vec()
    }

    pub fn dacl(&self) -> Option<Acl> {
        if self.control() & SE_DACL_PRESENT == SE_DACL_PRESENT && self.size_dacl > 0 {
            return Some(Acl { raw: self.slice(self.dacl_offset(), self.size_dacl), acl_type: AclType::Discretionary });
        }
        None
    }

    pub fn sacl(&self) -> Option<Acl> {
        if self.control() & SE_SACL_PRESENT != SE_SACL_PRESENT || self.size_sacl == 0 {
            return None;
        }
        Some(Acl { raw: self.slice(self.sacl_offset(), self.size_sacl), acl_type: AclType::Security })
    }
}

#[derive(Debug, Clone)]
pub struct Acl {
    pub raw: Vec<u8>,
    pub acl_type: AclType,
}

impl Acl {
    pub fn revision(&self) -> u8 {
        self.raw[0]
    }
    pub fn size(&self) -> u16 {
        u16::from_le_bytes([self.raw[2], self.raw[3]])
    }
    pub fn ace_count(&self) -> u16 {
        if self.raw.is_empty() { 0 } else { u16::from_le_bytes([self.raw[4], self.raw[5]]) }
    }

    pub fn aces(&self) -> Vec<Ace> {
        let mut index = 8usize;
        let mut aces = Vec::new();
        for _ in 0..self.ace_count() {
            if index + 4 > self.raw.len() {
                break;
            }
            let size = u16::from_le_bytes([self.raw[index + 2], self.raw[index + 3]]) as usize;
            if size < 8 || size > self.raw.len() - index {
                break;
            }
            aces.push(Ace { raw: self.raw[index..index + size].to_vec() });
            index += size;
        }
        aces
    }
}

#[derive(Debug, Clone)]
pub struct Ace {
    pub raw: Vec<u8>,
}

pub const ACE_FLAG_NAMES: &[(&str, i64)] = &[
    ("ContainerInheritAce", 0x02),
    ("FailedAccessAceFlag", 0x80),
    ("InheritedAce", 0x10),
    ("InheritOnlyAce", 0x08),
    ("None", 0x0),
    ("NoPropagateInheritAce", 0x04),
    ("ObjectInheritAce", 0x01),
    ("SuccessfulAccessAceFlag", 0x40),
];

pub const ACE_TYPE_NAMES: [&str; 21] = [
    "AccessAllowed",
    "AccessDenied",
    "SystemAudit",
    "SystemAlarm",
    "AccessAllowedCompound",
    "AccessAllowedObject",
    "AccessDeniedObject",
    "SystemAuditObject",
    "SystemAlarmObject",
    "AccessAllowedCallback",
    "AccessDeniedCallback",
    "AccessAllowedCallbackObject",
    "AccessDeniedCallbackObject",
    "SystemAuditCallback",
    "SystemAlarmCallback",
    "SystemAuditCallbackObject",
    "SystemAlarmCallbackObject",
    "SystemMandatoryLabel",
    "SystemResourceAttribute",
    "SystemScopedPolicyId",
    "SystemProcessTrustLabel",
];

pub const MASK_NAMES: &[(&str, i64)] = &[
    ("FilEExecute", 0x00000020),
    ("CreateSubDir", 0x00000004),
    ("ReadAttrs", 0x00000080),
    ("WriteAttrs", 0x00000100),
    ("WriteOwnProp", 0x00000200),
    ("DeleteOwnProp", 0x00000400),
    ("ViewOwnProp", 0x00000800),
    ("Delete", 0x00010000),
    ("ReadEa", 0x00000008),
    ("FullControl", 0x000F003F),
    ("WriteEa", 0x00000010),
    ("FileReadDirList", 0x00000001),
    ("ReadControl", 0x00020000),
    ("FileWriteFileAdd", 0x00000002),
    ("WriteDac", 0x00040000),
    ("WriteOwner", 0x00080000),
    ("Synchronize", 0x000100000),
    ("TrusteeOwn", 0x00004000),
    ("UserAsContact", 0x00008000),
];

impl Ace {
    pub fn flags(&self) -> u8 {
        self.raw[1]
    }
    pub fn size(&self) -> u16 {
        u16::from_le_bytes([self.raw[2], self.raw[3]])
    }
    /// The type's name (Unknown for types the library does not know)
    pub fn type_name(&self) -> &'static str {
        ACE_TYPE_NAMES.get(self.raw[0] as usize).copied().unwrap_or("Unknown")
    }
    pub fn mask(&self) -> u32 {
        u32::from_le_bytes(self.raw[4..8].try_into().unwrap())
    }

    pub fn sid(&self) -> String {
        let mut sid_offset = 8usize;
        if matches!(self.raw[0], 0x5 | 0x6 | 0x7 | 0x8 | 0xB | 0xC | 0xF | 0x10) {
            if self.raw.len() < 0xC {
                return String::new();
            }
            let object_flags = u32::from_le_bytes(self.raw[8..12].try_into().unwrap());
            sid_offset = 0xC + if object_flags & 1 == 1 { 16 } else { 0 } + if object_flags & 2 == 2 { 16 } else { 0 };
        }
        let length = (self.size() as i64).min(self.raw.len() as i64) - sid_offset as i64;
        if length < 8 {
            return String::new();
        }
        sid_string(&self.raw[sid_offset..sid_offset + length as usize])
    }
}

/// Helpers.ConvertHexStringToSidString: revision, subauthority count, 48 bit big-endian authority, subauthorities
pub fn sid_string(hex: &[u8]) -> String {
    use std::fmt::Write;
    if hex.len() < 8 {
        return String::new();
    }
    let auth = hex[2..8].iter().fold(0u64, |a, &b| (a << 8) | b as u64);
    let mut s = format!("S-{}-{auth}", hex[0]);
    let count = (hex[1] as usize).min((hex.len() - 8) / 4);
    for i in 0..count {
        let o = 8 + i * 4;
        write!(s, "-{}", u32::from_le_bytes(hex[o..o + 4].try_into().unwrap())).unwrap();
    }
    s
}
