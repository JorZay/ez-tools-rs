//! The base block (`regf`) at the start of a hive or transaction log, and the hive type from its file name.

use ez_common::net::{self, NetResult};

pub const REGF_SIGNATURE: i32 = 0x66676572;

/// HiveTypeEnum, from the base block's file name
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HiveType {
    Other = 0,
    NtUser = 1,
    Sam = 2,
    Security = 3,
    Software = 4,
    System = 5,
    UsrClass = 6,
    Components = 7,
    Drivers = 8,
    Amcache = 9,
    Syscache = 10,
    Bcd = 11,
    BcdTemplate = 12,
    Elam = 13,
    Userdiff = 14,
    Bbi = 15,
    Vsmidk = 16,
    Default = 17,
    User = 18,
    UserClasses = 19,
    Settings = 20,
    Registry = 21,
}

impl HiveType {
    /// The type for the last segment of a base block's file name
    pub fn from_file_name(file_name: &str) -> HiveType {
        let base = file_name.rsplit('\\').next().unwrap_or("").to_lowercase();
        match base.as_str() {
            "ntuser.dat" => HiveType::NtUser,
            "sam" => HiveType::Sam,
            "security" => HiveType::Security,
            "software" => HiveType::Software,
            "system" => HiveType::System,
            "drivers" => HiveType::Drivers,
            "usrclass.dat" => HiveType::UsrClass,
            "components" => HiveType::Components,
            "bcd" => HiveType::Bcd,
            "amcache.hve" | "amcache.hve.tmp" => HiveType::Amcache,
            "syscache.hve" => HiveType::Syscache,
            "elam" => HiveType::Elam,
            "default" => HiveType::Default,
            "vsmidk" => HiveType::Vsmidk,
            "bcd-template" => HiveType::BcdTemplate,
            "bbi" => HiveType::Bbi,
            "userdiff" => HiveType::Userdiff,
            "user.dat" => HiveType::User,
            "userclasses.dat" => HiveType::UserClasses,
            "settings.dat" => HiveType::Settings,
            "registry.dat" => HiveType::Registry,
            _ => HiveType::Other,
        }
    }

    /// The enum's name, as ToString() writes it
    pub fn name(self) -> &'static str {
        match self {
            HiveType::Other => "Other",
            HiveType::NtUser => "NtUser",
            HiveType::Sam => "Sam",
            HiveType::Security => "Security",
            HiveType::Software => "Software",
            HiveType::System => "System",
            HiveType::UsrClass => "UsrClass",
            HiveType::Components => "Components",
            HiveType::Drivers => "Drivers",
            HiveType::Amcache => "Amcache",
            HiveType::Syscache => "Syscache",
            HiveType::Bcd => "Bcd",
            HiveType::BcdTemplate => "BcdTemplate",
            HiveType::Elam => "Elam",
            HiveType::Userdiff => "Userdiff",
            HiveType::Bbi => "Bbi",
            HiveType::Vsmidk => "Vsmidk",
            HiveType::Default => "Default",
            HiveType::User => "User",
            HiveType::UserClasses => "UserClasses",
            HiveType::Settings => "settings",
            HiveType::Registry => "Registry",
        }
    }
}

/// RegistryHeader: the fields of the base block
#[derive(Debug, Clone)]
pub struct Header {
    pub primary_sequence_number: u32,
    pub secondary_sequence_number: u32,
    pub last_write_timestamp: i64,
    pub major_version: i32,
    pub minor_version: i32,
    pub file_type: u32,
    pub format: u32,
    pub root_cell_offset: u32,
    pub length: u32,
    pub cluster: u32,
    pub file_name: String,
    pub checksum: i32,
    pub calculated_checksum: i32,
    pub boot_type: u32,
    pub boot_recover: u32,
}

impl Header {
    /// Reads the (up to 4096) bytes of a base block, throwing (Err) where RegistryHeader's constructor does
    pub fn parse(b: &[u8]) -> NetResult<Header> {
        let signature = net::ascii_string(b, 0, 4)?;
        if signature != "regf" {
            return Err("This is not a Registry hive. Header != 'regf'".into());
        }
        let primary_sequence_number = net::u32_at(b, 4)?;
        let secondary_sequence_number = net::u32_at(b, 8)?;
        let last_write_timestamp = net::i64_at(b, 0xc)?;
        let major_version = net::i32_at(b, 0x14)?;
        let minor_version = net::i32_at(b, 0x18)?;
        let file_type = net::u32_at(b, 0x1c)?;
        let format = net::u32_at(b, 0x20)?;
        let root_cell_offset = net::u32_at(b, 0x24)?;
        let length = net::u32_at(b, 0x28)?;
        let cluster = net::u32_at(b, 0x2c)?;
        let file_name = net::unicode_string(b, 0x30, 64)?.replace('\0', "").replace("\\??\\", "");
        net::copy(b, 0x70, 16)?;
        net::copy(b, 0x80, 16)?;
        net::i32_at(b, 0x90)?;
        net::copy(b, 0x94, 16)?;
        net::i64_at(b, 0xa8)?;
        let checksum = net::i32_at(b, 0x1fc)?;
        let mut xsum = 0i32;
        let mut i = 0;
        while i <= 0x1fb {
            xsum ^= net::i32_at(b, i)?;
            i += 4;
        }
        let boot_type = net::u32_at(b, 0xff8)?;
        let boot_recover = net::u32_at(b, 0xffc)?;
        Ok(Header {
            primary_sequence_number,
            secondary_sequence_number,
            last_write_timestamp,
            major_version,
            minor_version,
            file_type,
            format,
            root_cell_offset,
            length,
            cluster,
            file_name,
            checksum,
            calculated_checksum: xsum,
            boot_type,
            boot_recover,
        })
    }

    pub fn checksum_ok(&self) -> bool {
        self.checksum == self.calculated_checksum
    }
}
