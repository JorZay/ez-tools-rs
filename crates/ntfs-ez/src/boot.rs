//! $Boot: the NTFS boot sector.

use ez_common::net;

#[derive(Debug, Clone)]
pub struct Boot {
    pub boot_entry_point: String,
    pub file_system_signature: String,
    pub bytes_per_sector: i32,
    pub sector_signature: i32,
    pub sectors_per_cluster: i32,
    pub reserved_sectors: i32,
    pub number_of_fats: i32,
    pub root_directory_entries: i32,
    pub total_number_of_sectors16: i32,
    pub media_descriptor: u8,
    pub sectors_per_fat: i32,
    pub sectors_per_track: i32,
    pub number_of_heads: i32,
    pub number_of_hidden_sectors: i32,
    pub total_number_of_sectors: i32,
    pub disk_unit_number: u8,
    pub unknown_flags: u8,
    pub bpb_version_signature: u8,
    pub unknown_reserved: u8,
    pub total_sectors: i64,
    pub mft_cluster_block_number: i64,
    pub mirror_mft_cluster_block_number: i64,
    pub mft_entry_size: i32,
    pub index_entry_size: i32,
    pub volume_serial_number_raw: i64,
    pub checksum: i32,
    /// "Expected signature (0x55 0xAA) not found" when the sector signature is wrong
    pub warnings: Vec<String>,
}

fn size_as_bytes(size: u8, cluster_size: i32) -> i32 {
    if size <= 127 {
        return (size as i32).wrapping_mul(cluster_size);
    }
    let exp = 256 - size as i32;
    // (int)Math.Pow(2, exp): past int's range .NET gives int.MinValue
    if exp >= 31 { i32::MIN } else { 1 << exp }
}

impl Boot {
    pub fn parse(b: &[u8]) -> Result<Boot, String> {
        if b.len() < 512 {
            return Err(format!("The boot sector needs 512 bytes; only {} were read", b.len()));
        }
        let i16_at = |o: usize| i16::from_le_bytes([b[o], b[o + 1]]) as i32;
        let i32_at = |o: usize| i32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let i64_at = |o: usize| i64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let sector_signature = u16::from_le_bytes([b[510], b[511]]) as i32;
        let bytes_per_sector = i16_at(11);
        let sectors_per_cluster = if b[13] > 0x80 { 1i32.wrapping_shl(256 - b[13] as u32) } else { b[13] as i32 };
        let cluster_size = bytes_per_sector.wrapping_mul(sectors_per_cluster);
        let mut boot = Boot {
            boot_entry_point: format!("0x{:02X} 0x{:02X} 0x{:02X}", b[0], b[1], b[2]),
            file_system_signature: net::ascii(&b[3..11]),
            bytes_per_sector,
            sector_signature,
            sectors_per_cluster,
            reserved_sectors: i16_at(14),
            number_of_fats: b[16] as i32,
            root_directory_entries: i16_at(17),
            total_number_of_sectors16: i16_at(19),
            media_descriptor: b[21],
            sectors_per_fat: i16_at(22),
            sectors_per_track: i16_at(24),
            number_of_heads: i16_at(26),
            number_of_hidden_sectors: i32_at(28),
            total_number_of_sectors: i32_at(32),
            disk_unit_number: b[36],
            unknown_flags: b[37],
            bpb_version_signature: b[38],
            unknown_reserved: b[39],
            total_sectors: i64_at(40),
            mft_cluster_block_number: i64_at(48),
            mirror_mft_cluster_block_number: i64_at(56),
            mft_entry_size: size_as_bytes(b[64], cluster_size),
            index_entry_size: size_as_bytes(b[68], cluster_size),
            volume_serial_number_raw: i64_at(72),
            checksum: i32_at(80),
            warnings: Vec::new(),
        };
        if sector_signature != 0xaa55 {
            boot.warnings.push(format!(
                "Expected signature (0x55 0xAA) not found at offset 0x1FE. Value found: {}",
                boot.sector_signature_text()
            ));
        }
        Ok(boot)
    }

    pub fn sector_signature_text(&self) -> String {
        let b = self.sector_signature.to_le_bytes();
        format!("{:02X} {:02X}", b[0], b[1])
    }

    /// GetVolumeSerialNumber: the bytes as hex, all 8, or the low 4 (optionally reversed)
    pub fn volume_serial_number(&self, as_32_bit: bool, reverse: bool) -> String {
        let b = self.volume_serial_number_raw.to_le_bytes();
        let parts: Vec<String> = if as_32_bit {
            if reverse { (0..4).rev().map(|i| format!("{:02X}", b[i])).collect() } else { (0..4).map(|i| format!("{:02X}", b[i])).collect() }
        } else {
            (0..8).map(|i| format!("{:02X}", b[i])).collect()
        };
        parts.join(" ")
    }
}
