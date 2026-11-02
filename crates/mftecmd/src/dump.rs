//! --de: a FILE record's details (MFTECmd's DumpEntry), and with --fls a directory's contents.

use ez_common::cli::log::Logger;
use ez_common::net::{self, enum_name, flags_name};
use ez_common::time::Timestamp;
use ntfs_ez::mft::attributes::{
    ATTRIBUTE_TYPE_NAMES, AttributeBody, AttributeHeader, EaItem, NAME_TYPE_NAMES, NonResidentData, SI_FLAG_NAMES,
};
use ntfs_ez::mft::record::ENTRY_FLAG_NAMES;
use ntfs_ez::mft::security::{ACE_FLAG_NAMES, Acl, AclType, CONTROL_NAMES, MASK_NAMES, SkSecurityDescriptor};
use ntfs_ez::mft::sid_types::{sid_description, sid_type};
use ntfs_ez::mft::{Key, Mft};

const FLAGS2_NAMES: &[(&str, i64)] = &[("None", 0), ("IsCaseSensitive", 1)];
const DATA_FLAG_NAMES: &[(&str, i64)] = &[("Compressed", 0x0001), ("Encrypted", 0x4000), ("Sparse", 0x8000)];
const COLLATION_NAMES: &[(&str, i64)] = &[
    ("Binary", 0),
    ("Filename", 1),
    ("Unicode", 2),
    ("NtOfsUlong", 0x10),
    ("NtOfsSid", 0x11),
    ("NtOfsSecurityHash", 0x12),
    ("NtOfsUlongs", 0x13),
];
const VOLUME_FLAG_NAMES: &[(&str, i64)] = &[
    ("None", 0),
    ("IsDirty", 1),
    ("ResizeJournalLogFile", 2),
    ("UpgradeOnNextMount", 4),
    ("MountedOnNt4", 8),
    ("DeleteUsnUnderway", 0x10),
    ("RepairObjectIDs", 0x20),
    ("ModifiedByChkDsk", 0x8000),
];

/// Parses `Entry` or `Entry-Seq` (decimal, or hex when it starts with 0x); the record's block, or false to exit
pub fn dump_entry(mft: &Mft, de: &str, fls: bool, dt: &str, log: &mut Logger) -> bool {
    log.info("");
    let segs: Vec<&str> = de.split('-').collect();
    let hex = de.starts_with("0x");
    let parse = |s: &str| -> Option<i32> {
        if hex { i32::from_str_radix(&s.replace("0x", ""), 16).ok() } else { s.trim().parse().ok() }
    };
    let key = match segs.len() {
        1 => {
            let entry = parse(segs[0]).unwrap_or(0);
            let found = mft.keys_for_entry(entry as u32 as u64);
            match found.len() {
                1 => found[0].0,
                0 => {
                    log.warning("\nCould not find FILE record with specified Entry #. Use the --csv option and verify\n");
                    return false;
                }
                _ => {
                    log.warning("\nMore than one FILE record found. Please specify one of the values below and try again!\n");
                    for (_, b) in found {
                        let r = mft.record(b);
                        log.info(&format!("0x{:X}-0x{:X}", r.entry_number, r.sequence_number));
                    }
                    return false;
                }
            }
        }
        _ => {
            let (Some(e), Some(s)) = (parse(segs[0]), parse(segs[1])) else {
                log.warning(&format!("Could not parse {de} to valid values. Exiting"));
                return false;
            };
            let key = Key { entry: e as u32 as u64, sequence: s };
            if segs.len() == 2 && mft.find(key).is_none() {
                log.warning("\nCould not find FILE record with specified Entry #. Use the --csv option and verify\n");
                return false;
            }
            key
        }
    };
    let Some(block) = mft.find(key) else {
        log.warning(&format!("Could not find file record with entry/seq {de}. Exiting"));
        return false;
    };
    let fr = mft.full_record(block);

    if fr.is_directory() && fls {
        let name = if fr.file_names().next().is_some() { mft.full_path(key).into_owned() } else { key.to_string() };
        log.info(&format!("Contents for {name}\n"));
        log.info("Key\t\t\tType\t\tName");
        for (n, k, is_dir) in mft.directory_contents(key) {
            if is_dir {
                log.info(&format!("{k:<16}\tDirectory\t{n}"));
            } else {
                log.info(&format!("{k:<16}\tFile\t\t{n}"));
            }
        }
        log.info("");
        return true;
    }

    let date = |raw: i64| -> String {
        Timestamp::from_filetime(raw).filter(|_| raw > 0).map(|t| t.format(dt)).unwrap_or_else(|| "null".into())
    };
    log.info(&format!("Dumping details for file record with key {key}\n"));
    let fixups: Vec<&[u8]> = fr.fixup_raw[2..].chunks(2).collect();
    let actual = format!("{} | {}", net::hex(fixups.first().copied().unwrap_or(&[])), net::hex(fixups.get(1).copied().unwrap_or(&[])));
    log.info(&format!(
        "Entry-seq #: 0x{:X}-0x{:X}, Offset: 0x{:X}, Flags: {}, Log seq #: 0x{:X}, Base Record entry-seq: 0x{:X}-0x{:X}",
        fr.entry_number,
        fr.sequence_number,
        fr.offset,
        flags_name(fr.entry_flags as i64, ENTRY_FLAG_NAMES),
        fr.log_sequence_number,
        fr.base_record.entry,
        fr.base_record.sequence
    ));
    log.info(&format!(
        "Reference count: 0x{:X}, FixUp Data Expected: {}, FixUp Data Actual: {actual} (FixUp OK: {})",
        fr.reference_count,
        net::hex(&fr.fixup_raw[..2]),
        if fr.fixup_ok { "True" } else { "False" }
    ));
    log.info("");

    let info = |log: &mut Logger, h: &AttributeHeader, description: &str| {
        log.info(&format!("**** {description} ****"));
        log.info(&format!(
            "  Attribute #: 0x{:X}, Size: 0x{:X}, Content size: 0x{:X}, Name size: 0x{:X}, ContentOffset 0x{:X}. Resident: {}",
            h.number,
            h.size,
            h.content_length,
            h.name_size,
            h.content_offset,
            if h.resident { "True" } else { "False" }
        ));
        if h.data_flags > 0 {
            log.info(&format!("  Attribute flags: {}", flags_name(h.data_flags as i64, DATA_FLAG_NAMES)));
        }
        if !h.name.is_empty() {
            log.info(&format!("  Name: {}", h.name));
        }
    };
    let resident = |log: &mut Logger, d: &[u8]| {
        log.info("  Resident Data\n");
        log.info(&format!("  Data: {}\n", net::hex(d)));
        log.info(&format!("    ASCII:   {}", net::ascii(d)));
        log.info(&format!("    UNICODE: {}", net::utf16(d)));
    };
    let non_resident = |log: &mut Logger, n: &NonResidentData| {
        log.info("  Non-Resident Data");
        log.info(&format!(
            "  Starting Virtual Cluster #: 0x{:X}, Ending Virtual Cluster #: 0x{:X}, Allocated Size: 0x{:X}, Actual Size: 0x{:X}, Initialized Size: 0x{:X} \n",
            n.starting_vcn, n.ending_vcn, n.allocated_size, n.actual_size, n.initialized_size
        ));
        log.info("  DataRuns Entries (Cluster offset -> # of clusters)");
        for r in &n.data_runs {
            log.info(&format!("  {:<32} ->      0x{:X}", format!("0x{:X}", r.cluster_offset), r.clusters_in_run));
        }
    };
    let content = |log: &mut Logger, r: &Option<Vec<u8>>, n: &Option<NonResidentData>| match (r, n) {
        (Some(d), _) => resident(log, d),
        (None, Some(n)) => non_resident(log, n),
        _ => {}
    };
    let acl_dump = |log: &mut Logger, acl: &Acl| {
        log.info(&format!("    ACL Revision:   0x{:X}", acl.revision()));
        log.info(&format!("    ACL Size:       0x{:X}", acl.size()));
        log.info(&format!("    ACL Type:       {}", if acl.acl_type == AclType::Security { "Security" } else { "Discretionary" }));
        log.info(&format!("    Sbz1:           0x{:X}", acl.raw.get(1).copied().unwrap_or(0)));
        log.info(&format!(
            "    Sbz2:           0x{:X}\n",
            acl.raw.get(6..8).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0)
        ));
        log.info(&format!("    ACE Records Count: {}\n", acl.ace_count()));
        for (i, a) in acl.aces().iter().enumerate() {
            let sid = a.sid();
            log.info(&format!("    ------------ Ace record #{i} ------------"));
            log.info(&format!("    ACE Size:  0x{:X}", a.size()));
            log.info(&format!("    ACE Type:  {}", a.type_name()));
            log.info(&format!("    ACE Flags: {}", flags_name(a.flags() as i64, ACE_FLAG_NAMES)));
            log.info(&format!("    Mask:      {}", flags_name(a.mask() as i32 as i64, MASK_NAMES)));
            log.info(&format!("    SID:       {sid}"));
            log.info(&format!("    SID Type:  {}", sid_type(&sid)));
            log.info(&format!(
                "    SID Type Description: {}\n",
                sid_description(&sid).unwrap_or("SID does not map to a common SID or this is a user SID")
            ));
        }
    };

    for a in &fr.attributes {
        let h = &a.header;
        match &a.body {
            AttributeBody::StandardInfo(si) => {
                info(log, h, "STANDARD INFO");
                log.info(&format!(
                    "  Flags: {}, Max Version: 0x{:X}, Flags 2: {}, Class Id: 0x{:X}, Owner Id: 0x{:X}, Security Id: 0x{:X}, Quota charged: 0x{:X}, Update sequence #: 0x{:X}\n",
                    flags_name(si.flags as i64, SI_FLAG_NAMES),
                    si.max_version,
                    flags_name(si.flags2 as i64, FLAGS2_NAMES),
                    si.class_id,
                    si.owner_id,
                    si.security_id,
                    si.quota_charged,
                    si.update_sequence_number
                ));
                times(log, [si.created, si.content_modified, si.record_modified, si.last_accessed], &date);
            }
            AttributeBody::FileName(f) => {
                info(log, h, "FILE NAME");
                log.info("");
                log.info(&format!("  File name: {}", f.file_name));
                log.info(&format!(
                    "  Flags: {}, Name Type: {}, Reparse Value: 0x{:X}, Physical Size: 0x{:X}, Logical Size: 0x{:X}",
                    flags_name(f.flags as i64, SI_FLAG_NAMES),
                    flags_name(f.name_type as i64, NAME_TYPE_NAMES),
                    f.reparse_value,
                    f.physical_size,
                    f.logical_size
                ));
                log.info(&format!("  Parent Entry-seq #: 0x{:X}-0x{:X}\n", f.parent.entry, f.parent.sequence));
                times(log, [f.created, f.content_modified, f.record_modified, f.last_accessed], &date);
            }
            AttributeBody::Data(d) => {
                info(log, h, "DATA");
                log.info("");
                content(log, &d.resident, &d.non_resident);
                log.info("");
            }
            AttributeBody::SecurityDescriptor(sd) => {
                info(log, h, "SECURITY DESCRIPTOR");
                log.info("");
                let Some(sk) = sd.resident.clone().and_then(|d| SkSecurityDescriptor::new(d).ok()) else { continue };
                log.info("  Security Information");
                log.info(&format!("    Revision: 0x{:X}", sk.revision()));
                log.info(&format!("    Control:  {}\n", flags_name(sk.control() as i64, CONTROL_NAMES)));
                let (o, g) = (sk.owner_sid(), sk.group_sid());
                log.info(&format!("    Owner Offset:   0x{:X}", sk.owner_offset()));
                log.info(&format!("    Owner SID:      {o}"));
                log.info(&format!("    Owner SID Type: {}\n", sid_type(&o)));
                log.info(&format!("    Group Offset:   0x{:X}", sk.group_offset()));
                log.info(&format!("    Group SID:      {g}"));
                log.info(&format!("    Group SID Type: {}", sid_type(&g)));
                if let Some(d) = sk.dacl() {
                    log.info(&format!("\n    Dacl Offset:    0x{:X}", sk.dacl_offset()));
                    acl_dump(log, &d);
                }
                if let Some(s) = sk.sacl() {
                    log.info(&format!("\n    Sacl Offset:    0x{:X}", sk.sacl_offset()));
                    acl_dump(log, &s);
                }
                log.info("");
                content(log, &sd.resident, &sd.non_resident);
                log.info("");
            }
            AttributeBody::IndexRoot(ir) => {
                info(log, h, "INDEX ROOT");
                log.info("");
                log.info(&format!(
                    "  Indexed Attribute Type: {} Entry Size: 0x{:X} Number Cluster Blocks: 0x{:X} Collation Type: {} Index entries count: 0x{:X}",
                    enum_name(ir.indexed_attribute_type as i64, ATTRIBUTE_TYPE_NAMES),
                    ir.entry_size,
                    ir.number_cluster_blocks,
                    enum_name(ir.collation_type as i64, COLLATION_NAMES),
                    ir.entries.len()
                ));
                log.info("  FileInfo Records Entries");
                for e in &ir.entries {
                    log.info(&format!("  File name: {}", e.file_name.as_deref().unwrap_or("null")));
                    log.info(&format!(
                        "  Flags: {}, Name Type: {}, Reparse Value: 0x{:X}, Physical Size: 0x{:X}, Logical Size: 0x{:X}",
                        flags_name(e.flags as i64, SI_FLAG_NAMES),
                        flags_name(e.name_type as i64, NAME_TYPE_NAMES),
                        e.reparse_value,
                        e.physical_size,
                        e.logical_size
                    ));
                    if let Some(m) = e.mft_reference {
                        log.info(&format!("  Entry-seq #: 0x{:X}-0x{:X}", m.entry, m.sequence));
                    }
                    if let Some(p) = e.parent {
                        log.info(&format!("  Parent Entry-seq #: 0x{:X}-0x{:X}", p.entry, p.sequence));
                    }
                    log.info("");
                    times(log, [e.created, e.content_modified, e.record_modified, e.last_accessed], &date);
                }
                log.info("");
            }
            AttributeBody::IndexAllocation(n) => {
                info(log, h, "INDEX ALLOCATION");
                log.info("");
                non_resident(log, n);
                log.info("");
            }
            AttributeBody::Bitmap(d) => {
                info(log, h, "BITMAP");
                log.info("");
                content(log, &d.resident, &d.non_resident);
                log.info("");
            }
            AttributeBody::LoggedUtilityStream(d) => {
                info(log, h, "LOGGED UTILITY STREAM");
                log.info("");
                resident(log, d);
                log.info("");
            }
            AttributeBody::ObjectId(o) => {
                info(log, h, "OBJECT ID");
                log.info("");
                let mac = |g: &[u8; 16]| net::hex(&g[10..16]).replace('-', ":").to_lowercase();
                let created = |g: &[u8; 16]| -> Option<Timestamp> {
                    let mut b = *g;
                    b[7] &= 0x0f;
                    let ts = i64::from_le_bytes(b[0..8].try_into().unwrap());
                    // 1582-10-15, where UUID times start
                    let ticks = ts.checked_add(499_163_040_000_000_000)?;
                    (0..=ez_common::time::MAX_TICKS).contains(&ticks).then_some(Timestamp(ticks))
                };
                log.info(&format!("  Object Id:            {}", net::guid(&o.object_id)));
                log.info(&format!("    Object Id MAC:        {}", mac(&o.object_id)));
                if let Some(c) = created(&o.object_id).filter(|c| c.parts().year < 3000) {
                    log.info(&format!("    Object Id Created On: {}", c.format(dt)));
                }
                log.info("");
                log.info(&format!("  Birth Volume Id:      {}", net::guid(&o.birth_volume_id)));
                if o.birth_object_id != [0u8; 16] {
                    log.info(&format!("    Birth Volume Id MAC:      {}", mac(&o.birth_object_id)));
                    let c = created(&o.birth_object_id).map(|c| c.format(dt)).unwrap_or_default();
                    log.info(&format!("  Birth Volume Id Created On: {c}"));
                }
                log.info("");
                log.info(&format!("  Birth Object Id:      {}", net::guid(&o.birth_object_id)));
                log.info(&format!("  Domain Id:            {}\n", net::guid(&o.domain_id)));
            }
            AttributeBody::Ea(ea) => {
                info(log, h, "EXTENDED ATTRIBUTE");
                log.info("");
                log.info(&format!("  Extended Attribute: {}", net::hex(&ea.content)));
                log.info(&format!("  ASCII: {}", net::ascii(&ea.content)));
                log.info(&format!("  Unicode: {}", net::utf16(&ea.content)));
                if !ea.items.is_empty() {
                    log.info("  Sub items");
                }
                let ft = |raw: i64| Timestamp::from_filetime(raw).map(|t| t.format(dt)).unwrap_or_default();
                let unix = |s: i64| Timestamp(s * 10_000_000 + 621_355_968_000_000_000).format(dt);
                for item in &ea.items {
                    match item {
                        EaItem::Lx { name } => {
                            log.info(&format!("  Name: {}", name.split(':').next().unwrap_or("")));
                            log.info(&format!("  Name: {name}"));
                        }
                        EaItem::LongName { name } => {
                            log.info("  Name: .LONGNAME");
                            log.info(&format!("  .LONGNAME: {name}"));
                        }
                        EaItem::Lxattrb { values, format, version, times } => {
                            log.info("  Name: LXATTRB");
                            log.info(&format!("  Format: 0x{format:X}"));
                            log.info(&format!("  Version: 0x{version:X}"));
                            log.info(&format!("  Mode: 0x{:X}", values[0]));
                            log.info(&format!("  Uid/Gid: 0x{:X}/0x{:X}", values[1], values[2]));
                            log.info(&format!("  DeviceId: 0x{:X}", values[3]));
                            let sub = |ns: i32| ez_common::dotnet::dotnet_f64(ns as f64 / 1e9);
                            let last = sub(values[4]);
                            let last = if last.len() > 2 { last[2..].to_string() } else { "0000000".into() };
                            log.info(&format!("  Last Access Time: {}.{last}", unix(times[0])));
                            log.info(&format!("  Modified Time: {}.{}", unix(times[1]), sub(values[5])));
                            log.info(&format!("  Inode Time: {}.{}", unix(times[1]), sub(values[6])));
                        }
                        EaItem::Lxattrr { key_values, .. } => {
                            log.info("  Name: LXXATTR");
                            for (k, v) in key_values {
                                log.info(&format!("  Key: {k} --> {v}"));
                            }
                        }
                        EaItem::PurgeEsbCache { timestamp, timestamp2 } => {
                            log.info("  Name: $KERNEL.PURGE.ESBCACHE");
                            log.info(&format!(
                                "  $KERNEL.PURGE.ESBCACHE | Timestamp: {} Timestamp2: {}",
                                ft(*timestamp),
                                ft(*timestamp2)
                            ));
                        }
                        EaItem::CatHint { hint, .. } => {
                            log.info("  Name: $CI.CATALOGHINT");
                            log.info(&format!("  $CI.CATALOGHINT | Hint: {hint}"));
                        }
                        EaItem::AppFixCache { timestamp, remaining } => {
                            log.info("  Name: $KERNEL.PURGE.APPFIXCACHE");
                            log.info(&format!(
                                "  $KERNEL.PURGE.APPFIXCACHE | Timestamp: {} Remaining bytes: {}",
                                ft(*timestamp),
                                net::hex(remaining)
                            ));
                        }
                        EaItem::ClassInfo => {
                            log.info("  Name: .CLASSINFO");
                            log.info("  .ClassInfo: Not decoded");
                        }
                    }
                }
                log.info("");
            }
            AttributeBody::EaInformation(e) => {
                info(log, h, "EXTENDED ATTRIBUTE INFORMATION");
                log.info("");
                log.info(&format!(
                    "  Ea Size: 0x{:X}, Number Of Extended Attributes With Need Ea Set: 0x{:X} Size Of Ea Data: 0x{:X} \n",
                    e.ea_size, e.need_ea_count, e.ea_data_size
                ));
            }
            AttributeBody::ReparsePoint(r) => {
                info(log, h, "REPARSE POINT");
                log.info("");
                log.info(&format!(
                    "  Substitute Name: {} Print Name: {} Tag: {}\n",
                    r.substitute_name,
                    r.print_name,
                    r.tag_name()
                ));
            }
            AttributeBody::VolumeInformation(v) => {
                info(log, h, "VOLUME INFORMATION");
                log.info("");
                log.info(&format!(
                    "  Volume Flags: {} Major Version: 0x{:X} Minor Version: 0x{:X} Unknown Bytes: {} \n",
                    flags_name(v.flags as i64, VOLUME_FLAG_NAMES),
                    v.major_version,
                    v.minor_version,
                    net::hex(&v.unknown)
                ));
            }
            AttributeBody::VolumeName(n) => {
                info(log, h, "VOLUME NAME");
                log.info("");
                log.info(&format!("  Volume Name: {n}\n"));
            }
            AttributeBody::AttributeList(_) => {}
        }
    }
    true
}

fn times(log: &mut Logger, t: [i64; 4], date: &dyn Fn(i64) -> String) {
    log.info(&format!("  Created On:         {}", date(t[0])));
    log.info(&format!("  Modified On:        {}", date(t[1])));
    log.info(&format!("  Record Modified On: {}", date(t[2])));
    log.info(&format!("  Last Accessed On:   {}\n", date(t[3])));
}
