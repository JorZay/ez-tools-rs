//! SAM's UserAccounts: local users and the groups they are in.

use std::collections::HashMap;

use ez_common::Timestamp;
use ez_common::net::{self, NetResult};
use registry_ez::cells::filetime;
use registry_ez::{Hive, KeyId};

use crate::helpers::{last_write, parse_hex_i32, path, row, subkey, subkeys, time, unicode_at, value, values};
use crate::{Output, ValuesOut};

const ACCOUNT_FLAGS: &[(&str, i64)] = &[
    ("None", 0),
    ("AccountDisabled", 0x1),
    ("HomeDirectoryRequired", 0x2),
    ("PasswordNotRequired", 0x4),
    ("TempDuplicateAccount", 0x8),
    ("NormalUserAccount", 0x10),
    ("MnsLogonAccount", 0x20),
    ("InterdomainTrustAccount", 0x40),
    ("WorkstationTrustAccount", 0x80),
    ("ServerTrustAccount", 0x100),
    ("PasswordDoesNotExpire", 0x200),
    ("AutoLocked", 0x400),
];

struct Group {
    name: String,
    sids: Vec<String>,
}

pub fn user_accounts(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let Some(names) = subkey(hive, key, "Names") else { return Ok(()) };
    let groups = get_groups(hive, key, out)?;
    let computer_sid = computer_sid(hive, hive.keys[key].parent)?;

    // the RID is the type of the first value of a key of Names; its last write is when the account was made
    let mut created: HashMap<i32, Timestamp> = HashMap::new();
    for &k in subkeys(hive, names) {
        let Some(&first) = values(hive, k).first() else { continue };
        let rid = hive.vks[first].data_type_raw as i32;
        if !created.contains_key(&rid) {
            created.insert(rid, last_write(hive, k)?);
        }
    }

    for &user in subkeys(hive, key) {
        if hive.key_name(user) == "Names" {
            continue;
        }
        match read_user(hive, user, &created, &groups, computer_sid.as_deref()) {
            Ok(Some(row)) => out.rows.push(row),
            Ok(None) => {}
            Err(e) => out.errors.push(format!("Error processing user account: {e}")),
        }
    }
    Ok(())
}

/// A time of the F value, if it is later than the year 1700
fn time_after_1700(t: Timestamp) -> Option<Timestamp> {
    (t.parts().year > 1700).then_some(t)
}

/// A name in the V value: its offset (after the header of 0xCC bytes) and length are at this place
fn v_text(raw: &[u8], at: i64) -> NetResult<String> {
    let offset = net::i32_at(raw, at)?.wrapping_add(0xCC);
    let length = net::i32_at(raw, at + 4)?;
    unicode_at(raw, i64::from(offset), i64::from(length))
}

/// `Encoding.Unicode.GetString(value)` of the value with this name, or an empty string
fn whole_text(hive: &Hive, key: KeyId, name: &str) -> NetResult<String> {
    match value(hive, key, name)? {
        Some(v) => Ok(net::utf16(&hive.value_raw(v)?)),
        None => Ok(String::new()),
    }
}

fn read_user(
    hive: &Hive,
    user: KeyId,
    created: &HashMap<i32, Timestamp>,
    groups: &[Group],
    computer_sid: Option<&str>,
) -> NetResult<Option<ValuesOut>> {
    let f = value(hive, user, "F")?;
    let internet_user_name = whole_text(hive, user, "InternetUserName")?;
    let reset_data = whole_text(hive, user, "ResetData")?;

    let (mut user_id, mut valid_user_id, mut invalid_logins, mut total_logins) = (0, false, 0, 0);
    let (mut last_login, mut last_password, mut expires, mut last_incorrect) = (None, None, None, None);
    let mut flags = 0i32;

    if let Some(f) = f {
        let raw = hive.value_raw(f)?;
        let key_id = parse_hex_i32(hive.key_name(user))?;
        user_id = net::i32_at(&raw, 0x30)?;
        valid_user_id = key_id == user_id;
        invalid_logins = i32::from(net::i16_at(&raw, 0x40)?);
        total_logins = i32::from(net::i16_at(&raw, 0x42)?);
        last_login = time_after_1700(filetime(net::i64_at(&raw, 0x8)?)?);
        last_password = time_after_1700(filetime(net::i64_at(&raw, 0x18)?)?);
        // the one the original lets fail: "never" is the largest number, which isn't a valid time
        expires = net::i64_at(&raw, 0x20).and_then(filetime).ok().and_then(time_after_1700);
        last_incorrect = time_after_1700(filetime(net::i64_at(&raw, 0x28)?)?);
        if raw.len() >= 0x38 {
            flags = i32::from(net::i16_at(&raw, 0x38)?);
        }
    }

    let Some(v) = value(hive, user, "V")? else { return Ok(None) };
    let raw = hive.value_raw(v)?;
    let user_name = v_text(&raw, 0xC)?;
    let full_name = v_text(&raw, 0x18)?;
    let comment = v_text(&raw, 0x24)?;
    let user_comment = v_text(&raw, 0x30)?;
    let home_directory = v_text(&raw, 0x48)?;
    let created_on = *created.get(&user_id).ok_or_else(|| format!("The given key '{user_id}' was not present in the dictionary."))?;
    let user_groups = groups_for_user(groups, user_id, computer_sid);
    let hint = whole_text(hive, user, "UserPasswordHint")?;

    let has = |flag: i32| flags & flag == flag;
    let valid_text = if valid_user_id { "True" } else { "False" };
    let data1 = format!("Username: {user_name} Id: {user_id} ValidUserId: {valid_text}");
    let data2 = format!(
        "Created: {} Last login: {} Last password change: {} Last incorrect password: {} Expires on: {}",
        time(Some(created_on)),
        time(last_login),
        time(last_password),
        time(last_incorrect),
        time(expires)
    );
    let data3 = format!("Account flags: {}", net::flags_name(i64::from(flags), ACCOUNT_FLAGS));
    Ok(Some(row(
        vec![
            ("ValidUserId", valid_user_id.into()),
            ("UserId", user_id.into()),
            ("InvalidLoginCount", invalid_logins.into()),
            ("TotalLoginCount", total_logins.into()),
            ("CreatedOn", created_on.into()),
            ("LastLoginTime", last_login.into()),
            ("LastPasswordChange", last_password.into()),
            ("LastIncorrectPassword", last_incorrect.into()),
            ("ExpiresOn", expires.into()),
            ("UserName", user_name.into()),
            ("FullName", full_name.into()),
            ("PasswordHint", hint.into()),
            ("Groups", user_groups.into()),
            ("Comment", comment.into()),
            ("UserComment", user_comment.into()),
            ("HomeDirectory", home_directory.into()),
            ("InternetUserName", internet_user_name.into()),
            ("ResetData", reset_data.into()),
            ("AccountDisabled", has(0x1).into()),
            ("HomeDirectoryRequired", has(0x2).into()),
            ("PasswordNotRequired", has(0x4).into()),
            ("TempDuplicateAccount", has(0x8).into()),
            ("NormalUserAccount", has(0x10).into()),
            ("MnsLogonAccount", has(0x20).into()),
            ("InterdomainTrustAccount", has(0x40).into()),
            ("WorkstationTrustAccount", has(0x80).into()),
            ("ServerTrustAccount", has(0x100).into()),
            ("PasswordDoesNotExpire", has(0x200).into()),
            ("AutoLocked", has(0x400).into()),
        ],
        Some(path(hive, user)),
        Some(hive.vks[v].name()?.to_string()),
        data1,
        Some(data2),
        Some(data3),
    )))
}

/// The built in groups (Domains\Builtin\Aliases), then the ones made on the computer (Domains\Account\Aliases)
fn get_groups(hive: &Hive, users: KeyId, out: &mut Output) -> NetResult<Vec<Group>> {
    let account = hive.keys[users].parent;
    let domains = account.and_then(|k| hive.keys[k].parent);
    let builtin = domains.and_then(|k| subkey(hive, k, "Builtin"));
    let aliases = [builtin.and_then(|k| subkey(hive, k, "Aliases")), account.and_then(|k| subkey(hive, k, "Aliases"))];

    let mut groups = Vec::new();
    for key in aliases.into_iter().flatten() {
        for &alias in subkeys(hive, key) {
            let Some(c) = value(hive, alias, "C")? else { continue };
            match hive.value_raw(c).and_then(|raw| read_group(&raw)) {
                Ok(Some(group)) => groups.push(group),
                Ok(None) => {}
                Err(e) => out.errors.push(format!("Error processing group '{}': {e}", hive.key_name(alias))),
            }
        }
    }
    Ok(groups)
}

fn read_group(raw: &[u8]) -> NetResult<Option<Group>> {
    const HEADER: i32 = 0x34;
    let name_offset = net::i32_at(raw, 0x10)?.wrapping_add(HEADER);
    let name_length = net::i32_at(raw, 0x14)?;
    let description_offset = net::i32_at(raw, 0x1C)?.wrapping_add(HEADER);
    let description_length = net::i32_at(raw, 0x20)?;
    let users_offset = net::i32_at(raw, 0x28)?.wrapping_add(HEADER);
    net::i32_at(raw, 0x2C)?;
    let user_count = net::i32_at(raw, 0x30)?;
    if user_count == 0 {
        return Ok(None);
    }
    let name = unicode_at(raw, i64::from(name_offset), i64::from(name_length))?;
    unicode_at(raw, i64::from(description_offset), i64::from(description_length))?;

    let mut index = i64::from(users_offset);
    let mut sids = Vec::new();
    for _ in 0..user_count.max(0) {
        let size = match net::i16_at(raw, index)? {
            0x501 => 0x1C,
            0x101 => 0xC,
            // not a SID this knows the size of, so the rest can't be found
            _ => break,
        };
        net::block_copy_check(raw.len(), index, size, 0, size as i64)?;
        sids.push(sid_text(&raw[index as usize..index as usize + size]));
        index += size as i64;
    }
    Ok(Some(Group { name, sids }))
}

/// ConvertHexStringToSidString: its authority as a signed number, as the original reads it
fn sid_text(hex: &[u8]) -> String {
    let authority = i32::from_be_bytes([hex[4], hex[5], hex[6], hex[7]]);
    let mut sid = format!("S-{}-{authority}", hex[0]);
    for sub in hex[8..].chunks_exact(4) {
        sid.push_str(&format!("-{}", u32::from_le_bytes([sub[0], sub[1], sub[2], sub[3]])));
    }
    sid
}

/// The computer's SID: the last 24 bytes of the V value of Domains\Account
fn computer_sid(hive: &Hive, account: Option<KeyId>) -> NetResult<Option<String>> {
    let Some(account) = account else { return Ok(None) };
    let Some(v) = value(hive, account, "V")? else { return Ok(None) };
    let raw = hive.value_raw(v)?;
    if raw.len() < 24 {
        return Ok(None);
    }
    let sid = &raw[raw.len() - 24..];
    // revision 1, 4 sub authorities, NT authority, 21
    if sid[0] != 1 || sid[1] != 4 || sid[7] != 5 || sid[8..12] != 21u32.to_le_bytes() {
        return Ok(None);
    }
    Ok(Some(sid_text(sid)))
}

/// Members are SIDs; without the computer's SID, the RID is all there is to go on
fn groups_for_user(groups: &[Group], user_id: i32, computer_sid: Option<&str>) -> String {
    let wanted = computer_sid.map(|sid| format!("{sid}-{user_id}"));
    let rid = format!("-{user_id}");
    let names: Vec<&str> = groups
        .iter()
        .filter(|g| {
            g.sids.iter().any(|t| match &wanted {
                Some(sid) => t == sid,
                None => t.ends_with(&rid),
            })
        })
        .map(|g| g.name.as_str())
        .collect();
    names.join(", ")
}
