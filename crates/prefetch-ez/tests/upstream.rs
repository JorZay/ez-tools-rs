//! The assertions of the Prefetch library's own tests (TestVersion17/23/26/30, EricZimmerman/Prefetch), on its sample
//! files. Set PREFETCH_TEST_FILES to its Prefetch.Test/TestFiles folder; without it these tests do nothing.

use prefetch_ez::Prefetch;

fn sample(name: &str) -> Option<Prefetch> {
    let root = std::env::var_os("PREFETCH_TEST_FILES")?;
    Some(prefetch_ez::open(std::path::Path::new(&root).join(name), &mut |_, _| {}).unwrap())
}

#[test]
fn test2k3_cmd_pf_properties() {
    let Some(pf) = sample("Win2k3/CMD.EXE-087B4001.pf") else { return };
    let h = pf.header.as_ref().unwrap();
    let _ = h;
    assert_eq!(h.executable_filename, r#"CMD.EXE"#);
    assert_eq!(h.hash, r#"87B4001"#);
    assert_eq!(h.file_size, 6002);
    assert_eq!(pf.last_run_times[0].to_string(), "2016-01-15 23:01:40.8750000");
    assert_eq!(pf.run_count, 3);
    assert_eq!(pf.volume_count, 1);
    assert_eq!(pf.volume_information[0].device_name, r#"\DEVICE\HARDDISKVOLUME1"#);
    assert_eq!(pf.volume_information[0].serial_number, r#"64BB3469"#);
    assert_eq!(pf.volume_information[0].creation_time.to_string(), "2016-01-15 15:45:15.8906250");
    assert_eq!(pf.volume_information[0].directory_names.len(), 4);
    assert_eq!(pf.volume_information[0].directory_names[3], r#"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\"#);
    assert_eq!(pf.volume_information[0].file_references.len(), 20);
    assert_eq!(pf.filenames.len(), 16);
    assert_eq!(pf.filenames[3], r#"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\LOCALE.NLS"#);
    assert_eq!(pf.volume_information[0].file_references[5].entry_number, 250);
    assert_eq!(pf.volume_information[0].file_references[5].sequence_number, Some(1));
}

#[test]
fn test_x_p_calc_pf_properties() {
    let Some(pf) = sample("XPPro/CALC.EXE-02CD573A.pf") else { return };
    let h = pf.header.as_ref().unwrap();
    let _ = h;
    assert_eq!(h.executable_filename, r#"CALC.EXE"#);
    assert_eq!(h.hash, r#"2CD573A"#);
    assert_eq!(h.file_size, 11332);
    assert_eq!(pf.last_run_times[0].to_string(), "2016-01-13 22:05:51.2812500");
    assert_eq!(pf.run_count, 3);
    assert_eq!(pf.volume_count, 1);
    assert_eq!(pf.volume_information[0].device_name, r#"\DEVICE\HARDDISKVOLUME1"#);
    assert_eq!(pf.volume_information[0].serial_number, r#"E0F7E847"#);
    assert_eq!(pf.volume_information[0].creation_time.to_string(), "2016-01-13 11:17:18.7187500");
    assert_eq!(pf.volume_information[0].directory_names.len(), 6);
    assert_eq!(pf.volume_information[0].directory_names[3], r#"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\"#);
    assert_eq!(pf.volume_information[0].file_references.len(), 36);
    assert_eq!(pf.filenames.len(), 30);
    assert_eq!(pf.filenames[3], r#"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\LOCALE.NLS"#);
    assert_eq!(pf.volume_information[0].file_references[34].entry_number, 126);
    assert_eq!(pf.volume_information[0].file_references[34].sequence_number, Some(1));
}

#[test]
fn test_vista_explorer_pf_properties() {
    let Some(pf) = sample("Vista/EXPLORER.EXE-7A3328DA.pf") else { return };
    let h = pf.header.as_ref().unwrap();
    let _ = h;
    assert_eq!(h.executable_filename, r#"EXPLORER.EXE"#);
    assert_eq!(h.hash, r#"7A3328DA"#);
    assert_eq!(h.file_size, 38470);
    assert_eq!(pf.last_run_times[0].to_string(), "2016-01-16 20:02:00.8326765");
    assert_eq!(pf.run_count, 1);
    assert_eq!(pf.volume_count, 1);
    assert_eq!(pf.volume_information[0].device_name, r#"\DEVICE\HARDDISKVOLUME1"#);
    assert_eq!(pf.volume_information[0].serial_number, r#"E8EAB8B5"#);
    assert_eq!(pf.volume_information[0].creation_time.to_string(), "2016-01-16 20:53:13.1093750");
    assert_eq!(pf.volume_information[0].directory_names.len(), 13);
    assert_eq!(pf.volume_information[0].directory_names[3], r#"\DEVICE\HARDDISKVOLUME1\USERS\PUBLIC"#);
    assert_eq!(pf.volume_information[0].file_references.len(), 84);
    assert_eq!(pf.filenames.len(), 66);
    assert_eq!(pf.filenames[3], r#"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\ADVAPI32.DLL"#);
    assert_eq!(pf.volume_information[0].file_references[0].entry_number, 352);
    assert_eq!(pf.volume_information[0].file_references[0].sequence_number, None);
}

#[test]
fn test_win7_d_code_pf_properties() {
    let Some(pf) = sample("Win7/DCODEDCODEDCODEDCODEDCODEDCOD-9054DA3F.pf") else { return };
    let h = pf.header.as_ref().unwrap();
    let _ = h;
    assert_eq!(h.executable_filename, r#"DCODEDCODEDCODEDCODEDCODEDCOD"#);
    assert_eq!(h.hash, r#"9054DA3F"#);
    assert_eq!(h.file_size, 29746);
    assert_eq!(pf.last_run_times[0].to_string(), "2016-01-22 16:23:16.3416250");
    assert_eq!(pf.run_count, 5);
    assert_eq!(pf.volume_count, 2);
    assert_eq!(pf.volume_information[0].device_name, r#"\DEVICE\HARDDISKVOLUME2"#);
    assert_eq!(pf.volume_information[0].serial_number, r#"88008C2F"#);
    assert_eq!(pf.volume_information[0].creation_time.to_string(), "2016-01-16 21:15:18.1093750");
    assert_eq!(pf.volume_information[0].directory_names.len(), 14);
    assert_eq!(pf.volume_information[0].directory_names[3], r#"\DEVICE\HARDDISKVOLUME2\USERS\E\APPDATA\LOCAL"#);
    assert_eq!(pf.volume_information[0].file_references.len(), 63);
    assert_eq!(pf.volume_information[1].device_name, r#"\DEVICE\HARDDISKVOLUME3"#);
    assert_eq!(pf.volume_information[1].serial_number, r#"E892367F"#);
    assert_eq!(pf.volume_information[1].creation_time.to_string(), "2016-01-22 16:11:36.5781250");
    assert_eq!(pf.volume_information[1].directory_names.len(), 2);
    assert_eq!(pf.volume_information[1].directory_names[1], r#"\DEVICE\HARDDISKVOLUME3\TEMP\222"#);
    assert_eq!(pf.volume_information[1].file_references.len(), 3);
    assert_eq!(pf.filenames.len(), 50);
    assert_eq!(pf.filenames[3], r#"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\WOW64CPU.DLL"#);
    assert_eq!(pf.volume_information[1].file_references[0].entry_number, 37);
    assert_eq!(pf.volume_information[1].file_references[0].sequence_number, Some(1));
}

#[test]
fn test_win7_calc_pf_properties() {
    let Some(pf) = sample("Win7/CALC.EXE-77FDF17F.pf") else { return };
    let h = pf.header.as_ref().unwrap();
    let _ = h;
    assert_eq!(h.executable_filename, r#"CALC.EXE"#);
    assert_eq!(h.hash, r#"77FDF17F"#);
    assert_eq!(h.file_size, 23538);
    assert_eq!(pf.last_run_times[0].to_string(), "2016-01-16 20:27:01.1967500");
    assert_eq!(pf.run_count, 2);
    assert_eq!(pf.volume_count, 1);
    assert_eq!(pf.volume_information[0].device_name, r#"\DEVICE\HARDDISKVOLUME2"#);
    assert_eq!(pf.volume_information[0].serial_number, r#"88008C2F"#);
    assert_eq!(pf.volume_information[0].creation_time.to_string(), "2016-01-16 21:15:18.1093750");
    assert_eq!(pf.volume_information[0].directory_names.len(), 8);
    assert_eq!(pf.volume_information[0].directory_names[3], r#"\DEVICE\HARDDISKVOLUME2\WINDOWS\GLOBALIZATION\SORTING"#);
    assert_eq!(pf.volume_information[0].file_references.len(), 45);
    assert_eq!(pf.filenames.len(), 37);
    assert_eq!(pf.filenames[3], r#"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\KERNELBASE.DLL"#);
    assert_eq!(pf.volume_information[0].file_references[1].entry_number, 25654);
    assert_eq!(pf.volume_information[0].file_references[1].sequence_number, Some(1));
}

#[test]
fn test_win2012_r2_reg_edit_pf_properties() {
    let Some(pf) = sample("Win2012R2/NOTEPAD.EXE-D8414F97.pf") else { return };
    let h = pf.header.as_ref().unwrap();
    let _ = h;
    assert_eq!(h.executable_filename, r#"NOTEPAD.EXE"#);
    assert_eq!(h.hash, r#"D8414F97"#);
    assert_eq!(h.file_size, 15320);
    assert_eq!(pf.last_run_times[0].to_string(), "2016-01-16 21:40:31.2944718");
    assert_eq!(pf.run_count, 2);
    assert_eq!(pf.volume_count, 1);
    assert_eq!(pf.volume_information[0].device_name, r#"\DEVICE\HARDDISKVOLUME2"#);
    assert_eq!(pf.volume_information[0].serial_number, r#"7450B65F"#);
    assert_eq!(pf.volume_information[0].creation_time.to_string(), "2016-01-16 22:21:57.7889266");
    assert_eq!(pf.volume_information[0].directory_names.len(), 7);
    assert_eq!(pf.volume_information[0].directory_names[3], r#"\DEVICE\HARDDISKVOLUME2\WINDOWS\GLOBALIZATION\SORTING"#);
    assert_eq!(pf.volume_information[0].file_references.len(), 35);
    assert_eq!(pf.filenames.len(), 26);
    assert_eq!(pf.filenames[3], r#"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\ADVAPI32.DLL"#);
    assert_eq!(pf.volume_information[0].file_references[4].entry_number, 0);
    assert_eq!(pf.volume_information[0].file_references[4].sequence_number, None);
    assert_eq!(pf.volume_information[0].file_references[0].entry_number, 18972);
    assert_eq!(pf.volume_information[0].file_references[0].sequence_number, None);
}

#[test]
fn test_win2012_reg_edit_pf_properties() {
    let Some(pf) = sample("Win2012/REGEDIT.EXE-90FEEA06.pf") else { return };
    let h = pf.header.as_ref().unwrap();
    let _ = h;
    assert_eq!(h.executable_filename, r#"REGEDIT.EXE"#);
    assert_eq!(h.hash, r#"90FEEA06"#);
    assert_eq!(h.file_size, 22982);
    assert_eq!(pf.last_run_times[0].to_string(), "2016-01-16 21:36:18.7186980");
    assert_eq!(pf.run_count, 1);
    assert_eq!(pf.volume_count, 1);
    assert_eq!(pf.volume_information[0].device_name, r#"\DEVICE\HARDDISKVOLUME2"#);
    assert_eq!(pf.volume_information[0].serial_number, r#"2E25F20A"#);
    assert_eq!(pf.volume_information[0].creation_time.to_string(), "2016-01-16 22:20:46.1666157");
    assert_eq!(pf.volume_information[0].directory_names.len(), 12);
    assert_eq!(pf.volume_information[0].directory_names[3], r#"\DEVICE\HARDDISKVOLUME2\USERS\ADMINISTRATOR\APPDATA\LOCAL"#);
    assert_eq!(pf.volume_information[0].file_references.len(), 62);
    assert_eq!(pf.filenames.len(), 42);
    assert_eq!(pf.volume_information[0].file_references[4].entry_number, 27324);
    assert_eq!(pf.volume_information[0].file_references[4].sequence_number, None);
    assert_eq!(pf.volume_information[0].file_references[8].entry_number, 29316);
    assert_eq!(pf.volume_information[0].file_references[8].sequence_number, None);
}

#[test]
fn test_win8_chrome_pf_properties() {
    let Some(pf) = sample("Win8x/CALC.EXE-77FDF17F.pf") else { return };
    let h = pf.header.as_ref().unwrap();
    let _ = h;
    assert_eq!(h.executable_filename, r#"CALC.EXE"#);
    assert_eq!(h.hash, r#"77FDF17F"#);
    assert_eq!(h.file_size, 22048);
    assert_eq!(pf.last_run_times[0].to_string(), "2016-01-16 21:10:26.0583417");
    assert_eq!(pf.run_count, 2);
    assert_eq!(pf.volume_count, 1);
    assert_eq!(pf.volume_information[0].device_name, r#"\DEVICE\HARDDISKVOLUME2"#);
    assert_eq!(pf.volume_information[0].serial_number, r#"C6EE7444"#);
    assert_eq!(pf.volume_information[0].creation_time.to_string(), "2016-01-16 22:04:54.3519546");
    assert_eq!(pf.volume_information[0].directory_names.len(), 7);
    assert_eq!(pf.volume_information[0].directory_names[3], r#"\DEVICE\HARDDISKVOLUME2\WINDOWS\GLOBALIZATION\SORTING"#);
    assert_eq!(pf.volume_information[0].file_references.len(), 46);
    assert_eq!(pf.filenames.len(), 37);
    assert_eq!(pf.filenames[3], r#"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\KERNELBASE.DLL"#);
    assert_eq!(pf.volume_information[0].file_references[4].entry_number, 43858);
    assert_eq!(pf.volume_information[0].file_references[4].sequence_number, Some(1));
    assert_eq!(pf.volume_information[0].file_references[8].entry_number, 46917);
    assert_eq!(pf.volume_information[0].file_references[8].sequence_number, Some(1));
}

#[test]
fn test_win8_cmd_pf_properties() {
    let Some(pf) = sample("Win8x/_CMD.EXE-4A81B364.pf") else { return };
    let h = pf.header.as_ref().unwrap();
    let _ = h;
    assert_eq!(h.executable_filename, r#"CMD.EXE"#);
    assert_eq!(h.hash, r#"4A81B364"#);
    assert_eq!(h.file_size, 8590);
    assert_eq!(pf.last_run_times[0].to_string(), "2016-01-16 21:25:41.5341178");
    assert_eq!(pf.run_count, 2);
    assert_eq!(pf.volume_count, 1);
    assert_eq!(pf.volume_information[0].device_name, r#"\DEVICE\HARDDISKVOLUME2"#);
    assert_eq!(pf.volume_information[0].serial_number, r#"A26E529A"#);
    assert_eq!(pf.volume_information[0].creation_time.to_string(), "2016-01-16 22:15:38.2977678");
    assert_eq!(pf.volume_information[0].directory_names.len(), 8);
    assert_eq!(pf.volume_information[0].directory_names[3], r#"\DEVICE\HARDDISKVOLUME2\WINDOWS\BRANDING\BASEBRD\EN-US"#);
    assert_eq!(pf.volume_information[0].file_references.len(), 20);
    assert_eq!(pf.filenames.len(), 12);
    assert_eq!(pf.filenames[3], r#"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\KERNELBASE.DLL"#);
    assert_eq!(pf.volume_information[0].file_references[0].entry_number, 44760);
    assert_eq!(pf.volume_information[0].file_references[0].sequence_number, None);
}

#[test]
fn test_win10_chrome_pf_properties() {
    let Some(pf) = sample("Win10/CHROME.EXE-B3BA7868.pf") else { return };
    let h = pf.header.as_ref().unwrap();
    let _ = h;
    assert_eq!(h.executable_filename, r#"CHROME.EXE"#);
    assert_eq!(h.hash, r#"B3BA7868"#);
    assert_eq!(h.file_size, 116042);
    assert_eq!(pf.last_run_times[0].to_string(), "2016-01-13 18:06:55.3344577");
    assert_eq!(pf.run_count, 20);
    assert_eq!(pf.volume_count, 1);
    assert_eq!(pf.volume_information[0].device_name, r#"\VOLUME{01d1217a9c4c6779-8c9f49ec}"#);
    assert_eq!(pf.volume_information[0].serial_number, r#"8C9F49EC"#);
    assert_eq!(pf.volume_information[0].creation_time.to_string(), "2015-11-17 20:57:46.2434681");
    assert_eq!(pf.volume_information[0].directory_names.len(), 23);
    assert_eq!(pf.volume_information[0].directory_names[3], r#"\VOLUME{01d1217a9c4c6779-8c9f49ec}\PROGRAM FILES (X86)\GOOGLE\CHROME\APPLICATION"#);
    assert_eq!(pf.volume_information[0].file_references.len(), 284);
    assert_eq!(pf.last_run_times.len(), 8);
    assert_eq!(pf.filenames.len(), 282);
    assert_eq!(pf.filenames[3], r#"\VOLUME{01d1217a9c4c6779-8c9f49ec}\WINDOWS\SYSTEM32\KERNEL32.DLL"#);
    assert_eq!(pf.volume_information[0].file_references[4].entry_number, 55125);
    assert_eq!(pf.volume_information[0].file_references[4].sequence_number, Some(1));
    assert_eq!(pf.volume_information[0].file_references[8].entry_number, 117682);
    assert_eq!(pf.volume_information[0].file_references[8].sequence_number, Some(2));
}

#[test]
fn test_win10_dcode_decode_pf_properties() {
    let Some(pf) = sample("Win10/DCODEDCODEDCODEDCODEDCODEDCOD-E65B9FE8.pf") else { return };
    let h = pf.header.as_ref().unwrap();
    let _ = h;
    assert_eq!(h.executable_filename, r#"DCODEDCODEDCODEDCODEDCODEDCOD"#);
    assert_eq!(h.hash, r#"E65B9FE8"#);
    assert_eq!(h.file_size, 33606);
    assert_eq!(pf.last_run_times[0].to_string(), "2016-01-13 22:47:25.7480759");
    assert_eq!(pf.run_count, 2);
    assert_eq!(pf.volume_count, 2);
    assert_eq!(pf.volume_information[0].device_name, r#"\VOLUME{01d12173f395296c-66f451bc}"#);
    assert_eq!(pf.volume_information[0].serial_number, r#"66F451BC"#);
    assert_eq!(pf.volume_information[0].creation_time.to_string(), "2015-11-17 20:10:06.2049644");
    assert_eq!(pf.volume_information[1].device_name, r#"\VOLUME{01d1217a9c4c6779-8c9f49ec}"#);
    assert_eq!(pf.volume_information[1].serial_number, r#"8C9F49EC"#);
    assert_eq!(pf.volume_information[1].creation_time.to_string(), "2015-11-17 20:57:46.2434681");
    assert_eq!(pf.volume_information[1].directory_names.len(), 19);
    assert_eq!(pf.volume_information[0].directory_names.len(), 1);
    assert_eq!(pf.volume_information[0].directory_names[0], r#"\VOLUME{01d12173f395296c-66f451bc}\TEMP"#);
    assert_eq!(pf.volume_information[0].file_references.len(), 2);
    assert_eq!(pf.volume_information[1].file_references.len(), 85);
    assert_eq!(pf.filenames.len(), 57);
    assert_eq!(pf.filenames[3], r#"\VOLUME{01d1217a9c4c6779-8c9f49ec}\WINDOWS\SYSTEM32\KERNEL32.DLL"#);
    assert_eq!(pf.volume_information[1].file_references[11].entry_number, 357876);
    assert_eq!(pf.volume_information[1].file_references[11].sequence_number, Some(1));
    assert_eq!(pf.volume_information[0].file_references[0].entry_number, 305846);
    assert_eq!(pf.volume_information[0].file_references[0].sequence_number, Some(2));
}

#[test]
fn test_win10_dev_env_pf_properties() {
    let Some(pf) = sample("Win10/DEVENV.EXE-854D7862.pf") else { return };
    let h = pf.header.as_ref().unwrap();
    let _ = h;
    assert_eq!(h.executable_filename, r#"DEVENV.EXE"#);
    assert_eq!(h.hash, r#"854D7862"#);
    assert_eq!(h.file_size, 380690);
    assert_eq!(pf.last_run_times[0].to_string(), "2016-01-13 16:50:34.6578416");
    assert_eq!(pf.run_count, 54);
    assert_eq!(pf.volume_count, 1);
    assert_eq!(pf.volume_information[0].device_name, r#"\VOLUME{01d1217a9c4c6779-8c9f49ec}"#);
    assert_eq!(pf.volume_information[0].serial_number, r#"8C9F49EC"#);
    assert_eq!(pf.volume_information[0].creation_time.to_string(), "2015-11-17 20:57:46.2434681");
    assert_eq!(pf.volume_information[0].directory_names.len(), 516);
    assert_eq!(pf.volume_information[0].directory_names[3], r#"\VOLUME{01d1217a9c4c6779-8c9f49ec}\PROGRAM FILES (X86)\COMMON FILES\MICROSOFT SHARED\MSENV"#);
    assert_eq!(pf.volume_information[0].file_references.len(), 681);
    assert_eq!(pf.filenames.len(), 403);
    assert_eq!(pf.volume_information[0].file_references[5].entry_number, 148922);
    assert_eq!(pf.volume_information[0].file_references[5].sequence_number, Some(1));
    assert_eq!(pf.volume_information[0].file_references[7].entry_number, 219686);
    assert_eq!(pf.volume_information[0].file_references[7].sequence_number, Some(2));
}
