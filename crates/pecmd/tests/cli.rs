
#[test]
fn arguments_follow_the_originals_rules() {
    let exe = env!("CARGO_BIN_EXE_pecmd");
    let code = |args: &[&str]| std::process::Command::new(exe).args(args).output().unwrap().status.code();
    // a value twice is refused, with 1; a flag can be repeated and takes a value in any case
    assert_eq!(code(&["-f", "a", "-f", "b"]), Some(1));
    assert_eq!(code(&["-f", "a", "--dt", "yyyy", "--dt", "MM"]), Some(1));
    assert_eq!(code(&["-f", "a", "--co", "false", "--co", "false"]), Some(1));
    assert_eq!(code(&["--nope"]), Some(1));
    // these get as far as the missing file
    assert_eq!(code(&["-f", "/nonexistent", "-q", "-q", "--co", "False"]), Some(1));
    let out = std::process::Command::new(exe).args(["-f", "/nonexistent", "-q", "-q", "--co", "False"]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("not found"), "{}", String::from_utf8_lossy(&out.stdout));
}
