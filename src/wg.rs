use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};

fn wg() -> Command {
    let mut command = Command::new("wg");
    command
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .stdout(Stdio::piped());

    command
}

pub fn generate_private_key() -> String {
    let output = wg().arg("genkey").output().unwrap();

    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end()
        .to_owned()
}

pub fn get_pubkey(private_key: &str) -> String {
    let mut child = wg().arg("pubkey").stdin(Stdio::piped()).spawn().unwrap();

    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(private_key.as_bytes()).unwrap();
    }

    let mut stdout = child.stdout.take().unwrap();

    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).unwrap();

    child.wait().unwrap();

    String::from_utf8(buf).unwrap().trim_end().to_owned()
}
