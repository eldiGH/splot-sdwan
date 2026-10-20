//! Running the programs splot drives (uci, wg, ubus): one place that spawns them,
//! feeds them their input and collects what they print.

use std::{
    io::{self, Write},
    panic,
    process::{Command, Output, Stdio},
    thread,
};

/// Why a program couldn't be run to the end. Callers name the program in their
/// own errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// It couldn't be started: missing, or not executable.
    #[error("couldn't start the program")]
    Spawn(#[source] io::Error),
    /// Talking to it failed while it ran.
    #[error("i/o error while talking to the program")]
    Io(#[source] io::Error),
}

/// Runs `command` to its end, with `stdin` as its input (none: an empty one),
/// and returns how it exited and what it printed.
///
/// The input is written from a thread while the output is read. Written first,
/// it would block for good on a program that prints before it has read all of
/// it: its output fills the pipe, it waits for room, and so would we.
pub fn run(mut command: Command, stdin: Option<&[u8]>) -> Result<Output, Error> {
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(Error::Spawn)?;
    let input = stdin.map(|input| {
        let pipe = child
            .stdin
            .take()
            .expect("stdin was piped and not yet taken");
        (pipe, input)
    });

    thread::scope(|scope| {
        // The pipe closes when the thread is done with it: the program's end of
        // input.
        let writer = input.map(|(mut pipe, input)| scope.spawn(move || pipe.write_all(input)));
        let output = child.wait_with_output().map_err(Error::Io)?;
        let written =
            writer.map(|writer| writer.join().unwrap_or_else(|p| panic::resume_unwind(p)));

        match written {
            // It stopped reading yet claims success: what it read can't be
            // trusted. One that failed says why in its exit and its output.
            Some(Err(err)) if output.status.success() => Err(Error::Io(err)),
            _ => Ok(output),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, thread, time::Duration};

    use super::*;

    /// `run`, given up on after a while: a deadlock fails the test instead of
    /// hanging it.
    fn run_within(command: Command, stdin: Vec<u8>, seconds: u64) -> Result<Output, Error> {
        let (done, result) = mpsc::channel();
        thread::spawn(move || {
            let _ = done.send(run(command, Some(&stdin)));
        });

        result
            .recv_timeout(Duration::from_secs(seconds))
            .expect("the program didn't finish: run blocked")
    }

    #[test]
    fn a_program_that_prints_before_it_has_read_all_its_input_completes() {
        // `cat` writes back as it reads. Its output fills the pipe long before
        // a megabyte of input is written, so whoever writes all the input first
        // and reads afterwards blocks for good, and so does `cat`.
        let input: Vec<u8> = (0..1_000_000).map(|i| b'a' + (i % 26) as u8).collect();
        let output = run_within(Command::new("cat"), input.clone(), 10).unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout, input);
    }

    #[test]
    fn a_program_that_fails_without_reading_its_input_reports_its_exit() {
        // It never reads: writing gets a broken pipe. What matters to the caller
        // is how the program exited and what it said.
        let mut command = Command::new("sh");
        command.args(["-c", "echo bad input >&2; exit 3"]);

        let output = run_within(command, vec![b'x'; 1_000_000], 10).unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stderr, b"bad input\n");
    }

    #[test]
    fn a_program_that_succeeds_without_reading_its_input_is_an_error() {
        // It never read what it was given, so its success means nothing.
        let mut command = Command::new("sh");
        command.args(["-c", "exit 0"]);

        let result = run_within(command, vec![b'x'; 1_000_000], 10);
        assert!(matches!(result, Err(Error::Io(_))), "{result:?}");
    }

    #[test]
    fn a_program_that_isnt_there_cant_be_started() {
        let result = run(Command::new("splot-no-such-program"), None);
        assert!(matches!(result, Err(Error::Spawn(_))));
    }

    #[test]
    fn without_input_a_program_reads_an_empty_one() {
        let output = run(Command::new("cat"), None).unwrap();
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
    }
}
