//! The agent splot runs on a node: it answers splot's requests, one JSON line
//! each on stdin, with a JSON line each on stdout.

use std::io;

fn main() -> io::Result<()> {
    splot_agent::watch_if_asked();
    splot_agent::serve(io::stdin().lock(), io::stdout().lock())
}
