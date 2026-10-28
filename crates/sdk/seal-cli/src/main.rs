//! The `seal` binary: `seal_cli::run` on the process's arguments.

fn main() {
    std::process::exit(seal_cli::run(std::env::args_os()));
}
