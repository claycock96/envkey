fn main() {
    if let Err(err) = envkey::cli::run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
