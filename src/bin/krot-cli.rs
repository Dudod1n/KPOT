fn main() {
    if let Err(error) = krot::app::run() {
        eprintln!("КРОТ: {error:#}");
        std::process::exit(1);
    }
}
