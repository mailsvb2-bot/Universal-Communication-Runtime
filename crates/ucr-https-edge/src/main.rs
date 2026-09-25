#![forbid(unsafe_code)]

#[tokio::main]
async fn main() {
    if let Err(error) = ucr_https_edge::run().await {
        eprintln!("ucr-https-edge: {error}");
        std::process::exit(2);
    }
}
