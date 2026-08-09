use axum::{Router, routing::get};

async fn index() -> &'static str {
    "hello from axum, running on a tcp stack it knows nothing about\n"
}

async fn whoami(headers: axum::http::HeaderMap) -> String {
    format!("you asked for host {:?}\n", headers.get("host"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/", get(index))
        .route("/whoami", get(whoami));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;

    eprintln!("axum listening on {}", listener.local_addr()?);

    axum::serve(listener, app).await?;

    Ok(())
}
