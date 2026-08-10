use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);

    let url = arguments
        .next()
        .unwrap_or_else(|| "http://10.77.0.2:3000/".to_owned());

    let rounds: usize = arguments
        .next()
        .and_then(|rounds| rounds.parse().ok())
        .unwrap_or(3);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    eprintln!("requesting {url} {rounds} times");

    let mut failures = 0;

    for round in 1..=rounds {
        let started = Instant::now();

        match client.get(&url).send().await {
            Ok(response) => {
                let status = response.status();
                let body = response.text().await?;
                let elapsed = started.elapsed();

                eprintln!(
                    "round {round}: {status} in {:.1}ms, {} bytes",
                    elapsed.as_secs_f64() * 1000.0,
                    body.len()
                );

                print!("{body}");
            }
            Err(e) => {
                failures += 1;
                eprintln!("round {round}: failed after {:?}: {e}", started.elapsed());
            }
        }
    }

    if failures > 0 {
        return Err(format!("{failures} of {rounds} requests failed").into());
    }

    eprintln!("all {rounds} requests succeeded");

    Ok(())
}
