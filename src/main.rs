use anyhow::Result;
use didethresolver::run;

#[tokio::main]
async fn main() -> Result<()> {
    crate::run().await?;
    Ok(())
}
