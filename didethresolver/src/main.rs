//! Minimal to allow integration testing on the bulk of dideth code [rust code organization](https://doc.rust-lang.org/book/ch11-03-test-organization.html#integration-tests-for-binary-crates)

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    libresolver::run().await?;
    Ok(())
}
