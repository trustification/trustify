use goose::goose::{GooseUser, TransactionResult};

pub async fn website_index(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("").await?;

    Ok(())
}

pub async fn website_openapi(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/openapi").await?;

    Ok(())
}

pub async fn website_sboms(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/sboms").await?;

    Ok(())
}

pub async fn website_packages(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/packages").await?;

    Ok(())
}

pub async fn website_advisories(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/advisories").await?;

    Ok(())
}

pub async fn website_importers(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/importers").await?;

    Ok(())
}
