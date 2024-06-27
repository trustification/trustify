use goose::goose::{GooseUser, TransactionResult};

pub async fn get_advisory(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/v1/advisory").await?;

    Ok(())
}

pub async fn get_importer(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/v1/importer").await?;

    Ok(())
}

pub async fn get_oganizations(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/v1/oganization").await?;

    Ok(())
}

pub async fn get_packages(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/v1/package").await?;

    Ok(())
}

pub async fn search_packages(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/v1/package?q=curl").await?;

    Ok(())
}

pub async fn get_packages_type(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/v1/package/type").await?;

    Ok(())
}

pub async fn get_products(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/v1/product").await?;

    Ok(())
}

pub async fn get_sboms(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/v1/sbom").await?;

    Ok(())
}
pub async fn get_vulnerabilities(user: &mut GooseUser) -> TransactionResult {
    let _goose = user.get("/v1/vulnerability").await?;

    Ok(())
}
