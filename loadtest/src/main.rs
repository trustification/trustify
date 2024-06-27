// The simplest loadtest example

mod restapi;
mod website;

use crate::restapi::{
    get_advisory, get_importer, get_oganizations, get_packages, get_packages_type, get_products,
    get_sboms, get_vulnerabilities, search_packages,
};
use crate::website::{
    website_advisories, website_importers, website_index, website_openapi, website_packages,
    website_sboms,
};
use goose::prelude::*;
use std::time::Duration;

// TODO: we will need to login at some point
//
// async fn website_login(user: &mut GooseUser) -> TransactionResult {
//     let params = [("username", "test_user"), ("password", "")];
//     let _goose = user.post_form("/login", &params).await?;
//
//     Ok(())
// }

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        .register_scenario(
            scenario!("WebsiteUser")
                // After each transactions runs, sleep randomly from 5 to 15 seconds.
                .set_wait_time(Duration::from_secs(5), Duration::from_secs(15))?
                // .register_transaction(transaction!(website_login).set_on_start())
                .register_transaction(transaction!(website_index).set_name("/index"))
                .register_transaction(transaction!(website_openapi).set_name("/openapi"))
                .register_transaction(transaction!(website_sboms).set_name("/sboms"))
                .register_transaction(transaction!(website_packages).set_name("/packages"))
                .register_transaction(transaction!(website_advisories).set_name("/advisories"))
                .register_transaction(transaction!(website_importers).set_name("/importers")),
        )
        .register_scenario(
            scenario!("RestAPIUser")
                // After each transactions runs, sleep randomly from 5 to 15 seconds.
                .set_wait_time(Duration::from_secs(5), Duration::from_secs(15))?
                // .register_transaction(transaction!(website_login).set_on_start())
                .register_transaction(transaction!(get_advisory).set_name("/v1/advisory"))
                .register_transaction(transaction!(get_importer).set_name("/v1/importer"))
                .register_transaction(transaction!(get_oganizations).set_name("/v1/organization"))
                .register_transaction(transaction!(get_packages).set_name("/v1/package"))
                .register_transaction(transaction!(search_packages).set_name("/v1/package?q=curl"))
                .register_transaction(transaction!(get_packages_type).set_name("/v1/package/type"))
                .register_transaction(transaction!(get_products).set_name("/v1/product"))
                .register_transaction(transaction!(get_sboms).set_name("/v1/sbom"))
                .register_transaction(
                    transaction!(get_vulnerabilities).set_name("/v1/vulnerability"),
                ),
        )
        .execute()
        .await?;

    Ok(())
}
