use actix_web::web;
use std::sync::Arc;
use trustify_auth::authenticator::Authenticator;
use trustify_common::db::Database;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::IngestorService;
use trustify_module_storage::service::dispatch::DispatchBackend;

pub fn configure(
    config: &mut web::ServiceConfig,
    db: Database,
    storage: impl Into<DispatchBackend>,
    auth: Option<Arc<Authenticator>>,
) {
    let storage = storage.into();

    let ingestor_service = IngestorService::new(Graph::new(db.clone()), storage.clone());
    config.app_data(web::Data::new(ingestor_service));

    crate::advisory::endpoints::configure(config, db.clone(), auth.clone());

    crate::organization::endpoints::configure(config, db.clone(), auth.clone());

    crate::package::endpoints::configure(config, db.clone(), auth.clone());

    crate::sbom::endpoints::configure(config, db.clone(), auth.clone());

    crate::vulnerability::endpoints::configure(config, db.clone(), auth.clone());
}
