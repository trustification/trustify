use actix_web::web;
use trustify_common::db::Database;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::IngestorService;
use trustify_module_storage::service::dispatch::DispatchBackend;

pub fn configure(
    config: &mut web::ServiceConfig,
    db: Database,
    storage: impl Into<DispatchBackend>,
) {
    let ingestor_service = IngestorService::new(Graph::new(db.clone()), storage);
    config.app_data(web::Data::new(ingestor_service));

    crate::advisory::endpoints::configure(config, db.clone());

    crate::license::endpoints::configure(config, db.clone());

    crate::organization::endpoints::configure(config, db.clone());

    crate::purl::endpoints::configure(config, db.clone());

    crate::product::endpoints::configure(config, db.clone());

    crate::sbom::endpoints::configure(config, db.clone());

    crate::vulnerability::endpoints::configure(config, db.clone());

    crate::weakness::endpoints::configure(config, db.clone());
}
