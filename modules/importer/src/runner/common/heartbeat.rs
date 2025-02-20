use super::Error;
use crate::model::Importer;
use sea_orm::{entity::*, prelude::*, QueryFilter};
use time::OffsetDateTime;
use tokio::{
    task::JoinHandle,
    time::{interval, Duration},
};
use trustify_common::db::Database;
use trustify_entity::importer;

pub struct Heart {
    name: String,
    handle: JoinHandle<()>,
}

impl Heart {
    pub const RATE: Duration = Duration::from_secs(10);

    pub fn new(importer: Importer, db: Database) -> Self {
        let name = importer.name.clone();
        let handle = tokio::spawn(async move {
            let mut interval = interval(Heart::RATE);
            let mut importer = importer;
            loop {
                interval.tick().await;
                match Self::beat(&importer, &db).await {
                    Ok(i) => {
                        log::debug!("{}: {:#?}", i.name, i.data.progress);
                        importer = i;
                    }
                    Err(e) => log::error!("Failed to send heartbeat for '{}': {e}", importer.name),
                }
            }
        });
        Self { name, handle }
    }

    // Updates the importer record with the current time, but only if
    // the db matches our previous update, i.e. optimistic
    // locking. Returns the updated record on success.
    pub async fn beat(importer: &Importer, db: &Database) -> Result<Importer, Error> {
        let t = OffsetDateTime::now_utc().unix_timestamp_nanos();
        let model = importer::ActiveModel {
            name: Set(importer.name.to_owned()),
            heartbeat: Set(Some(t.into())),
            ..Default::default()
        };
        use importer::Column::Heartbeat;
        let lock = match importer.heartbeat {
            Some(t) => Expr::col(Heartbeat).eq(Decimal::from_i128_with_scale(t, 0)),
            None => Expr::col(Heartbeat).is_null(),
        };
        // We rely on the fact that `update` will return an error if
        // no row is affected. This is contrary to how `update_many`
        // behaves.
        match importer::Entity::update(model).filter(lock).exec(db).await {
            Ok(model) => Importer::try_from(model).map_err(Error::Json),
            Err(e) => Err(Error::Heartbeat(e)),
        }
    }
}

impl Drop for Heart {
    fn drop(&mut self) {
        log::debug!("Shutting down heartbeat for {}", self.name);
        self.handle.abort();
    }
}
