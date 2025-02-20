use std::future::Future;

use super::Error;
use crate::model::Importer;
use sea_orm::{QueryFilter, entity::*, prelude::*};
use time::OffsetDateTime;
use tokio::{
    task::{JoinHandle, spawn_local},
    time::{Duration, interval},
};
use trustify_common::db::Database;
use trustify_entity::importer;

pub struct Heart {
    handle: JoinHandle<()>,
}

impl Heart {
    pub const RATE: Duration = Duration::from_secs(10);

    pub fn new<F>(importer: Importer, db: Database, future: F) -> Self
    where
        F: Future + 'static,
    {
        let handle = spawn_local(Heart::pump(importer, db, future));
        Self { handle }
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
        // no row is affected. This is not how `update_many` behaves.
        match importer::Entity::update(model).filter(lock).exec(db).await {
            Ok(model) => Importer::try_from(model).map_err(Error::Json),
            Err(e) => Err(Error::Heartbeat(e)),
        }
    }

    pub fn is_beating(&self) -> bool {
        !self.handle.is_finished()
    }

    async fn pump<F>(importer: Importer, db: Database, future: F)
    where
        F: Future + 'static,
    {
        let name = importer.name.clone();
        if let Ok(importer) = Heart::beat(&importer, &db).await {
            log::debug!("Acquired lock; running '{name}'");
            let work = spawn_local(future);
            let mut interval = interval(Heart::RATE);
            let mut importer = importer;
            loop {
                interval.tick().await;
                match Self::beat(&importer, &db).await {
                    Ok(i) => {
                        log::debug!("{name}: {:#?}", i.data.progress);
                        importer = i;
                    }
                    Err(e) => {
                        log::error!("Aborting '{name}': {e}");
                        work.abort();
                    }
                }
                if work.is_finished() {
                    log::debug!("Releasing lock; finished '{name}'");
                    break;
                }
            }
        } else {
            log::debug!("Unable to acquire lock to run '{name}'");
        }
    }
}

impl Drop for Heart {
    fn drop(&mut self) {
        self.handle.abort()
    }
}
