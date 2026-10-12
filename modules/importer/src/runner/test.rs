use super::{
    common::heartbeat::Heart,
    context::RunContext,
    report::{Phase, Report, Severity},
};
use crate::{model::ImporterConfiguration, service::ImporterService};
use futures::TryStreamExt;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::{
    cell::Cell,
    fmt::{self, Display},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use test_context::test_context;
use test_log::test;
use tokio::{
    task::LocalSet,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use trustify_common::{
    db::{ReadWrite, pagination_cache::PaginationCache},
    hashing::Digests,
    id::Id,
};
use trustify_entity::source_document;
use trustify_module_storage::service::{StorageBackend, StorageKey};
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

pub(crate) fn assert_send<T: Send>(value: T) -> T {
    value
}

pub(crate) fn assert_send_sync<T: Send + Sync>() {}

#[derive(Clone, Debug, Default)]
pub(crate) struct TestRunContext {
    pub(crate) canceled: Arc<AtomicBool>,
    pub(crate) checks: Arc<AtomicUsize>,
}

impl RunContext for TestRunContext {
    fn name(&self) -> &str {
        "callback-test"
    }

    async fn is_canceled(&self) -> bool {
        self.checks.fetch_add(1, Ordering::SeqCst);
        self.canceled.load(Ordering::SeqCst)
    }
}

// Deliberately neither Send nor Sync. Formatting is observable before polling.
pub(crate) struct NonSendDisplay(pub(crate) Rc<Cell<usize>>);

impl Display for NonSendDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.set(self.0.get() + 1);
        f.write_str("formatted progress")
    }
}

pub(crate) async fn persisted_document(ctx: &TrustifyContext, data: &[u8]) -> anyhow::Result<Uuid> {
    let digest = Id::sha256(&Digests::digest(data).sha256).value();
    let document = source_document::Entity::find()
        .filter(source_document::Column::Sha256.eq(digest))
        .one(&ctx.db)
        .await?
        .expect("callback must persist its source document");
    let content = ctx
        .storage
        .retrieve(StorageKey::from_sha256(&document.sha256))
        .await?
        .expect("callback must persist its document bytes");
    let chunks = content.try_collect::<Vec<_>>().await?;
    let mut stored = Vec::with_capacity(data.len());
    for chunk in chunks {
        stored.extend_from_slice(&chunk);
    }
    assert_eq!(stored, data);
    Ok(document.id)
}

pub(crate) async fn assert_not_persisted(ctx: &TrustifyContext, data: &[u8]) -> anyhow::Result<()> {
    let digest = Id::sha256(&Digests::digest(data).sha256).value();
    assert!(
        source_document::Entity::find()
            .filter(source_document::Column::Sha256.eq(digest))
            .one(&ctx.db)
            .await?
            .is_none(),
        "callback must not persist the attempted source document"
    );
    Ok(())
}

pub(crate) fn assert_message(
    report: &Report,
    phase: Phase,
    file: &str,
    severity: Severity,
    text: &str,
) {
    let messages = &report.messages[&phase][file];
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].severity, severity);
    assert!(messages[0].message.contains(text), "{:?}", messages[0]);
}

pub(crate) fn configuration() -> ImporterConfiguration {
    serde_json::from_value(serde_json::json!({
        "sbom": {
            "source": "https://example.test/sbom/",
            "period": "30s",
            "disabled": false
        }
    }))
    .expect("valid test importer configuration")
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn retained_heart_runs_non_send_work_locks_out_stale_importer_and_cancels_on_drop(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let db = ReadWrite::new(ctx.db.clone());
    let service = ImporterService::new(db.clone(), PaginationCache::for_test());
    let name = format!("heartbeat-test-{}", Uuid::new_v4());
    service.create(name.clone(), configuration()).await?;

    let result = timeout(
        Duration::from_secs(5),
        LocalSet::new().run_until(async {
            let original = service
                .read(&name)
                .await?
                .expect("test importer exists")
                .value;
            assert_eq!(original.heartbeat, None);
            let token = CancellationToken::new();
            let started = Rc::new(Cell::new(0));
            let completed = Rc::new(Cell::new(false));
            let work_started = started.clone();
            let work_completed = completed.clone();
            let work_token = token.clone();

            // Retain the actual Heart while deliberately non-Send work waits for cancellation.
            // work_completed is used after the await, keeping its Rc in the future state.
            let heart = Heart::new(
                original.clone(),
                db.clone(),
                async move {
                    work_started.set(work_started.get() + 1);
                    work_token.cancelled().await;
                    work_completed.set(true);
                },
                token.clone(),
            );
            while started.get() == 0 {
                assert!(heart.is_beating());
                sleep(Duration::from_millis(1)).await;
            }
            let locked = service
                .read(&name)
                .await?
                .expect("test importer exists")
                .value;
            assert!(locked.heartbeat.is_some());
            assert_ne!(locked.heartbeat, original.heartbeat);
            assert!(locked.is_running());
            assert!(heart.is_beating());
            assert!(!token.is_cancelled());
            assert!(!completed.get());

            // The original snapshot still has no heartbeat, so its optimistic lock must miss.
            let duplicate_started = Rc::new(Cell::new(0));
            let duplicate_work_started = duplicate_started.clone();
            let duplicate_token = CancellationToken::new();
            let duplicate_work_token = duplicate_token.clone();
            let duplicate = Heart::new(
                original,
                db.clone(),
                async move {
                    duplicate_work_started.set(duplicate_work_started.get() + 1);
                    duplicate_work_token.cancelled().await;
                    drop(duplicate_work_started);
                },
                duplicate_token.clone(),
            );
            while duplicate.is_beating() {
                sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(duplicate_started.get(), 0);
            assert_eq!(
                Rc::strong_count(&duplicate_started),
                1,
                "stale work was dropped"
            );
            assert_eq!(started.get(), 1);
            assert!(heart.is_beating());
            drop(duplicate);
            assert!(duplicate_token.is_cancelled());
            assert!(!token.is_cancelled());

            drop(heart);
            assert!(token.is_cancelled(), "dropping Heart must cancel its token");
            while !completed.get() {
                sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(started.get(), 1);
            Ok::<_, anyhow::Error>(())
        }),
    )
    .await;

    // Also remove our own row on an ordinary error or timeout; never touch other importers.
    assert!(service.delete(&name, None).await?);
    result??;
    Ok(())
}
