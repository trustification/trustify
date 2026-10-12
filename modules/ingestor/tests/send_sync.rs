#![recursion_limit = "512"]

use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, Iterable, PaginatorTrait,
    QueryFilter, QueryOrder, Select, TransactionTrait,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use test_context::test_context;
use test_log::test;
use trustify_common::db::chunk::owned_chunked;
use trustify_entity::{advisory, sbom, vulnerability};
use trustify_module_ingestor::{
    graph::vulnerability::{VulnerabilityInformation, creator::VulnerabilityCreator},
    service::{Cache, Format},
};
use trustify_test_context::{TrustifyContext, document_bytes};
use uuid::Uuid;

fn assert_send<T: Send>(future: T) -> T {
    future
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn ingest_futures_are_send_with_borrowed_transactions(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    for (format, path) in [
        (Format::CSAF, "csaf/cve-2023-0044.json"),
        (Format::CVE, "cve/CVE-2021-32714.json"),
        (Format::OSV, "osv/RUSTSEC-2021-0079.json"),
        (Format::SPDX, "spdx/simple.json"),
        (Format::CycloneDX, "cyclonedx/simple_1dot6.json"),
    ] {
        let bytes = document_bytes(path).await?;
        let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let name = format!("send-regression-{}", Uuid::new_v4());
        match format {
            Format::CSAF => value["document"]["title"] = name.into(),
            Format::CVE => value["containers"]["cna"]["title"] = name.into(),
            Format::OSV => value["summary"] = name.into(),
            Format::SPDX => value["name"] = name.into(),
            Format::CycloneDX => value["metadata"]["component"]["name"] = name.into(),
            _ => unreachable!("only the listed formats are tested"),
        }
        let bytes = serde_json::to_vec(&value)?;
        let tx = ctx.db.begin().await?;

        // Check the real service/dispatcher future, without requiring 'static or spawning it.
        let result = assert_send(ctx.ingestor.ingest(
            &bytes,
            format,
            ("source", "send-regression"),
            None,
            Cache::Skip,
            &tx,
        ))
        .await?;
        assert!(!result.duplicate, "{path} should be newly ingested");
        let id = Uuid::parse_str(&result.id)?;
        assert_document_present(&tx, format, id, true).await?;
        assert_document_present(&ctx.db, format, id, false).await?;

        tx.rollback().await?;
        assert_document_present(&ctx.db, format, id, false).await?;
    }

    Ok(())
}

async fn assert_document_present(
    connection: &impl ConnectionTrait,
    format: Format,
    id: Uuid,
    present: bool,
) -> Result<(), DbErr> {
    let count = if matches!(format, Format::SPDX | Format::CycloneDX) {
        sbom::Entity::find_by_id(id).count(connection).await?
    } else {
        advisory::Entity::find_by_id(id).count(connection).await?
    };
    assert_eq!(count, u64::from(present), "{format} document visibility");
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn vulnerability_creator_multiple_batches_preserve_transactions(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let prefix = format!("SEND-SYNC-{}-", Uuid::new_v4());
    let columns = vulnerability::Column::iter().count();
    let batch_size = usize::from(u16::MAX - 128) / columns;
    // The creator leaves authoritative_advisory_id and generated id_sort_key NotSet.
    // Exceed even the hard limit for the remaining bound columns, so removing chunking
    // would fail. Currently this is 6,556 rows, split into batches of 5,450 and 1,106.
    let bound_columns = columns - 2;
    let item_count = usize::from(u16::MAX) / bound_columns + 3;
    assert!(item_count > batch_size);
    assert_eq!(regression_vulnerabilities(&prefix).count(&ctx.db).await?, 0);

    // Roll back actual multi-batch inserts, not just updates of existing rows.
    let tx = ctx.db.begin().await?;
    assert_send(vulnerability_creator(&prefix, item_count, None).create(&tx)).await?;
    assert_vulnerabilities(&tx, &prefix, item_count, None).await?;
    assert_eq!(regression_vulnerabilities(&prefix).count(&ctx.db).await?, 0);
    tx.rollback().await?;
    assert_eq!(regression_vulnerabilities(&prefix).count(&ctx.db).await?, 0);

    // The creator must leave committing to its caller, even after the last batch.
    let tx = ctx.db.begin().await?;
    assert_send(vulnerability_creator(&prefix, item_count, Some("committed")).create(&tx)).await?;
    assert_vulnerabilities(&tx, &prefix, item_count, Some("committed")).await?;
    assert_eq!(regression_vulnerabilities(&prefix).count(&ctx.db).await?, 0);
    tx.commit().await?;
    assert_vulnerabilities(&ctx.db, &prefix, item_count, Some("committed")).await?;

    // Exercise both ON CONFLICT paths across batches: empty data must not overwrite,
    // while supplied data must update. Rolling back must preserve the committed data.
    let tx = ctx.db.begin().await?;
    assert_send(vulnerability_creator(&prefix, item_count, None).create(&tx)).await?;
    assert_vulnerabilities(&tx, &prefix, item_count, Some("committed")).await?;
    assert_send(vulnerability_creator(&prefix, item_count, Some("rolled back")).create(&tx))
        .await?;
    assert_vulnerabilities(&tx, &prefix, item_count, Some("rolled back")).await?;
    assert_vulnerabilities(&ctx.db, &prefix, item_count, Some("committed")).await?;
    tx.rollback().await?;
    assert_vulnerabilities(&ctx.db, &prefix, item_count, Some("committed")).await?;

    // Remove only this invocation's committed rows, including on a shared test database.
    let deleted = vulnerability::Entity::delete_many()
        .filter(vulnerability::Column::Id.starts_with(&prefix))
        .exec(&ctx.db)
        .await?;
    assert_eq!(deleted.rows_affected, item_count as u64);
    assert_eq!(regression_vulnerabilities(&prefix).count(&ctx.db).await?, 0);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn owned_batches_later_constraint_error_rolls_back_earlier_inserts(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let prefix = format!("SEND-SYNC-FAIL-{}-", Uuid::new_v4());
    let batch_size = usize::from(u16::MAX - 128) / vulnerability::Column::iter().count();
    let missing_advisory = Uuid::new_v4();
    let completed = AtomicUsize::new(0);
    let models = (0..batch_size + 1).map(|index| vulnerability::ActiveModel {
        id: Set(vulnerability_id(&prefix, index)),
        // Only the last batch violates the authoritative-advisory foreign key.
        authoritative_advisory_id: Set((index == batch_size).then_some(missing_advisory)),
        ..Default::default()
    });
    let result = assert_send(ctx.db.transaction(async |tx| {
        for batch in owned_chunked(models) {
            vulnerability::Entity::insert_many(batch)
                .exec_without_returning(tx)
                .await?;
            completed.fetch_add(1, Ordering::SeqCst);
        }
        Ok::<_, DbErr>(())
    }))
    .await;
    assert_eq!(completed.load(Ordering::SeqCst), 1);
    let error = result.expect_err("the second batch must fail");
    assert!(error.to_string().contains("foreign key"), "{error}");
    assert_eq!(regression_vulnerabilities(&prefix).count(&ctx.db).await?, 0);
    Ok(())
}

fn vulnerability_id(prefix: &str, index: usize) -> String {
    format!("{prefix}{index:06}")
}

fn vulnerability_creator(
    prefix: &str,
    item_count: usize,
    title: Option<&str>,
) -> VulnerabilityCreator {
    let mut creator = VulnerabilityCreator::new();
    // Reverse input order and duplicate every key to exercise creator ordering/deduplication.
    for index in (0..item_count).rev() {
        let id = vulnerability_id(prefix, index);
        creator.add(&id, ());
        if let Some(title) = title {
            creator.add(
                &id,
                VulnerabilityInformation {
                    title: Some("superseded".to_owned()),
                    ..Default::default()
                },
            );
            creator.add(
                &id,
                VulnerabilityInformation {
                    title: Some(format!("{title} {index}")),
                    ..Default::default()
                },
            );
        }
        // A later empty entry must not discard accumulated information.
        creator.add(id, ());
    }
    creator
}

fn regression_vulnerabilities(prefix: &str) -> Select<vulnerability::Entity> {
    vulnerability::Entity::find().filter(vulnerability::Column::Id.starts_with(prefix))
}

async fn assert_vulnerabilities(
    connection: &impl ConnectionTrait,
    prefix: &str,
    item_count: usize,
    title: Option<&str>,
) -> Result<(), DbErr> {
    // SQL tables have no implicit order; compare an explicitly ordered result, including
    // every identifier/title on both sides of the batch boundary.
    let rows = regression_vulnerabilities(prefix)
        .order_by_asc(vulnerability::Column::Id)
        .all(connection)
        .await?;
    assert_eq!(rows.len(), item_count);
    for (index, row) in rows.into_iter().enumerate() {
        assert_eq!(row.id, vulnerability_id(prefix, index));
        assert_eq!(row.title, title.map(|title| format!("{title} {index}")));
    }
    Ok(())
}
