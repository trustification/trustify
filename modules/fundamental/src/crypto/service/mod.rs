pub mod conforma;
pub mod evaluator;
pub mod policy;

use crate::{
    Error,
    crypto::{
        model::{
            AlgorithmPolicyResult, CryptoAlgorithmSummary, CryptoSummary, PolicyEvaluationResponse,
            PolicySummaryResult,
        },
        service::policy::PolicyVerdict,
    },
};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, Condition, ConnectionTrait, EntityTrait, JoinType,
    LoaderTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, RelationTrait,
};
use std::collections::{HashMap, HashSet};
use tracing::instrument;
use trustify_common::{
    db::{
        limiter::{LimitedResult, LimiterTrait},
        pagination_cache::PaginationCache,
        query::{Columns, Filtering, Query},
    },
    model::{PaginatedResults, Pagination},
};
use trustify_entity::{
    package_relates_to_package, relationship::Relationship, sbom_crypto,
    sbom_crypto::{CryptoAssetType, PolicyVerdictDb},
    sbom_node,
};
use uuid::Uuid;

fn most_severe_verdict(
    a: Option<PolicyVerdictDb>,
    b: Option<PolicyVerdictDb>,
) -> Option<PolicyVerdictDb> {
    match (a, b) {
        (_, Some(PolicyVerdictDb::NonCompliant)) | (Some(PolicyVerdictDb::NonCompliant), _) => {
            Some(PolicyVerdictDb::NonCompliant)
        }
        (_, Some(PolicyVerdictDb::Warning)) | (Some(PolicyVerdictDb::Warning), _) => {
            Some(PolicyVerdictDb::Warning)
        }
        (_, Some(PolicyVerdictDb::Compliant)) | (Some(PolicyVerdictDb::Compliant), _) => {
            Some(PolicyVerdictDb::Compliant)
        }
        _ => None,
    }
}

fn db_to_policy_verdict(v: PolicyVerdictDb) -> PolicyVerdict {
    match v {
        PolicyVerdictDb::Compliant => PolicyVerdict::Compliant,
        PolicyVerdictDb::Warning => PolicyVerdict::Warning,
        PolicyVerdictDb::NonCompliant => PolicyVerdict::NonCompliant,
    }
}

fn policy_to_db_verdict(v: PolicyVerdict) -> PolicyVerdictDb {
    match v {
        PolicyVerdict::Compliant => PolicyVerdictDb::Compliant,
        PolicyVerdict::Warning => PolicyVerdictDb::Warning,
        PolicyVerdict::NonCompliant => PolicyVerdictDb::NonCompliant,
    }
}

pub struct CryptoService {
    cache: PaginationCache,
    evaluator: Option<Box<dyn evaluator::PolicyEvaluator>>,
}

impl CryptoService {
    pub fn new(cache: PaginationCache, conforma_url: Option<String>) -> Self {
        Self {
            cache,
            evaluator: conforma_url
                .map(conforma::ConformaClient::new)
                .map(|c| Box::new(c) as Box<dyn evaluator::PolicyEvaluator>),
        }
    }

    pub fn has_evaluator(&self) -> bool {
        self.evaluator.is_some()
    }

    #[cfg(test)]
    pub fn with_evaluator(
        cache: PaginationCache,
        evaluator: Box<dyn evaluator::PolicyEvaluator>,
    ) -> Self {
        Self {
            cache,
            evaluator: Some(evaluator),
        }
    }

    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn list_algorithms<C: ConnectionTrait>(
        &self,
        query: Query,
        paginated: impl Pagination,
        asset_type: Option<CryptoAssetType>,
        sbom_id: Option<Uuid>,
        connection: &C,
    ) -> Result<PaginatedResults<CryptoAlgorithmSummary>, Error> {
        let mut select = sbom_crypto::Entity::find()
            .join(JoinType::InnerJoin, sbom_node::Relation::Crypto.def().rev());

        if let Some(at) = asset_type {
            select = select.filter(sbom_crypto::Column::AssetType.eq(at));
        }

        if let Some(id) = sbom_id {
            // Per-SBOM view: show all rows for this SBOM (no deduplication).
            select = select.filter(sbom_crypto::Column::SbomId.eq(id));

            let limiter = select
                .filtering_with(
                    query,
                    Columns::from_entity::<sbom_crypto::Entity>()
                        .add_columns(Columns::from_entity::<sbom_node::Entity>()),
                )?
                .order_by_asc(sbom_node::Column::Name)
                .order_by_asc(sbom_crypto::Column::AssetType)
                .limiting(connection, paginated, &self.cache)?;

            let LimitedResult { items, total } = limiter.fetch().await?;
            let total = total.requested(paginated.total()).await?;
            return self.build_summaries(items, total, connection).await;
        }

        // Global view: fetch all matching rows, deduplicate by (name, asset_type) in memory,
        // then apply pagination. This ensures each algorithm appears exactly once regardless
        // of how many SBOMs contain it.
        let all_items = select
            .filtering_with(
                query,
                Columns::from_entity::<sbom_crypto::Entity>()
                    .add_columns(Columns::from_entity::<sbom_node::Entity>()),
            )?
            .order_by_asc(sbom_node::Column::Name)
            .order_by_asc(sbom_crypto::Column::AssetType)
            .order_by_asc(sbom_crypto::Column::SbomId)
            .all(connection)
            .await?;

        let all_nodes = all_items.load_one(sbom_node::Entity, connection).await?;
        let pkg_counts = self.batch_packages_count(&all_items, connection).await?;

        let all_names: Vec<String> = all_items
            .iter()
            .zip(&all_nodes)
            .filter_map(|(_, n)| n.as_ref().map(|n| n.name.clone()))
            .collect();
        let sbom_counts = self.batch_sboms_count(&all_names, connection).await?;

        // Deduplicate: OID is the canonical identity for an algorithm — different SBOMs may spell
        // the same algorithm differently ("AES", "AES-256-XT", "AES128") but share an OID.
        // Use (oid, asset_type) as the key when an OID is present, fall back to (name, asset_type).
        //
        // First pass: aggregate packages_count (sum) and policy_verdict (most-severe) per identity
        // so that the deduplicated entry reflects data from all SBOMs, not just the first row.
        let mut agg: HashMap<(String, String), (i64, Option<PolicyVerdictDb>)> = HashMap::new();
        for (crypto, node_opt) in all_items.iter().zip(all_nodes.iter()) {
            let Some(node) = node_opt.as_ref() else {
                continue;
            };
            let identity = crypto.oid.clone().unwrap_or_else(|| node.name.clone());
            let key = (identity, crypto.asset_type.to_string());
            let pc = pkg_counts
                .get(&(crypto.sbom_id, crypto.node_id.clone()))
                .copied()
                .unwrap_or(0);
            let entry = agg.entry(key).or_insert((0, None));
            entry.0 += pc;
            entry.1 = most_severe_verdict(entry.1, crypto.policy_verdict);
        }

        // Second pass: emit one entry per identity using aggregated values.
        let mut seen: HashSet<(String, String)> = HashSet::new();
        let unique: Vec<CryptoAlgorithmSummary> = all_items
            .into_iter()
            .zip(all_nodes)
            .filter_map(|(crypto, node)| {
                let node = node?;
                let identity = crypto
                    .oid
                    .clone()
                    .unwrap_or_else(|| node.name.clone());
                let key = (identity, crypto.asset_type.to_string());
                if !seen.insert(key.clone()) {
                    return None;
                }
                let (agg_pc, agg_verdict) = agg.remove(&key).unwrap_or_default();
                let primitive = crypto
                    .properties
                    .get("algorithmProperties")
                    .and_then(|ap| ap.get("primitive"))
                    .and_then(|p| p.as_str())
                    .map(String::from);
                let sc = sbom_counts.get(&node.name).copied().unwrap_or(0);
                let policy_status = agg_verdict.map(db_to_policy_verdict);
                Some(CryptoAlgorithmSummary {
                    sbom_id: crypto.sbom_id,
                    node_id: crypto.node_id,
                    name: node.name,
                    asset_type: crypto.asset_type,
                    oid: crypto.oid,
                    primitive,
                    properties: crypto.properties,
                    policy_status,
                    packages_count: agg_pc,
                    sboms_count: sc,
                })
            })
            .collect();

        Ok(paginated.paginate_array(&unique))
    }

    async fn build_summaries<C: ConnectionTrait>(
        &self,
        items: Vec<sbom_crypto::Model>,
        total: Option<u64>,
        connection: &C,
    ) -> Result<PaginatedResults<CryptoAlgorithmSummary>, Error> {
        let nodes = items.load_one(sbom_node::Entity, connection).await?;
        let pkg_counts = self.batch_packages_count(&items, connection).await?;

        let names: Vec<String> = items
            .iter()
            .zip(&nodes)
            .filter_map(|(_, n)| n.as_ref().map(|n| n.name.clone()))
            .collect();
        let sbom_counts = self.batch_sboms_count(&names, connection).await?;

        let algorithms = items
            .into_iter()
            .zip(nodes)
            .filter_map(|(crypto, node)| {
                let node = node?;
                let primitive = crypto
                    .properties
                    .get("algorithmProperties")
                    .and_then(|ap| ap.get("primitive"))
                    .and_then(|p| p.as_str())
                    .map(String::from);
                let pc = pkg_counts
                    .get(&(crypto.sbom_id, crypto.node_id.clone()))
                    .copied()
                    .unwrap_or(0);
                let sc = sbom_counts.get(&node.name).copied().unwrap_or(0);
                let policy_status = crypto.policy_verdict.map(db_to_policy_verdict);
                Some(CryptoAlgorithmSummary {
                    sbom_id: crypto.sbom_id,
                    node_id: crypto.node_id,
                    name: node.name,
                    asset_type: crypto.asset_type,
                    oid: crypto.oid,
                    primitive,
                    properties: crypto.properties,
                    policy_status,
                    packages_count: pc,
                    sboms_count: sc,
                })
            })
            .collect();

        Ok(PaginatedResults {
            items: algorithms,
            total,
        })
    }

    /// Aggregate stored policy verdicts from the DB, counting each distinct algorithm once.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn fetch_policy_summary<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<PolicySummaryResult, Error> {
        // Fetch (name, oid, policy_verdict) for all algorithm rows.
        let rows: Vec<(String, Option<String>, Option<PolicyVerdictDb>)> =
            sbom_crypto::Entity::find()
                .join(JoinType::InnerJoin, sbom_node::Relation::Crypto.def().rev())
                .filter(sbom_crypto::Column::AssetType.eq(CryptoAssetType::Algorithm))
                .select_only()
                .column(sbom_node::Column::Name)
                .column(sbom_crypto::Column::Oid)
                .column(sbom_crypto::Column::PolicyVerdict)
                .into_tuple()
                .all(connection)
                .await?;

        // Deduplicate by OID (canonical) or name (fallback): keep the most severe verdict.
        let mut by_identity: HashMap<String, Option<PolicyVerdictDb>> = HashMap::new();
        for (name, oid, verdict) in rows {
            let identity = oid.unwrap_or(name);
            by_identity
                .entry(identity)
                .and_modify(|existing| {
                    *existing = most_severe_verdict(*existing, verdict);
                })
                .or_insert(verdict);
        }

        let (total, compliant, warning, non_compliant) =
            by_identity
                .values()
                .fold((0, 0, 0, 0), |(t, c, w, n), verdict| {
                    match verdict {
                        Some(PolicyVerdictDb::Compliant) => (t + 1, c + 1, w, n),
                        Some(PolicyVerdictDb::Warning) => (t + 1, c, w + 1, n),
                        Some(PolicyVerdictDb::NonCompliant) => (t + 1, c, w, n + 1),
                        None => (t + 1, c, w, n),
                    }
                });

        Ok(PolicySummaryResult {
            total,
            compliant,
            warning,
            non_compliant,
        })
    }

    /// Compute aggregate KPI metrics across all SBOMs.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn fetch_summary<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<CryptoSummary, Error> {
        let total_algorithms = sbom_crypto::Entity::find()
            .filter(sbom_crypto::Column::AssetType.eq(CryptoAssetType::Algorithm))
            .count(connection)
            .await? as i64;

        Ok(CryptoSummary { total_algorithms })
    }

    async fn batch_packages_count<C: ConnectionTrait>(
        &self,
        items: &[sbom_crypto::Model],
        connection: &C,
    ) -> Result<HashMap<(Uuid, String), i64>, Error> {
        if items.is_empty() {
            return Ok(HashMap::new());
        }

        let mut condition = Condition::any();
        for item in items {
            condition = condition.add(
                Condition::all()
                    .add(package_relates_to_package::Column::SbomId.eq(item.sbom_id))
                    .add(package_relates_to_package::Column::RightNodeId.eq(item.node_id.clone())),
            );
        }

        let rows: Vec<(Uuid, String, i64)> = package_relates_to_package::Entity::find()
            .select_only()
            .column(package_relates_to_package::Column::SbomId)
            .column(package_relates_to_package::Column::RightNodeId)
            .column_as(
                package_relates_to_package::Column::LeftNodeId.count(),
                "packages_count",
            )
            .filter(condition)
            .filter(package_relates_to_package::Column::Relationship.eq(Relationship::Generates))
            .group_by(package_relates_to_package::Column::SbomId)
            .group_by(package_relates_to_package::Column::RightNodeId)
            .into_tuple()
            .all(connection)
            .await?;

        Ok(rows
            .into_iter()
            .map(|(sbom_id, node_id, count)| ((sbom_id, node_id), count))
            .collect())
    }

    async fn batch_sboms_count<C: ConnectionTrait>(
        &self,
        names: &[String],
        connection: &C,
    ) -> Result<HashMap<String, i64>, Error> {
        if names.is_empty() {
            return Ok(HashMap::new());
        }

        let unique_names: Vec<&str> = names
            .iter()
            .map(|s| s.as_str())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let rows: Vec<(Uuid, String)> = sbom_crypto::Entity::find()
            .join(JoinType::InnerJoin, sbom_node::Relation::Crypto.def().rev())
            .select_only()
            .column(sbom_crypto::Column::SbomId)
            .column(sbom_node::Column::Name)
            .filter(sbom_node::Column::Name.is_in(unique_names))
            .into_tuple()
            .all(connection)
            .await?;

        let mut counts: HashMap<String, HashSet<Uuid>> = HashMap::new();
        for (sbom_id, name) in rows {
            counts.entry(name).or_default().insert(sbom_id);
        }

        Ok(counts
            .into_iter()
            .map(|(name, ids)| (name, ids.len() as i64))
            .collect())
    }

    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn evaluate_policy<C: ConnectionTrait>(
        &self,
        sbom_id: Option<Uuid>,
        connection: &C,
    ) -> Result<PolicyEvaluationResponse, Error> {
        let policy_evaluator = self
            .evaluator
            .as_ref()
            .ok_or_else(|| Error::Internal("CONFORMA_URL is not configured".into()))?;

        let mut query = sbom_crypto::Entity::find()
            .filter(sbom_crypto::Column::AssetType.eq(CryptoAssetType::Algorithm));

        if let Some(id) = sbom_id {
            query = query.filter(sbom_crypto::Column::SbomId.eq(id));
        }

        let items = query.all(connection).await?;
        let nodes = items.load_one(sbom_node::Entity, connection).await?;

        let algo_input: Vec<evaluator::AlgorithmInput> = items
            .iter()
            .zip(nodes.iter())
            .filter_map(|(crypto, node)| {
                let node = node.as_ref()?;
                Some(evaluator::AlgorithmInput {
                    node_id: crypto.node_id.clone(),
                    sbom_id: crypto.sbom_id,
                    name: node.name.clone(),
                    oid: crypto.oid.clone(),
                    properties: crypto.properties.clone(),
                })
            })
            .collect();

        let report = policy_evaluator.evaluate(&algo_input).await?;

        let violation_ids: HashSet<&str> = report
            .violations
            .iter()
            .filter_map(|v| v.node_id.as_deref())
            .collect();

        let warning_ids: HashSet<&str> = report
            .warnings
            .iter()
            .filter_map(|w| w.node_id.as_deref())
            .collect();

        let results: Vec<AlgorithmPolicyResult> = items
            .into_iter()
            .zip(nodes)
            .filter_map(|(crypto, node)| {
                let node = node?;
                let verdict = if violation_ids.contains(crypto.node_id.as_str()) {
                    PolicyVerdict::NonCompliant
                } else if warning_ids.contains(crypto.node_id.as_str()) {
                    PolicyVerdict::Warning
                } else {
                    PolicyVerdict::Compliant
                };
                Some(AlgorithmPolicyResult {
                    sbom_id: crypto.sbom_id,
                    node_id: crypto.node_id,
                    name: node.name,
                    oid: crypto.oid,
                    verdict,
                    properties: crypto.properties,
                })
            })
            .collect();

        for result in &results {
            let active: sbom_crypto::ActiveModel = sbom_crypto::ActiveModel {
                sbom_id: ActiveValue::Unchanged(result.sbom_id),
                node_id: ActiveValue::Unchanged(result.node_id.clone()),
                policy_verdict: ActiveValue::Set(Some(policy_to_db_verdict(result.verdict))),
                ..Default::default()
            };
            active.update(connection).await.map_err(|e| {
                Error::Internal(format!("failed to persist policy verdict: {e}"))
            })?;
        }

        let summary = PolicySummaryResult {
            total: results.len(),
            compliant: results
                .iter()
                .filter(|r| r.verdict == PolicyVerdict::Compliant)
                .count(),
            warning: results
                .iter()
                .filter(|r| r.verdict == PolicyVerdict::Warning)
                .count(),
            non_compliant: results
                .iter()
                .filter(|r| r.verdict == PolicyVerdict::NonCompliant)
                .count(),
        };

        Ok(PolicyEvaluationResponse { summary, results })
    }
}
