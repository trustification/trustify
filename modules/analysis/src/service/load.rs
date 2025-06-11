use crate::{
    Error,
    model::{PackageGraph, graph},
    service::{
        AnalysisService, ComponentReference, GraphQuery, InnerService, resolve_external_sbom,
    },
};
use ::cpe::{
    component::Component,
    cpe::{Cpe, CpeType, Language},
    uri::OwnedUri,
};
use anyhow::anyhow;
use futures::FutureExt;
use opentelemetry::KeyValue;
use petgraph::{Graph, prelude::NodeIndex};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DbErr, EntityOrSelect, EntityTrait,
    FromQueryResult, QueryFilter, QuerySelect, QueryTrait, Related, RelationTrait, Select,
    Statement,
};
use sea_query::{Alias, Expr, JoinType, PostgresQueryBuilder, Query, SelectStatement};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    fmt::Debug,
    str::FromStr,
    sync::Arc,
};
use tokio::sync::oneshot;
use tracing::{Level, instrument};
use trustify_common::{
    cpe::Cpe as TrustifyCpe,
    db::query::{Columns, Filtering, IntoColumns},
    purl::Purl,
};
use trustify_entity::{
    cpe::{self, CpeDto},
    package_relates_to_package,
    qualified_purl::{self, CanonicalPurl},
    relationship::Relationship,
    sbom, sbom_external_node,
    sbom_external_node::ExternalType,
    sbom_node, sbom_package, sbom_package_cpe_ref, sbom_package_purl_ref,
};
use uuid::Uuid;

/// A query result struct for fetching all node types
#[derive(Debug, FromQueryResult)]
pub struct Node {
    pub sbom_id: Uuid,
    pub document_id: Option<String>,
    pub published: String,

    pub node_id: String,
    pub node_name: String,

    pub package_node_id: Option<String>,
    pub package_version: Option<String>,
    pub purls: Option<Vec<Value>>,
    pub cpes: Option<Vec<Value>>,

    pub ext_node_id: Option<String>,
    pub ext_external_document_ref: Option<String>,
    pub ext_external_node_id: Option<String>,
    pub ext_external_type: Option<ExternalType>,

    pub product_name: Option<String>,
    pub product_version: Option<String>,
}

impl From<Node> for graph::Node {
    fn from(value: Node) -> Self {
        let base = graph::BaseNode {
            sbom_id: value.sbom_id.to_string(),
            node_id: value.node_id,
            published: value.published.clone(),
            name: value.node_name,
            document_id: value.document_id.clone().unwrap_or_default(),
            product_name: value.product_name.clone().unwrap_or_default(),
            product_version: value.product_version.clone().unwrap_or_default(),
        };

        match (value.package_node_id, value.ext_node_id) {
            (Some(_), _) => graph::Node::Package(graph::PackageNode {
                base,
                purl: to_purls(value.purls),
                cpe: to_cpes(value.cpes),
                version: value.package_version.clone().unwrap_or_default(),
            }),
            (_, Some(_)) => graph::Node::External(graph::ExternalNode {
                base,
                external_document_reference: value.ext_external_document_ref.unwrap_or_default(),
                external_node_id: value.ext_external_node_id.unwrap_or_default(),
            }),
            _ => graph::Node::Unknown(base),
        }
    }
}

#[derive(Debug, FromQueryResult)]
pub struct Edge {
    pub left_node_id: String,
    pub relationship: Relationship,
    pub right_node_id: String,
}

#[instrument(skip(connection))]
pub async fn get_nodes<C: ConnectionTrait>(
    connection: &C,
    distinct_sbom_id: Uuid,
) -> Result<Vec<Node>, DbErr> {
    let sql = r#"
WITH
purl_ref AS (
    SELECT
        sbom_id,
        node_id,
        array_agg(qualified_purl.purl) AS purls
    FROM
        sbom_package_purl_ref
    LEFT JOIN
        qualified_purl ON (sbom_package_purl_ref.qualified_purl_id = qualified_purl.id)
    GROUP BY
        sbom_id,
        node_id
),
cpe_ref AS (
    SELECT
        sbom_id,
        node_id,
        array_agg(row_to_json(cpe)) AS cpes
    FROM
        sbom_package_cpe_ref
    LEFT JOIN
        cpe ON (sbom_package_cpe_ref.cpe_id = cpe.id)
    GROUP BY
        sbom_id,
        node_id
)
SELECT
    sbom.sbom_id,
    sbom.document_id,
    sbom.published::text,

    t1_node.node_id AS node_id,
    t1_node.name AS node_name,

    t1_package.node_id AS package_node_id,
    t1_package.version AS package_version,
    purl_ref.purls,
    cpe_ref.cpes,

    t1_ext_node.node_id AS ext_node_id,
    t1_ext_node.external_doc_ref AS ext_external_document_ref,
    t1_ext_node.external_node_ref AS ext_external_node_id,
    t1_ext_node.external_type AS ext_external_type,

    product.name AS product_name,
    product_version.version AS product_version
FROM
    sbom
LEFT JOIN
    product_version ON sbom.sbom_id = product_version.sbom_id
LEFT JOIN
    product ON product_version.product_id = product.id
LEFT JOIN
    sbom_node t1_node ON sbom.sbom_id = t1_node.sbom_id
LEFT JOIN
    sbom_package t1_package ON t1_node.sbom_id = t1_package.sbom_id AND t1_node.node_id = t1_package.node_id
LEFT JOIN
    purl_ref ON purl_ref.sbom_id = sbom.sbom_id AND purl_ref.node_id = t1_node.node_id
LEFT JOIN
    cpe_ref ON cpe_ref.sbom_id = sbom.sbom_id AND cpe_ref.node_id = t1_node.node_id
LEFT JOIN
    sbom_external_node t1_ext_node ON t1_node.sbom_id = t1_ext_node.sbom_id AND t1_node.node_id = t1_ext_node.node_id
WHERE
    sbom.sbom_id = $1
"#;

    let stmt =
        Statement::from_sql_and_values(DatabaseBackend::Postgres, sql, [distinct_sbom_id.into()]);

    Node::find_by_statement(stmt).all(connection).await
}

#[instrument(skip(connection))]
pub async fn get_relationships<C: ConnectionTrait>(
    connection: &C,
    distinct_sbom_id: Uuid,
) -> Result<Vec<Edge>, DbErr> {
    Ok(package_relates_to_package::Entity::find()
        .filter(package_relates_to_package::Column::SbomId.eq(distinct_sbom_id))
        .all(connection)
        .await?
        .into_iter()
        .map(|prtp| Edge {
            left_node_id: prtp.left_node_id,
            relationship: prtp.relationship,
            right_node_id: prtp.right_node_id,
        })
        .collect())
}

fn to_purls(purls: Option<Vec<Value>>) -> Vec<Purl> {
    purls
        .into_iter()
        .flatten()
        .filter_map(|purl| {
            serde_json::from_value::<CanonicalPurl>(purl)
                .ok()
                .map(Purl::from)
        })
        .collect()
}

fn to_cpes(cpes: Option<Vec<Value>>) -> Vec<TrustifyCpe> {
    cpes.into_iter()
        .flatten()
        .flat_map(|cpe| {
            serde_json::from_value::<CpeDto>(cpe)
                .ok()
                .and_then(|cpe| TrustifyCpe::try_from(cpe).ok())
        })
        .collect()
}

impl AnalysisService {
    /// Load the SBOM matching the provided ID
    ///
    /// Compared to the plural version [`self.load_all_graphs`], it does not resolve external
    /// references and only loads this single SBOM.
    #[instrument(skip(self, connection))]
    pub async fn load_graph<C: ConnectionTrait>(
        &self,
        connection: &C,
        distinct_sbom_id: &str,
    ) -> Result<Arc<PackageGraph>, Error> {
        self.inner.load_graph(connection, distinct_sbom_id).await
    }

    /// Load all SBOMs by the provided IDs
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn load_graphs<C: ConnectionTrait>(
        &self,
        connection: &C,
        distinct_sbom_ids: &[impl AsRef<str> + Debug],
    ) -> Result<Vec<(String, Arc<PackageGraph>)>, Error> {
        self.inner.load_graphs(connection, distinct_sbom_ids).await
    }
}

impl InnerService {
    /// Take a [`GraphQuery`] and load all required SBOMs
    #[instrument(skip(self, connection), err(level=Level::INFO))]
    pub(crate) async fn load_graphs_query<C: ConnectionTrait>(
        &self,
        connection: &C,
        query: GraphQuery<'_>,
    ) -> Result<Vec<(String, Arc<PackageGraph>)>, Error> {
        let search_sbom_subquery = match query {
            GraphQuery::Component(ComponentReference::Id(name)) => sbom_node::Entity::find()
                .filter(sbom_node::Column::NodeId.eq(name))
                .select_only()
                .column(sbom_node::Column::SbomId)
                .distinct()
                .into_query(),
            GraphQuery::Component(ComponentReference::Name(name)) => sbom_node::Entity::find()
                .filter(sbom_node::Column::Name.eq(name))
                .select_only()
                .column(sbom::Column::SbomId)
                .distinct()
                .into_query(),
            GraphQuery::Component(ComponentReference::Purl(purl)) => sbom_node::Entity::find()
                .join(JoinType::Join, sbom_node::Relation::Package.def())
                .join(JoinType::Join, sbom_package::Relation::Purl.def())
                .filter(sbom_package_purl_ref::Column::QualifiedPurlId.eq(purl.qualifier_uuid()))
                .select_only()
                .distinct()
                .column(sbom_node::Column::SbomId)
                .into_query(),
            GraphQuery::Component(ComponentReference::Cpe(cpe)) => sbom_node::Entity::find()
                .join(JoinType::Join, sbom_node::Relation::Package.def())
                .join(JoinType::Join, sbom_package::Relation::Cpe.def())
                .filter(sbom_package_cpe_ref::Column::CpeId.eq(cpe.uuid()))
                .select_only()
                .column(sbom_node::Column::SbomId)
                .distinct()
                .into_query(),
            GraphQuery::Query(query) => sbom_node::Entity::find()
                .join(JoinType::Join, sbom_node::Relation::Package.def())
                .join(JoinType::LeftJoin, sbom_package::Relation::Purl.def())
                .join(JoinType::LeftJoin, sbom_package::Relation::Cpe.def())
                .join(
                    JoinType::LeftJoin,
                    sbom_package_cpe_ref::Relation::Cpe.def(),
                )
                .join(
                    JoinType::LeftJoin,
                    sbom_package_purl_ref::Relation::Purl.def(),
                )
                .select_only()
                .column(sbom_node::Column::SbomId)
                .filtering_with(query.clone(), q_columns())?
                .distinct()
                .into_query(),
        };

        self.load_graphs_subquery(connection, search_sbom_subquery)
            .await
    }

    #[instrument(skip(self, connection), err(level=Level::INFO))]
    pub(crate) async fn load_latest_graphs_query<C: ConnectionTrait>(
        &self,
        connection: &C,
        query: GraphQuery<'_>,
    ) -> Result<Vec<(String, Arc<PackageGraph>)>, Error> {
        #[derive(Debug, FromQueryResult)]
        struct Row {
            sbom_id: Uuid,
        }

        fn find<E>() -> Select<E>
        where
            E: EntityTrait + Related<sbom::Entity>,
        {
            const RANK_SQL: &str = "RANK() OVER (PARTITION BY cpe.id ORDER BY sbom.published DESC)";

            E::find()
                .select_only()
                .column(sbom::Column::SbomId)
                .column(sbom::Column::Published)
                .column(cpe::Column::Id)
                .column_as(Expr::cust(RANK_SQL), "rank")
                .left_join(sbom::Entity)
        }

        async fn query_all<C>(
            subquery: SelectStatement,
            connection: &C,
        ) -> Result<Vec<String>, Error>
        where
            C: ConnectionTrait,
        {
            let select_query = Query::select()
                .expr(Expr::col(Alias::new("sbom_id")))
                .from_subquery(subquery, Alias::new("subquery"))
                .cond_where(Expr::col(Alias::new("rank")).eq(1))
                .distinct()
                .to_owned();
            let (sql, values) = select_query.build(PostgresQueryBuilder);

            let rows: Vec<Row> = Row::find_by_statement(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                sql,
                values,
            ))
            .all(connection)
            .await?;

            Ok(rows
                .into_iter()
                .map(|row| row.sbom_id.to_string())
                .collect())
        }

        let latest_sbom_ids: Vec<_> = match query {
            GraphQuery::Component(ComponentReference::Id(node_id)) => {
                let subquery = find::<sbom_node::Entity>()
                    .left_join(sbom_package::Entity)
                    .join(JoinType::LeftJoin, sbom_package::Relation::Cpe.def())
                    .join(
                        JoinType::LeftJoin,
                        sbom_package_cpe_ref::Relation::Cpe.def(),
                    )
                    .filter(sbom_node::Column::NodeId.eq(node_id));

                query_all(subquery.into_query(), connection).await?
            }
            GraphQuery::Component(ComponentReference::Name(name)) => {
                let subquery = find::<sbom_node::Entity>()
                    .left_join(sbom_package::Entity)
                    .join(JoinType::LeftJoin, sbom_package::Relation::Cpe.def())
                    .join(
                        JoinType::LeftJoin,
                        sbom_package_cpe_ref::Relation::Cpe.def(),
                    )
                    .filter(sbom_node::Column::Name.eq(name));

                query_all(subquery.into_query(), connection).await?
            }
            GraphQuery::Component(ComponentReference::Purl(purl)) => {
                let subquery = find::<sbom_package_purl_ref::Entity>()
                    .left_join(sbom_package::Entity)
                    .join(JoinType::LeftJoin, sbom_package::Relation::Cpe.def())
                    .join(
                        JoinType::LeftJoin,
                        sbom_package_cpe_ref::Relation::Cpe.def(),
                    )
                    .filter(
                        sbom_package_purl_ref::Column::QualifiedPurlId.eq(purl.qualifier_uuid()),
                    );

                query_all(subquery.into_query(), connection).await?
            }
            GraphQuery::Component(ComponentReference::Cpe(cpe)) => {
                let subquery = find::<sbom_package_cpe_ref::Entity>()
                    .join(
                        JoinType::LeftJoin,
                        sbom_package_cpe_ref::Relation::Cpe.def(),
                    )
                    .filter(sbom_package_cpe_ref::Column::CpeId.eq(cpe.uuid()));

                query_all(subquery.into_query(), connection).await?
            }
            GraphQuery::Query(query) => {
                let subquery = find::<sbom_node::Entity>()
                    .join(JoinType::Join, sbom_node::Relation::Package.def())
                    .join(JoinType::LeftJoin, sbom_package::Relation::Purl.def())
                    .join(JoinType::LeftJoin, sbom_package::Relation::Cpe.def())
                    .join(
                        JoinType::LeftJoin,
                        sbom_package_cpe_ref::Relation::Cpe.def(),
                    )
                    .join(
                        JoinType::LeftJoin,
                        sbom_package_purl_ref::Relation::Purl.def(),
                    )
                    .filtering_with(query.clone(), q_columns())?;

                query_all(subquery.into_query(), connection).await?
            }
        };

        self.load_graphs(connection, &latest_sbom_ids).await
    }

    /// Take a select for sboms, and ensure they are loaded and return their IDs.
    async fn load_graphs_subquery<C: ConnectionTrait>(
        &self,
        connection: &C,
        subquery: SelectStatement,
    ) -> Result<Vec<(String, Arc<PackageGraph>)>, Error> {
        let distinct_sbom_ids: Vec<String> = sbom::Entity::find()
            .filter(sbom::Column::SbomId.in_subquery(subquery))
            .select()
            .all(connection)
            .await?
            .into_iter()
            .map(|record| record.sbom_id.to_string()) // Assuming sbom_id is of type String
            .collect();

        self.load_graphs(connection, &distinct_sbom_ids).await
    }

    /// Load the SBOM matching the provided ID
    ///
    /// Compared to the plural version [`self.load_all_graphs`], it does not resolve external
    /// references and only loads this single SBOM.
    #[instrument(skip(self, connection))]
    pub async fn load_graph<C: ConnectionTrait>(
        &self,
        connection: &C,
        distinct_sbom_id: &str,
    ) -> Result<Arc<PackageGraph>, Error> {
        log::debug!("loading sbom: {:?}", distinct_sbom_id);

        if let Some(g) = self.graph_cache.get(distinct_sbom_id) {
            log::debug!("Cache hit");
            self.cache_hit.add(1, &[]);
            // early return if we already loaded it
            return Ok(g);
        }

        let distinct_sbom_id = Uuid::parse_str(distinct_sbom_id).map_err(|err| {
            Error::Database(anyhow!("Unable to parse SBOM ID {distinct_sbom_id}: {err}"))
        })?;

        // check if there is a loading operation pending

        let tx = {
            let mut lock = self.loading_ops.lock().await;

            match lock.entry(distinct_sbom_id) {
                Entry::Occupied(o) => {
                    log::debug!("Cache miss, but loading in progress");

                    self.cache_miss.add(1, &[KeyValue::new("type", "await")]);

                    let rx = o.get().clone();

                    // drop lock before awaiting
                    drop(lock);

                    // there is an operation in progress, await and return
                    return rx
                        .await
                        // error awaiting
                        .map_err(|_| Error::Internal("failed to await loading operation".into()))?
                        // error from performing the loading operation
                        .map_err(Error::Internal);
                }
                Entry::Vacant(v) => {
                    log::debug!("Cache miss, need to load");

                    self.cache_miss.add(1, &[KeyValue::new("type", "load")]);

                    // we are the first, create and insert a channel and perform the work
                    // we need to ensure: 1) we remove the entry from the map, 2) we send to the channel
                    let (tx, rx) = oneshot::channel();
                    v.insert(rx.shared());
                    tx
                }
            }
        };

        // full cache miss, perform the work

        let g = match Self::perform_load_graph(connection, distinct_sbom_id).await {
            Ok(g) => g,
            Err(err) => {
                // failed to load, remove and notify
                self.loading_ops.lock().await.remove(&distinct_sbom_id);
                let _ = tx.send(Err(err.to_string()));
                return Err(err);
            }
        };
        let g = Arc::new(g);

        self.graph_cache
            .insert(distinct_sbom_id.to_string(), g.clone());

        // remove the ops handle

        self.loading_ops.lock().await.remove(&distinct_sbom_id);

        // notify the waiting tasks

        let _ = tx.send(Ok(g.clone()));

        // done

        Ok(g)
    }

    /// Perform the actual loading operation, returning the graph, but not adding to the cache.
    #[instrument(skip(connection))]
    async fn perform_load_graph<C>(
        connection: &C,
        distinct_sbom_id: Uuid,
    ) -> Result<PackageGraph, Error>
    where
        C: ConnectionTrait,
    {
        // lazy load graphs

        let mut g: PackageGraph = Graph::new();
        let mut nodes = HashMap::new();
        let mut detected_nodes = HashSet::new();

        // populate packages/components

        let loaded_nodes = match get_nodes(connection, distinct_sbom_id).await {
            Ok(nodes) => nodes,
            Err(err) => {
                return Err(err.into());
            }
        };

        for node in loaded_nodes {
            detected_nodes.insert(node.node_id.clone());

            match nodes.entry(node.node_id.clone()) {
                Entry::Vacant(entry) => {
                    let index = g.add_node(node.into());

                    log::debug!("Inserting - id: {}, index: {index:?}", entry.key());

                    entry.insert(index);
                }
                Entry::Occupied(_) => {}
            }
        }

        // populate relationships

        let edges = match get_relationships(connection, distinct_sbom_id).await {
            Ok(edges) => edges,
            Err(err) => {
                return Err(err.into());
            }
        };

        // the nodes describing the document
        let mut describedby_node_id: HashSet<NodeIndex> = Default::default();

        for edge in edges {
            log::debug!("Adding edge {:?}", edge);

            // insert edge into the graph
            if let (Some(left), Some(right)) = (
                nodes.get(&edge.left_node_id),
                nodes.get(&edge.right_node_id),
            ) {
                if edge.relationship == Relationship::Describes {
                    describedby_node_id.insert(*left);
                }

                // remove all node IDs we somehow connected
                detected_nodes.remove(&edge.left_node_id);
                detected_nodes.remove(&edge.right_node_id);

                g.add_edge(*left, *right, edge.relationship);
            }
        }

        log::debug!("Describing nodes: {describedby_node_id:?}");
        log::debug!("Unconnected nodes: {detected_nodes:?}");

        if !describedby_node_id.is_empty() {
            // search of unconnected nodes and create undefined relationships
            // all nodes not removed are unconnected
            for id in detected_nodes {
                let Some(id) = nodes.get(&id) else { continue };
                // add "undefined" relationship
                for from in &describedby_node_id {
                    log::debug!("Creating undefined relationship - left: {from:?}, right: {id:?}");
                    g.add_edge(*from, *id, Relationship::Undefined);
                }
            }
        }

        Ok(g)
    }

    /// Load all SBOMs by the provided IDs
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn load_graphs<C: ConnectionTrait>(
        &self,
        connection: &C,
        distinct_sbom_ids: &[impl AsRef<str> + Debug],
    ) -> Result<Vec<(String, Arc<PackageGraph>)>, Error> {
        log::info!("loading {} SBOMs", distinct_sbom_ids.len());

        let mut results = Vec::new();
        for distinct_sbom_id in distinct_sbom_ids {
            let distinct_sbom_id = distinct_sbom_id.as_ref();
            // TODO: we need a better heuristic for loading external sboms
            let external_sboms = sbom_external_node::Entity::find().all(connection).await?;
            for external_sbom in &external_sboms {
                if !distinct_sbom_id.eq(&external_sbom.node_id.to_string()) {
                    let resolved_external_sbom =
                        resolve_external_sbom(external_sbom.node_id.to_string(), connection).await;
                    log::debug!("resolved external sbom: {:?}", resolved_external_sbom);
                    if let Some(resolved_external_sbom) = resolved_external_sbom {
                        let resolved_external_sbom_id = resolved_external_sbom.sbom_id;
                        results.push((
                            resolved_external_sbom_id.clone().to_string(),
                            self.load_graph(connection, &resolved_external_sbom_id.to_string())
                                .await?,
                        ));
                    } else {
                        log::debug!("Cannot find external sbom {:?}", external_sbom.node_id);
                        continue;
                    }
                }
            }
            log::debug!("loading sbom: {:?}", distinct_sbom_id);

            results.push((
                distinct_sbom_id.to_string(),
                self.load_graph(connection, distinct_sbom_id).await?,
            ));
        }
        Ok(results)
    }
}

// These are the columns and translation rules with which we filter
// 'q=' component queries
fn q_columns() -> Columns {
    sbom_node::Entity
        .columns()
        .add_columns(cpe::Entity.columns())
        .add_columns(qualified_purl::Entity.columns())
        .translator(|f, op, v| {
            match f {
                "purl:type" => Some(format!("purl:ty{op}{v}")),
                "purl" => Purl::translate(op, v),
                "cpe" => match (op, OwnedUri::from_str(v)) {
                    ("=" | "~", Ok(cpe)) => {
                        // We break out cpe into its constituent columns in CPE table
                        let q = match (cpe.part(), cpe.language()) {
                            (CpeType::Any, Language::Any) => String::new(),
                            (CpeType::Any, l) => format!("language={l}"),
                            (p, Language::Any) => format!("part={p}"),
                            (p, l) => format!("part={p}&language={l}"),
                        };
                        let q = [
                            ("vendor", cpe.vendor()),
                            ("product", cpe.product()),
                            ("version", cpe.version()),
                            ("update", cpe.update()),
                            ("edition", cpe.edition()),
                        ]
                        .iter()
                        .fold(q, |acc, (k, v)| match v {
                            Component::Value(s) => {
                                format!("{acc}&{k}={s}|*")
                            }
                            _ => acc,
                        });
                        Some(q)
                    }
                    ("~", Err(_)) => Some(v.into()),
                    (_, Err(e)) => Some(e.to_string()),
                    (_, _) => Some("illegal operation for cpe field".into()),
                },
                _ => None,
            }
        })
}
