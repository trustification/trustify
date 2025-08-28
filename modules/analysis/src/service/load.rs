use crate::{
    Error,
    model::{PackageGraph, graph},
    service::{
        AnalysisService, ComponentReference, GraphQuery, InnerService, LoadingOp,
        resolve_external_sbom,
    },
};
use ::cpe::{
    component::Component,
    cpe::{Cpe, CpeType, Language},
    uri::OwnedUri,
};
use actix_http::StatusCode;
use futures::FutureExt;
use opentelemetry::KeyValue;
use petgraph::{Graph, prelude::NodeIndex};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DbErr, EntityOrSelect, EntityTrait,
    FromQueryResult, QueryFilter, QuerySelect, QueryTrait, RelationTrait, Select, Statement,
};
use sea_query::{
    CommonTableExpression, Cond, Expr, IntoColumnRef, IntoCondition, JoinType, Order,
    PostgresQueryBuilder, SelectStatement, WithClause, WithQuery, all,
};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    fmt::Debug,
    str::FromStr,
    sync::Arc,
};
use time::OffsetDateTime;
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
    sbom_node, sbom_package, sbom_package_cpe_ref, sbom_package_purl_ref, versioned_purl,
};
use uuid::Uuid;

/// A query result struct for fetching all node types
#[derive(Debug, FromQueryResult)]
pub struct Node {
    pub sbom_id: Uuid,
    pub document_id: Option<String>,
    pub published: OffsetDateTime,

    pub node_id: String,
    pub node_name: String,

    pub package_node_id: Option<String>,
    pub package_version: Option<String>,
    pub purls: Option<Vec<Value>>,
    pub cpes: Option<Vec<Value>>,

    pub ext_node_id: Option<String>,
    pub ext_external_document_ref: Option<String>,
    pub ext_external_node_id: Option<String>,
    #[allow(unused)]
    pub ext_external_type: Option<ExternalType>,

    pub product_name: Option<String>,
    pub product_version: Option<String>,
}

#[derive(Debug, Default)]
struct Context {
    strings: HashMap<String, Arc<String>>,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn intern(&mut self, s: String) -> Arc<String> {
        if self.strings.contains_key(&s) {
            if let Some(s) = self.strings.get(&s) {
                return s.clone();
            }
        }

        let a = Arc::new(s.clone());
        self.strings.insert(s, a.clone());
        a
    }
}

impl Node {
    fn into_graph_node(self, ctx: &mut Context) -> graph::Node {
        let base = graph::BaseNode {
            sbom_id: self.sbom_id,
            node_id: self.node_id,
            published: self.published,
            name: self.node_name,
            document_id: self.document_id.map(|s| ctx.intern(s)),
            product_name: self.product_name.map(|s| ctx.intern(s)),
            product_version: self.product_version.map(|s| ctx.intern(s)),
        };

        match (self.package_node_id, self.ext_node_id) {
            (Some(_), _) => graph::Node::Package(graph::PackageNode {
                base,
                purl: to_purls(self.purls).into(),
                cpe: to_cpes(self.cpes).into(),
                version: self.package_version.clone().unwrap_or_default(),
            }),
            (_, Some(_)) => graph::Node::External(graph::ExternalNode {
                base,
                external_document_reference: self.ext_external_document_ref.unwrap_or_default(),
                external_node_id: self.ext_external_node_id.unwrap_or_default(),
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
    sbom.published,

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
                .column(sbom_node::Column::SbomId)
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
        let latest_sbom_ids: Vec<_> = match query {
            GraphQuery::Component(ComponentReference::Id(node_id)) => {
                let subquery = find(sbom_node::Relation::Package)
                    .filter(sbom_node::Column::NodeId.eq(node_id));

                query_all(subquery.into_query(), connection).await?
            }
            GraphQuery::Component(ComponentReference::Name(name)) => {
                let subquery =
                    find(sbom_node::Relation::Package).filter(sbom_node::Column::Name.eq(name));

                query_all(subquery.into_query(), connection).await?
            }
            GraphQuery::Component(ComponentReference::Purl(purl)) => {
                let subquery = find(sbom_node::Relation::Package)
                    .join(JoinType::LeftJoin, sbom_package::Relation::Purl.def())
                    .join(
                        JoinType::LeftJoin,
                        sbom_package_purl_ref::Relation::Purl.def(),
                    )
                    .join(
                        JoinType::LeftJoin,
                        qualified_purl::Relation::VersionedPurl.def(),
                    )
                    .join(JoinType::LeftJoin, versioned_purl::Relation::BasePurl.def())
                    .filter(
                        Cond::any()
                            .add(
                                sbom_package_purl_ref::Column::QualifiedPurlId
                                    .eq(purl.qualifier_uuid()),
                            )
                            .add(qualified_purl::Column::VersionedPurlId.eq(purl.version_uuid()))
                            .add(versioned_purl::Column::BasePurlId.eq(purl.package_uuid())),
                    );

                query_all(subquery.into_query(), connection).await?
            }
            GraphQuery::Component(ComponentReference::Cpe(cpe)) => {
                let subquery = find(sbom_node::Relation::Package)
                    .join(
                        JoinType::LeftJoin,
                        sbom_package_cpe_ref::Relation::Cpe.def(),
                    )
                    .filter(sbom_package_cpe_ref::Column::CpeId.eq(cpe.uuid()));

                query_all(subquery.into_query(), connection).await?
            }
            GraphQuery::Query(query) => {
                let subquery = find(sbom_node::Relation::Package)
                    .join(JoinType::LeftJoin, sbom_package::Relation::Purl.def())
                    .join(
                        JoinType::LeftJoin,
                        sbom_package_purl_ref::Relation::Purl.def(),
                    )
                    .join(
                        JoinType::LeftJoin,
                        sbom_package_cpe_ref::Relation::Cpe.def(),
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

        let distinct_sbom_id =
            Uuid::parse_str(distinct_sbom_id).map_err(|err| Error::BadRequest {
                msg: format!("Unable to parse SBOM ID {distinct_sbom_id}: {err}"),
                status: StatusCode::BAD_REQUEST,
            })?;

        // check if there is a loading operation pending

        enum Ops {
            /// existing operation to await
            Existing(LoadingOp),
            /// new operation to report back to
            New(oneshot::Sender<Result<Arc<PackageGraph>, String>>),
        }

        // Evaluate if we need a new operation or have an existing one
        //
        // This locks the map, so we need to just extract, not await anything.

        let ops = match self.loading_ops.lock().entry(distinct_sbom_id) {
            Entry::Occupied(o) => Ops::Existing(o.get().clone()),
            Entry::Vacant(v) => {
                let (tx, rx) = oneshot::channel();
                v.insert(rx.shared());
                Ops::New(tx)
            }
        };

        // Act on operation (await or proceed)

        let tx = match ops {
            Ops::Existing(rx) => {
                log::debug!("Cache miss, but loading in progress");

                self.cache_miss.add(1, &[KeyValue::new("type", "await")]);

                // there is an operation in progress, await and return

                return rx
                    .await
                    // error awaiting
                    .map_err(|_| Error::Internal("failed to await loading operation".into()))?
                    // error from performing the loading operation
                    .map_err(Error::Internal);
            }
            Ops::New(tx) => {
                log::debug!("Cache miss, need to load");
                self.cache_miss.add(1, &[KeyValue::new("type", "load")]);
                tx
            }
        };

        // full cache miss, perform the work

        let g = match Self::perform_load_graph(connection, distinct_sbom_id).await {
            Ok(g) => g,
            Err(err) => {
                // failed to load, remove and notify
                self.loading_ops.lock().remove(&distinct_sbom_id);
                let _ = tx.send(Err(err.to_string()));
                return Err(err);
            }
        };
        let g = Arc::new(g);

        self.graph_cache
            .insert(distinct_sbom_id.to_string(), g.clone());

        // remove the ops handle and notify the waiting tasks

        self.loading_ops.lock().remove(&distinct_sbom_id);
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

        let mut ctx = Context::new();

        for node in loaded_nodes {
            detected_nodes.insert(node.node_id.clone());

            match nodes.entry(node.node_id.clone()) {
                Entry::Vacant(entry) => {
                    let index = g.add_node(node.into_graph_node(&mut ctx));

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

    /// Load all SBOMs by the provided IDs, also resolve external references and load them too
    #[instrument(
        skip(self, connection, distinct_sbom_ids),
        fields(distinct_sbom_ids_len = distinct_sbom_ids.len()),
        err(level=tracing::Level::INFO))
    ]
    pub async fn load_graphs<C: ConnectionTrait>(
        &self,
        connection: &C,
        distinct_sbom_ids: &[impl AsRef<str> + Debug],
    ) -> Result<Vec<(String, Arc<PackageGraph>)>, Error> {
        log::info!(
            "Initiating SBOM graph loading for {} SBOM(s)",
            distinct_sbom_ids.len()
        );

        let mut seen_sbom_ids: HashSet<String> = HashSet::new();
        self.load_graphs_inner(connection, distinct_sbom_ids, &mut seen_sbom_ids)
            .await
    }

    pub async fn load_graphs_inner<C: ConnectionTrait>(
        &self,
        connection: &C,
        distinct_sbom_ids: &[impl AsRef<str> + Debug],
        seen_sbom_ids: &mut HashSet<String>,
    ) -> Result<Vec<(String, Arc<PackageGraph>)>, Error> {
        let mut results = Vec::new();

        for distinct_sbom_id in distinct_sbom_ids.iter().map(AsRef::as_ref) {
            log::debug!("loading sbom: {:?}", distinct_sbom_id);
            let current_sbom_id_str = distinct_sbom_id.to_string();
            if seen_sbom_ids.insert(current_sbom_id_str.clone()) {
                // at this stage we just have sbom_id string, so have to convert back to uuid
                let distinct_sbom_id_uuid = match Uuid::parse_str(distinct_sbom_id) {
                    Ok(uuid) => uuid,
                    Err(e) => {
                        log::error!(
                            "Failed to parse distinct_sbom_id '{distinct_sbom_id:?}' as UUID: {e:?}"
                        );
                        Uuid::nil()
                    }
                };
                // select all related external nodes
                let external_sboms = sbom_external_node::Entity::find()
                    .filter(sbom_external_node::Column::SbomId.eq(distinct_sbom_id_uuid))
                    .all(connection)
                    .await?;

                //resolve and load externally referenced sboms
                for external_sbom in &external_sboms {
                    let resolved_external_sbom =
                        resolve_external_sbom(&external_sbom.node_id, connection).await;
                    log::debug!("resolved external sbom: {:?}", resolved_external_sbom);
                    if let Some(resolved_external_sbom) = resolved_external_sbom {
                        let resolved_external_sbom_id_str =
                            resolved_external_sbom.sbom_id.to_string();
                        if seen_sbom_ids.insert(resolved_external_sbom_id_str.clone()) {
                            results.push((
                                resolved_external_sbom_id_str,
                                self.load_graph(
                                    connection,
                                    &resolved_external_sbom.sbom_id.to_string(),
                                )
                                .await?,
                            ));
                            // recurse into to find nested external sboms
                            Box::pin(self.load_graphs_inner(
                                connection,
                                &[resolved_external_sbom.sbom_id.to_string()],
                                seen_sbom_ids,
                            ))
                            .await?;
                        } else {
                            log::debug!(
                                "Skipping duplicate external SBOM ID: {}",
                                resolved_external_sbom_id_str
                            );
                        }
                    } else {
                        log::debug!("Cannot find external sbom {:?}", external_sbom.node_id);
                        continue;
                    }
                }

                results.push((
                    current_sbom_id_str,
                    self.load_graph(connection, distinct_sbom_id).await?,
                ));
            } else {
                log::debug!("Skipping duplicate SBOM ID: {}", current_sbom_id_str);
            }
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

#[derive(Debug, FromQueryResult)]
struct Row {
    sbom_id: Uuid,
}

fn find(sbom_package_relation: sbom_node::Relation) -> Select<sbom_node::Entity> {
    sbom_node::Entity::find()
        .distinct()
        .select_only()
        .column(sbom_node::Column::SbomId)
        .join(JoinType::LeftJoin, sbom_package_relation.def())
        .join(JoinType::LeftJoin, sbom_package::Relation::Cpe.def())
}

fn rank_query(mut subquery: SelectStatement) -> WithQuery {
    const CTE_TABLE_NAME: &str = "describing_ranked";
    subquery.join(
        JoinType::Join,
        CTE_TABLE_NAME,
        Expr::col((CTE_TABLE_NAME, "sbom_id")).eq(sbom_node::Column::SbomId.into_expr()),
    );

    WithClause::new()
        .query(subquery)
        .cte(
            CommonTableExpression::new()
                .table_name(CTE_TABLE_NAME)
                .query(
                    SelectStatement::new()
                        .distinct_on([
                            (sbom_node::Entity, sbom_node::Column::Name).into_column_ref(),
                            (
                                sbom_package_cpe_ref::Entity,
                                sbom_package_cpe_ref::Column::CpeId,
                            )
                                .into_column_ref(),
                        ])
                        .from(sbom_node::Entity)
                        .column((sbom_node::Entity, sbom_node::Column::SbomId))
                        .column((sbom_node::Entity, sbom_node::Column::Name))
                        .column((
                            sbom_package_cpe_ref::Entity,
                            sbom_package_cpe_ref::Column::CpeId,
                        ))
                        .join(
                            JoinType::Join,
                            sbom::Entity,
                            sbom_node::Relation::Sbom.def(),
                        )
                        .join(
                            JoinType::Join,
                            package_relates_to_package::Entity,
                            package_relates_to_package::Relation::Right
                                .def()
                                .rev()
                                .on_condition(|_left, right| {
                                    Expr::col((
                                        right,
                                        package_relates_to_package::Column::Relationship,
                                    ))
                                    .eq(Relationship::Describes)
                                    .into_condition()
                                }),
                        )
                        .left_join(
                            sbom_package_cpe_ref::Entity,
                            all![
                                Expr::col((sbom_node::Entity, sbom_node::Column::SbomId)).equals((
                                    sbom_package_cpe_ref::Entity,
                                    sbom_package_cpe_ref::Column::SbomId
                                )),
                                Expr::col((sbom_node::Entity, sbom_node::Column::NodeId)).equals((
                                    sbom_package_cpe_ref::Entity,
                                    sbom_package_cpe_ref::Column::NodeId
                                )),
                            ],
                        )
                        .order_by((sbom_node::Entity, sbom_node::Column::Name), Order::Asc)
                        .order_by(
                            (
                                sbom_package_cpe_ref::Entity,
                                sbom_package_cpe_ref::Column::CpeId,
                            ),
                            Order::Asc,
                        )
                        .order_by((sbom::Entity, sbom::Column::Published), Order::Desc)
                        .to_owned(),
                )
                .to_owned(),
        )
        .to_owned()
}

/// Take a select statement and load all sboms from it. The select statement will be used
/// as a sub-select and needs to provide:
/// * `sbom_id`
/// * `rank`
async fn query_all<C>(subquery: SelectStatement, connection: &C) -> Result<Vec<String>, Error>
where
    C: ConnectionTrait,
{
    let select_query = rank_query(subquery);

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

#[cfg(test)]
mod test {
    use super::*;
    use sea_query::Values;

    #[test]
    fn rank_sql() {
        let subquery = find(sbom_node::Relation::Package)
            .filter(sbom_package_cpe_ref::Column::CpeId.eq("00000000-0000-0000-0000-000000000000"));

        let select_query = rank_query(subquery.into_query());
        let (sql, values) = select_query.build(PostgresQueryBuilder);

        assert_eq!(
            sql,
            r#"
WITH "describing_ranked" AS (SELECT DISTINCT ON ("sbom_node"."name", "sbom_package_cpe_ref"."cpe_id")
        "sbom_node"."sbom_id",
        "sbom_node"."name",
        "sbom_package_cpe_ref"."cpe_id"
    FROM
        "sbom_node"
        JOIN "sbom"
            ON "sbom_node"."sbom_id" = "sbom"."sbom_id"
         JOIN "package_relates_to_package"
              ON "sbom_node"."sbom_id" = "package_relates_to_package"."sbom_id"
                  AND "sbom_node"."node_id" = "package_relates_to_package"."right_node_id"
                  AND "package_relates_to_package"."relationship" = $1
         LEFT JOIN "sbom_package_cpe_ref"
               ON "sbom_node"."sbom_id" = "sbom_package_cpe_ref"."sbom_id"
                   AND "sbom_node"."node_id" = "sbom_package_cpe_ref"."node_id"
         ORDER BY "sbom_node"."name" ASC, "sbom_package_cpe_ref"."cpe_id" ASC, "sbom"."published" DESC)
SELECT
    DISTINCT "sbom_node"."sbom_id"
FROM
    "sbom_node"
    LEFT JOIN "sbom_package"
        ON "sbom_node"."sbom_id" = "sbom_package"."sbom_id"
            AND "sbom_node"."node_id" = "sbom_package"."node_id"
    LEFT JOIN "sbom_package_cpe_ref"
        ON "sbom_package"."sbom_id" = "sbom_package_cpe_ref"."sbom_id"
            AND "sbom_package"."node_id" = "sbom_package_cpe_ref"."node_id"
    JOIN "describing_ranked"
        ON "describing_ranked"."sbom_id" = "sbom_node"."sbom_id"
WHERE
    "sbom_package_cpe_ref"."cpe_id" = $2
"#
            .replace('\n', " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
        );

        assert_eq!(
            values,
            Values(vec![
                13.into(),
                "00000000-0000-0000-0000-000000000000".into(),
            ])
        );
    }
}
