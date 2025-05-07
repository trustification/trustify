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
use petgraph::{Graph, prelude::NodeIndex};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DbErr, EntityOrSelect, EntityTrait,
    FromQueryResult, QueryFilter, QuerySelect, QueryTrait, RelationTrait, Statement,
};
use sea_query::{JoinType, SelectStatement};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    fmt::Debug,
    str::FromStr,
    sync::Arc,
};
use tracing::{Level, instrument};
use trustify_common::{
    cpe::Cpe as TrustifyCpe,
    db::query::{Filtering, IntoColumns},
    purl::Purl,
};
use trustify_entity::qualified_purl::{self, CanonicalPurl};
use trustify_entity::{
    cpe, cpe::CpeDto, package_relates_to_package, relationship::Relationship, sbom,
    sbom_external_node, sbom_external_node::ExternalType, sbom_node, sbom_package,
    sbom_package_cpe_ref, sbom_package_purl_ref,
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
            GraphQuery::Query(query) => {
                sbom_node::Entity::find()
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
                    .filtering_with(
                        query.clone(),
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
                            }),
                    )?
                    .distinct()
                    .into_query()
            }
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
        let latest_sbom_ids = match query {
            // TODO: due to limitations in sea_orm/sqlx with using PARTITION_BY queries
            //       this codepath uses raw sql ... this means we will have 2 query codepaths to 
            //       maintain in the short term. 
            GraphQuery::Component(ComponentReference::Id(node_id)) => {
                let sql = r#"
                  SELECT distinct sbom_id
                  FROM (
                      SELECT sbom.sbom_id, sbom.published, cpe.id,
                      RANK() OVER (PARTITION BY cpe.id ORDER BY sbom.published DESC) AS rank
                      FROM sbom_node
                      LEFT JOIN sbom ON sbom.sbom_id = sbom_node.sbom_id
                      LEFT JOIN sbom_package_cpe_ref on sbom.sbom_id = sbom_package_cpe_ref.sbom_id
                      LEFT JOIN cpe ON sbom_package_cpe_ref.cpe_id = cpe.id
                      WHERE sbom_node.node_id = $1
                  ) AS subquery
                  WHERE rank = 1;                
                "#;
                let stmt = Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    sql,
                    [node_id.into()],
                );
                let rows = connection.query_all(stmt).await?;
                rows.into_iter()
                    .filter_map(|row| {
                        row.try_get_by_index::<Uuid>(0)
                            .ok()
                            .map(|sbom_id| sbom_id.to_string())
                    })
                    .collect::<Vec<String>>()
            }
            GraphQuery::Component(ComponentReference::Name(name)) => {
                let sql = r#"
                  SELECT distinct sbom_id
                  FROM (
                      SELECT sbom.sbom_id, sbom.published, cpe.id,
                      RANK() OVER (PARTITION BY cpe.id ORDER BY sbom.published DESC) AS rank
                      FROM sbom_node
                      LEFT JOIN sbom ON sbom.sbom_id = sbom_node.sbom_id
                      LEFT JOIN sbom_package_cpe_ref on sbom.sbom_id = sbom_package_cpe_ref.sbom_id
                      LEFT JOIN cpe ON sbom_package_cpe_ref.cpe_id = cpe.id
                      WHERE sbom_node.name = $1
                  ) AS subquery
                  WHERE rank = 1;
                  "#;
                let stmt =
                    Statement::from_sql_and_values(DatabaseBackend::Postgres, sql, [name.into()]);
                let rows = connection.query_all(stmt).await?;
                rows.into_iter()
                    .filter_map(|row| {
                        row.try_get_by_index::<Uuid>(0)
                            .ok()
                            .map(|sbom_id| sbom_id.to_string())
                    })
                    .collect::<Vec<String>>()
            }
            GraphQuery::Component(ComponentReference::Purl(purl)) => {
                let sql = r#"
                 SELECT distinct sbom_id
                  FROM (
                      SELECT sbom.sbom_id, sbom.published, cpe.id,
                      RANK() OVER (PARTITION BY cpe.id ORDER BY sbom.published DESC) AS rank
                      FROM sbom_package_purl_ref
                      LEFT JOIN sbom ON sbom.sbom_id = sbom_package_purl_ref.sbom_id
                      LEFT JOIN sbom_package_cpe_ref on sbom.sbom_id = sbom_package_cpe_ref.sbom_id
                      LEFT JOIN cpe ON sbom_package_cpe_ref.cpe_id = cpe.id
                      WHERE sbom_package_purl_ref.qualified_purl_id = $1
                  ) AS subquery
                  WHERE rank = 1;
                "#;
                let stmt = Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    sql,
                    [purl.qualifier_uuid().into()],
                );
                let rows = connection.query_all(stmt).await?;
                rows.into_iter()
                    .filter_map(|row| {
                        row.try_get_by_index::<Uuid>(0)
                            .ok()
                            .map(|sbom_id| sbom_id.to_string())
                    })
                    .collect::<Vec<String>>()
            }
            GraphQuery::Component(ComponentReference::Cpe(cpe)) => {
                let sql = r#"
                  SELECT distinct sbom_id
                  FROM (
                      SELECT sbom.sbom_id, sbom.published, cpe.id,
                      RANK() OVER (PARTITION BY cpe.id ORDER BY sbom.published DESC) AS rank
                      FROM sbom_package_cpe_ref
                      LEFT JOIN sbom ON sbom.sbom_id = sbom_package_cpe_ref.sbom_id
                      LEFT JOIN cpe ON sbom_package_cpe_ref.cpe_id = cpe.id
                      WHERE sbom_package_cpe_ref.cpe_id = $1
                  ) AS subquery
                  WHERE rank = 1;
                "#;
                let stmt = Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    sql,
                    [cpe.uuid().into()],
                );
                let rows = connection.query_all(stmt).await?;
                rows.into_iter()
                    .filter_map(|row| {
                        row.try_get_by_index::<Uuid>(0)
                            .ok()
                            .map(|sbom_id| sbom_id.to_string())
                    })
                    .collect::<Vec<String>>()
            }
            GraphQuery::Query(query) => {
                // TODO: we assume q=<partial purl> was supplied this area of the code will change.
                //       for now creating a special local function to handle.
                #[derive(Debug, Default, PartialEq)]
                struct BasicPurlParts<'a> {
                    ptype: Option<&'a str>,
                    namespace: Option<&'a str>, // Represents the full namespace string
                    name: Option<&'a str>,
                    version: Option<&'a str>,
                    qualifiers_str: Option<&'a str>, // Qualifiers as a single raw string
                    subpath: Option<&'a str>,
                }

                // TODO: Non-compliant parsing of partial, incomplete pURL.
                //       This attempts to parse whatever is given into 
                //       purl parts.
                fn basic_non_compliant_parse_purl(purl_str: &str) -> Option<BasicPurlParts> {
                    // start with "pkg:" if it exists
                    let remaining = purl_str.strip_prefix("pkg:")?;

                    let mut parts = BasicPurlParts::default();
                    let mut current_part = remaining; 

                    // subpath (split by '#') - assume only one '#' allowed
                    if let Some(subpath_idx) = current_part.find('#') {
                        parts.subpath = Some(&current_part[subpath_idx + 1..]);
                        current_part = &current_part[..subpath_idx];
                    }

                    // qualifiers (split by '?')
                    if let Some(qualifiers_idx) = current_part.find('?') {
                        parts.qualifiers_str = Some(&current_part[qualifiers_idx + 1..]);
                        current_part = &current_part[..qualifiers_idx];
                    }

                    // version (split by last '@')
                    if let Some(version_idx) = current_part.rfind('@') {
                        // Check if '@' is not the first char after potentially splitting off type
                        let type_separator_pos = current_part.find('/');
                        if version_idx > type_separator_pos.unwrap_or(0) {
                            parts.version = Some(&current_part[version_idx + 1..]);
                            current_part = &current_part[..version_idx];
                        }
                    }
                    // type (split by the first '/')
                    let type_separator_idx = current_part.find('/')?; 
                    parts.ptype = Some(&current_part[..type_separator_idx]);
                    let rest_after_type = &current_part[type_separator_idx + 1..];
                    
                    if let Some(name_separator_idx) = rest_after_type.rfind('/') {
                        // Check if the slash is not the only character or the last character
                        if name_separator_idx > 0 && name_separator_idx < rest_after_type.len() - 1
                        {
                            parts.namespace = Some(&rest_after_type[..name_separator_idx]);
                            parts.name = Some(&rest_after_type[name_separator_idx + 1..]);
                        } else {
                            // Handle cases like "type//name" or "type/name/" -> treat as no namespace
                            parts.namespace = None;
                            parts.name = Some(rest_after_type);
                        }
                    } else {
                        // No '/' in the remaining part, so it's all name, no namespace
                        parts.namespace = None;
                        parts.name = Some(rest_after_type);
                    }

                    // Name must exist and be non-empty
                    #[allow(clippy::unnecessary_map_or)]
                    if parts.name.map_or(true, |n| n.is_empty()) {
                        return None;
                    }

                    Some(parts)
                }

                let purl_search_string = query.q.as_str();
                log::warn!("{:?}",query);
                    
                match basic_non_compliant_parse_purl(purl_search_string) {
                    Some(url_parts) => {
                        let ptype = url_parts.ptype;
                        let name = url_parts.name;
                        let namespace = url_parts.namespace;
                        let version = url_parts.version;
                        // let qualifiers_str = url_parts.qualifiers_str;
                        // let subpath = url_parts.subpath;
                        let sql = r#"
                          SELECT distinct sbom_id
                          FROM (
                              SELECT sbom.sbom_id, sbom.published, cpe.id,
                              RANK() OVER (PARTITION BY cpe.id ORDER BY sbom.published DESC) AS rank
                              FROM sbom_package_purl_ref
                              LEFT JOIN sbom ON sbom.sbom_id = sbom_package_purl_ref.sbom_id
                              LEFT JOIN sbom_package_cpe_ref on sbom.sbom_id = sbom_package_cpe_ref.sbom_id
                              LEFT JOIN cpe ON sbom_package_cpe_ref.cpe_id = cpe.id
                              LEFT JOIN qualified_purl on sbom_package_purl_ref.qualified_purl_id = qualified_purl.id
                              WHERE
                                ( NULLIF($1, '') IS NULL OR qualified_purl.purl->>'ty' ~ $1 )
                              AND
                                ( NULLIF($2, '') IS NULL OR qualified_purl.purl->>'name' ~ $2 )
                              AND
                                ( NULLIF($3, '') IS NULL OR qualified_purl.purl->>'namespace' ~ $3 )
                              AND
                                ( NULLIF($4, '') IS NULL OR qualified_purl.purl->>'version' ~ $4 )
                          ) AS subquery
                          WHERE rank = 1;
                        "#;
                        let stmt = Statement::from_sql_and_values(
                            DatabaseBackend::Postgres,
                            sql,
                            [ptype.into(), name.into(), namespace.into(), version.into()],
                        );
                        let rows = connection.query_all(stmt).await?;
                        rows.into_iter()
                            .filter_map(|row| {
                                row.try_get_by_index::<Uuid>(0)
                                    .ok()
                                    .map(|sbom_id| sbom_id.to_string())
                            })
                            .collect::<Vec<String>>()
                    }
                    None => {
                        log::debug!(
                            "Failed to parse into any pURL parts: {}",
                            purl_search_string
                        );
                        let name = query.q.clone().to_string();
                        let sql = r#"
                          SELECT distinct sbom_id
                          FROM (
                              SELECT sbom.sbom_id, sbom.published, cpe.id,
                              RANK() OVER (PARTITION BY cpe.id ORDER BY sbom.published DESC) AS rank
                              FROM sbom_node
                              LEFT JOIN sbom ON sbom.sbom_id = sbom_node.sbom_id
                              LEFT JOIN sbom_package_cpe_ref on sbom.sbom_id = sbom_package_cpe_ref.sbom_id
                              LEFT JOIN cpe ON sbom_package_cpe_ref.cpe_id = cpe.id
                              WHERE sbom_node.name ~ $1
                          ) AS subquery
                          WHERE rank = 1;
                          "#;
                        let stmt = Statement::from_sql_and_values(
                            DatabaseBackend::Postgres,
                            sql,
                            [name.into()],
                        );
                        let rows = connection.query_all(stmt).await?;
                        rows.into_iter()
                            .filter_map(|row| {
                                row.try_get_by_index::<Uuid>(0)
                                    .ok()
                                    .map(|sbom_id| sbom_id.to_string())
                            })
                            .collect::<Vec<String>>()
                    }
                }
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
            // early return if we already loaded it
            return Ok(g);
        }

        let distinct_sbom_id = match Uuid::parse_str(distinct_sbom_id) {
            Ok(uuid) => uuid,
            Err(err) => {
                return Err(Error::Database(anyhow!(
                    "Unable to parse SBOM ID {distinct_sbom_id}: {err}"
                )));
            }
        };

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

        // Set the result. A parallel call might have done the same. We wasted some time, but the
        // state is still correct.

        let g = Arc::new(g);
        self.graph_cache
            .insert(distinct_sbom_id.to_string(), g.clone());
        Ok(g)
    }

    /// Load all SBOMs by the provided IDs
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn load_graphs<C: ConnectionTrait>(
        &self,
        connection: &C,
        distinct_sbom_ids: &[impl AsRef<str> + Debug],
    ) -> Result<Vec<(String, Arc<PackageGraph>)>, Error> {
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
