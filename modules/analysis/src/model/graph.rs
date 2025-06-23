use super::*;
use time::{OffsetDateTime, macros::format_description};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize, DeepSizeOf)]
pub enum Node {
    Package(PackageNode),
    External(ExternalNode),
    Unknown(BaseNode),
}

impl Deref for Node {
    type Target = BaseNode;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Package(package) => &package.base,
            Self::External(external) => &external.base,
            Self::Unknown(base) => base,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize)]
pub struct BaseNode {
    pub sbom_id: Uuid,
    pub node_id: String,
    pub published: OffsetDateTime,

    pub name: String,

    pub document_id: Option<Arc<String>>,
    pub product_name: Option<Arc<String>>,
    pub product_version: Option<Arc<String>>,
}

impl DeepSizeOf for BaseNode {
    fn deep_size_of_children(&self, context: &mut Context) -> usize {
        let Self {
            sbom_id,
            node_id,
            published,
            name,
            document_id,
            product_name,
            product_version,
        } = self;

        size_of_val(sbom_id)
            + node_id.deep_size_of_children(context)
            + size_of_val(published)
            + name.deep_size_of_children(context)
            + document_id.deep_size_of_children(context)
            + product_name.deep_size_of_children(context)
            + product_version.deep_size_of_children(context)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize, DeepSizeOf)]
pub struct PackageNode {
    pub base: BaseNode,

    pub purl: Arc<[Purl]>,
    pub cpe: Arc<[Cpe]>,
    pub version: String,
}

impl Deref for PackageNode {
    type Target = BaseNode;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl fmt::Display for PackageNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.purl)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize, DeepSizeOf)]
pub struct ExternalNode {
    pub base: BaseNode,

    pub external_document_reference: String,
    pub external_node_id: String,
}

impl Deref for ExternalNode {
    type Target = BaseNode;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

fn published_to_string(value: OffsetDateTime) -> String {
    let format = format_description!(
        "[year]-[month]-[day] [hour]:[minute]:[second][offset_hour sign:mandatory]"
    );

    value.format(&format).unwrap_or_else(|_| value.to_string())
}

impl From<&Node> for BaseSummary {
    fn from(value: &Node) -> Self {
        match value {
            Node::Package(value) => BaseSummary::from(value),
            _ => Self {
                sbom_id: value.sbom_id.to_string(),
                node_id: value.node_id.to_string(),
                purl: vec![],
                cpe: vec![],
                name: value.name.to_string(),
                version: "".to_string(),
                published: published_to_string(value.published),
                document_id: value
                    .document_id
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                product_name: value
                    .product_name
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                product_version: value
                    .product_version
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
            },
        }
    }
}

impl From<&PackageNode> for BaseSummary {
    fn from(value: &PackageNode) -> Self {
        Self {
            sbom_id: value.sbom_id.to_string(),
            node_id: value.node_id.to_string(),
            purl: value.purl.to_vec(),
            cpe: value.cpe.to_vec(),
            name: value.name.to_string(),
            version: value.version.to_string(),
            published: published_to_string(value.published),
            document_id: value
                .document_id
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default(),
            product_name: value
                .product_name
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default(),
            product_version: value
                .product_version
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default(),
        }
    }
}
