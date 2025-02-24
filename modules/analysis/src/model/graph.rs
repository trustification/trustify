use super::*;

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

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize, DeepSizeOf)]
pub struct BaseNode {
    pub sbom_id: String,
    pub node_id: String,
    pub published: String,

    pub name: String,

    pub document_id: String,
    pub product_name: String,
    pub product_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, ToSchema, serde::Serialize, DeepSizeOf)]
pub struct PackageNode {
    pub base: BaseNode,

    pub purl: Vec<Purl>,
    pub cpe: Vec<Cpe>,
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
                published: value.published.to_string(),
                document_id: value.document_id.to_string(),
                product_name: value.product_name.to_string(),
                product_version: value.product_version.to_string(),
            },
        }
    }
}

impl From<&PackageNode> for BaseSummary {
    fn from(value: &PackageNode) -> Self {
        Self {
            sbom_id: value.sbom_id.to_string(),
            node_id: value.node_id.to_string(),
            purl: value.purl.clone(),
            cpe: value.cpe.clone(),
            name: value.name.to_string(),
            version: value.version.to_string(),
            published: value.published.to_string(),
            document_id: value.document_id.to_string(),
            product_name: value.product_name.to_string(),
            product_version: value.product_version.to_string(),
        }
    }
}
