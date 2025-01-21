use crate::{
    endpoints::configure,
    model::{AncNode, AncestorSummary},
};
use itertools::Itertools;
use trustify_test_context::{
    call::{self, CallService},
    TrustifyContext,
};

pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService + '_> {
    call::caller(|svc| configure(svc, ctx.db.clone())).await
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct Node<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub version: &'a str,

    pub cpes: &'a [&'a str],
    pub purls: &'a [&'a str],
}

#[derive(PartialEq, Eq, Debug, Clone)]
struct OwnedNode<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub version: &'a str,

    pub cpes: Vec<String>,
    pub purls: Vec<String>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
struct RefNode<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub version: &'a str,

    pub cpes: Vec<&'a str>,
    pub purls: Vec<&'a str>,
}

impl<'a> From<&'a AncNode> for OwnedNode<'a> {
    fn from(value: &'a AncNode) -> Self {
        Self {
            id: &value.node_id,
            name: &value.name,
            version: &value.version,
            cpes: value.cpe.iter().map(ToString::to_string).collect(),
            purls: value.purl.iter().map(ToString::to_string).collect(),
        }
    }
}

pub fn assert_ancestors<F>(ancestors: &[AncestorSummary], f: F)
where
    F: for<'a> FnOnce(&'a [&'a [Node]]),
{
    let ancestors = ancestors
        .iter()
        .sorted_by_key(|a| &a.node_id)
        .map(|item| {
            item.ancestors
                .iter()
                .map(OwnedNode::from)
                .sorted_by_key(|n| n.id.to_string())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let ancestors = ancestors
        .iter()
        .map(|a| {
            a.iter()
                .map(|node| RefNode {
                    id: node.id,
                    name: node.name,
                    version: node.version,
                    cpes: node.cpes.iter().map(|s| s.as_str()).collect(),
                    purls: node.purls.iter().map(|s| s.as_str()).collect(),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let ancestors = ancestors
        .iter()
        .map(|a| {
            a.iter()
                .map(|node| Node {
                    id: node.id,
                    name: node.name,
                    version: node.version,
                    cpes: node.cpes.as_slice(),
                    purls: node.purls.as_slice(),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let ancestors = ancestors.iter().map(|a| a.as_slice()).collect::<Vec<_>>();

    log::debug!("Ancestors: {ancestors:#?}");

    f(ancestors.as_slice())
}
