use csaf::definitions::{Branch, BranchesT, ProductIdT};
use csaf::product_tree::ProductTree;
use csaf::Csaf;
use packageurl::PackageUrl;

pub fn resolve_identifier<'a>(
    csaf: &'a Csaf,
    id: &'a ProductIdT,
) -> Option<(
    Option<&'a cpe::uri::OwnedUri>,
    Option<&'a PackageUrl<'static>>,
)> {
    let id = &id.0;

    if let Some(tree) = &csaf.product_tree {
        for rel in tree.relationships.iter().flatten() {
            if &rel.full_product_name.product_id.0 != id {
                continue;
            }

            let inner_id = &rel.product_reference;
            let context = &rel.relates_to_product_reference;

            let purls: Vec<_> = trace_product(csaf, &inner_id.0)
                .into_iter()
                .flat_map(branch_purl)
                .collect();
            let cpes: Vec<_> = trace_product(csaf, &context.0)
                .into_iter()
                .flat_map(branch_cpe)
                .collect();

            if cpes.is_empty() && purls.is_empty() {
                return None;
            } else {
                return Some((cpes.first().cloned(), purls.first().cloned()));
            }
        }
    }

    None
}

pub fn branch_purl(branch: &Branch) -> Option<&PackageUrl<'static>> {
    branch.product.as_ref().and_then(|name| {
        name.product_identification_helper
            .iter()
            .flat_map(|pih| pih.purl.as_ref())
            .next()
    })
}

pub fn branch_cpe(branch: &Branch) -> Option<&cpe::uri::OwnedUri> {
    branch.product.as_ref().and_then(|name| {
        name.product_identification_helper
            .iter()
            .flat_map(|pih| pih.cpe.as_ref())
            .next()
    })
}

#[allow(clippy::needless_lifetimes)]
pub fn walk_product_tree_branches<'a, F>(product_tree: &'a Option<ProductTree>, f: F)
where
    F: FnMut(&[&'a Branch], &'a Branch),
{
    if let Some(product_tree) = &product_tree {
        walk_product_branches(&product_tree.branches, f);
    }
}

#[allow(clippy::needless_lifetimes)]
pub fn walk_product_branches<'a, F>(branches: &'a Option<BranchesT>, mut f: F)
where
    F: FnMut(&[&'a Branch], &'a Branch),
{
    let mut parents = vec![];
    walk_product_branches_ref(branches, &mut parents, &mut f)
}

fn walk_product_branches_ref<'a, F>(
    branches: &'a Option<BranchesT>,
    parents: &mut Vec<&'a Branch>,
    f: &mut F,
) where
    F: FnMut(&[&'a Branch], &'a Branch),
{
    if let Some(branches) = &branches {
        for branch in &branches.0 {
            f(parents, branch);
            parents.push(branch);
            walk_product_branches_ref(&branch.branches, parents, f);
            parents.pop();
        }
    }
}

pub fn trace_product<'a>(csaf: &'a Csaf, product_id: &str) -> Vec<&'a Branch> {
    let mut result = vec![];

    walk_product_tree_branches(&csaf.product_tree, |parents, branch| {
        if let Some(full_name) = &branch.product {
            if full_name.product_id.0 == product_id {
                // trace back
                result = parents
                    .iter()
                    .copied()
                    .chain(Some(branch))
                    .collect::<Vec<&'a Branch>>()
            }
        }
    });

    result
}
