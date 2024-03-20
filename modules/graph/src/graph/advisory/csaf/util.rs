use csaf::definitions::{Branch, BranchesT, ProductIdT};
use csaf::product_tree::ProductTree;
use csaf::Csaf;
use packageurl::PackageUrl;

pub fn resolve_purls<'a>(csaf: &'a Csaf, id: &'a ProductIdT) -> Vec<&'a PackageUrl<'static>> {
    let id = &id.0;
    let mut result = vec![];

    if let Some(tree) = &csaf.product_tree {
        for rel in tree.relationships.iter().flatten() {
            if &rel.full_product_name.product_id.0 != id {
                continue;
            }

            /*
            let id = match &rel.category {
                RelationshipCategory::DefaultComponentOf => &rel.product_reference,
                RelationshipCategory::OptionalComponentOf => &rel.product_reference,
            };*/
            let id = &rel.product_reference;

            let purls = trace_product(csaf, &id.0).into_iter().flat_map(branch_purl);
            result.extend(purls);
        }
    }

    result
}

pub fn branch_purl(branch: &Branch) -> Option<&PackageUrl<'static>> {
    branch.product.as_ref().and_then(|name| {
        name.product_identification_helper
            .iter()
            .flat_map(|pih| pih.purl.as_ref())
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
