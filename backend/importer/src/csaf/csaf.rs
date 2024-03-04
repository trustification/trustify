use csaf::definitions::{Branch, BranchesT};
use csaf::product_tree::ProductTree;
use csaf::Csaf;

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
