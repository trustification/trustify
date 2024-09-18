use spdx_rs::models::SPDX;
use std::collections::HashSet;

/// remove all relationships having broken references
pub fn fix_spdx_rels(mut spdx: SPDX) -> SPDX {
    let mut ids = spdx
        .package_information
        .iter()
        .map(|p| &p.package_spdx_identifier)
        .collect::<HashSet<_>>();

    ids.insert(&spdx.document_creation_information.spdx_identifier);

    spdx.relationships.retain(|rel| {
        let r = ids.contains(&rel.spdx_element_id) && ids.contains(&rel.related_spdx_element);
        if !r {
            log::warn!(
                "Dropping - left: {}, rel: {:?}, right: {}",
                rel.spdx_element_id,
                rel.relationship_type,
                rel.related_spdx_element
            );
        }
        r
    });

    spdx
}
