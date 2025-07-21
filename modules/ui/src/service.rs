use crate::model::ExtractPackage;
use serde_cyclonedx::cyclonedx::v_1_6::{Component, ComponentEvidenceIdentity};
use std::collections::BTreeMap;
use trustify_common::purl::Purl;

/// Extract PURLs from a SPDX file
pub fn extract_spdx_purls(sbom: spdx_rs::models::SPDX) -> BTreeMap<String, ExtractPackage> {
    let mut result = BTreeMap::<String, ExtractPackage>::new();

    for pkg in sbom.package_information {
        let mut purls = vec![];
        for er in pkg.external_reference {
            if er.reference_type == "purl" {
                purls.extend(filter_purl(er.reference_locator));
            }
        }

        result
            .entry(pkg.package_name)
            .or_default()
            .purls
            .extend(purls)
    }

    result
}

/// Extract PURLs from a CycloneDX file
pub fn extract_cyclonedx_purls(
    sbom: serde_cyclonedx::cyclonedx::v_1_6::CycloneDx,
) -> BTreeMap<String, ExtractPackage> {
    let mut result = BTreeMap::new();

    fn scan_comps(result: &mut BTreeMap<String, ExtractPackage>, component: Component) {
        let mut purls = vec![];
        if let Some(purl) = component.purl.and_then(filter_purl) {
            purls.push(purl);
        }

        purls.extend(
            component
                .evidence
                .into_iter()
                .flat_map(|cev| cev.identity)
                .flat_map(|id| match id {
                    ComponentEvidenceIdentity::Variant0(id) => id,
                    ComponentEvidenceIdentity::Variant1(id) => vec![id],
                })
                .filter(|id| id.field == "purl")
                .flat_map(|id| id.concluded_value)
                .flat_map(filter_purl),
        );

        result
            .entry(component.name)
            .or_default()
            .purls
            .extend(purls);

        for comp in component.components.into_iter().flatten() {
            scan_comps(result, comp);
        }
    }

    if let Some(component) = sbom.metadata.and_then(|md| md.component) {
        scan_comps(&mut result, component);
    }

    for component in sbom.components.into_iter().flatten() {
        scan_comps(&mut result, component);
    }

    result
}

/// Filter out invalid PURLs
///
/// If the PURL is valid, return the `Some(input)`, otherwise return `None`.
fn filter_purl(purl: String) -> Option<String> {
    Purl::try_from(purl.as_str()).ok().map(|_| purl)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn invalid() {
        assert_eq!(filter_purl("".into()), None);
        assert_eq!(filter_purl("pkg:".into()), None);
    }

    #[test]
    fn valid() {
        assert_eq!(
            filter_purl("pkg:golang/archive/tar".into()),
            Some("pkg:golang/archive/tar".into())
        );
    }
}
