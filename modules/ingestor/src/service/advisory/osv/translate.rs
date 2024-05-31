use osv::schema::{Ecosystem, Package};
use packageurl::PackageUrl;

/// Try converting an ecosystem/name pair into a purl.
pub fn to_purl(
    Package {
        ecosystem,
        name,
        purl: _,
    }: &Package,
) -> Option<PackageUrl> {
    translate(ecosystem, name)
}

/// Also see: <https://ossf.github.io/osv-schema/#affectedpackage-field>
fn translate<'a>(ecosystem: &Ecosystem, name: &'a str) -> Option<PackageUrl<'a>> {
    match ecosystem {
        Ecosystem::CRAN => PackageUrl::new("cran", name).ok(),
        Ecosystem::CratesIO => PackageUrl::new("cargo", name).ok(),
        Ecosystem::Npm => PackageUrl::new("npm", name).ok(),
        Ecosystem::Maven => {
            let split = name.split(':').collect::<Vec<_>>();
            if split.len() == 2 {
                let namespace = split[0];
                let name = split[1];
                PackageUrl::new("maven", name)
                    .map(|mut purl| {
                        purl.with_namespace(namespace);
                        purl
                    })
                    .ok()
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[test_log::test(rstest)]
    #[case(Ecosystem::CratesIO, "packageurl", Some("pkg:cargo/packageurl"))]
    fn test_translate(
        #[case] ecosystem: Ecosystem,
        #[case] name: &str,
        #[case] outcome: Option<&str>,
    ) {
        assert_eq!(
            to_purl(&Package {
                ecosystem,
                name: name.to_string(),
                purl: None,
            })
            .map(|purl| purl.to_string())
            .as_deref(),
            outcome
        );
    }
}
