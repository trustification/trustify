use osv::schema::{Ecosystem, Package};
use packageurl::PackageUrl;

const MAVEN_DEFAULT_REPO: &str = "https://repo.maven.apache.org/maven2";

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
        Ecosystem::Maven(repo) => {
            let split = name.split(':').collect::<Vec<_>>();
            if split.len() == 2 {
                let namespace = split[0];
                let name = split[1];
                PackageUrl::new("maven", name)
                    .and_then(|mut purl| {
                        purl.with_namespace(namespace);
                        if repo != MAVEN_DEFAULT_REPO {
                            purl.add_qualifier("repository_url", repo.clone())?;
                        }
                        Ok(purl)
                    })
                    .ok()
            } else {
                None
            }
        }
        Ecosystem::PyPI => PackageUrl::new("pypi", name).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[test_log::test(rstest)]
    #[case(Ecosystem::CratesIO, "packageurl", Some("pkg:cargo/packageurl"))]
    #[case(
        Ecosystem::Maven(MAVEN_DEFAULT_REPO.to_string()),
        "groupid:artifactid",
        Some("pkg:maven/groupid/artifactid")
    )]
    #[case(
        Ecosystem::Maven("http://other/repo".to_string()),
        "groupid:artifactid",
        Some("pkg:maven/groupid/artifactid?repository_url=http://other/repo")
    )]
    #[case(Ecosystem::PyPI, "aiohttp", Some("pkg:pypi/aiohttp"))]
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
