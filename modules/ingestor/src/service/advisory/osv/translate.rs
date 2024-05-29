use crate::service::advisory::osv::schema::Ecosystem;
use trustify_common::purl::Purl;

/// try converting a ecosystem/name pair into a purl
pub fn to_purl(ecosystem: &Ecosystem, name: &str) -> Option<Purl> {
    let r#type = to_type(ecosystem)?;

    packageurl::PackageUrl::new(r#type, name)
        .map(Purl::from)
        .ok()
}

fn to_type(ecosystem: &Ecosystem) -> Option<&'static str> {
    Some(match ecosystem {
        Ecosystem::CRAN => "cran",
        _ => return None,
    })
}
