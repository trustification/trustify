use crate::{
    Error,
    license::{
        get_sanitize_filename,
        model::sbom_license::{ExtractedLicensingInfos, SbomPackageLicense},
    },
};
use core::time::Duration;
use csv::{Writer, WriterBuilder};
use flate2::{Compression, write::GzEncoder};
use tar::Builder;
use trustify_common::purl::Purl;
use trustify_entity::sbom_package_license::LicenseCategory;

type CSVs = (Writer<Vec<u8>>, Writer<Vec<u8>>);

pub struct LicenseExporter {
    sbom_id: String,
    sbom_name: String,
    sbom_license: Vec<SbomPackageLicense>,
    extracted_licensing_infos: Vec<ExtractedLicensingInfos>,
}

impl LicenseExporter {
    pub fn new(
        sbom_id: String,
        sbom_name: String,
        sbom_license: Vec<SbomPackageLicense>,
        extracted_licensing_infos: Vec<ExtractedLicensingInfos>,
    ) -> Self {
        LicenseExporter {
            sbom_id,
            sbom_name,
            sbom_license,
            extracted_licensing_infos,
        }
    }

    pub fn generate(self) -> Result<Vec<u8>, Error> {
        let prefix = get_sanitize_filename(String::from(&self.sbom_name));

        let (wtr_sbom, wtr_license_ref) = self.generate_csvs()?;

        let sbom_csv = wtr_sbom
            .into_inner()
            .map_err(|err| Error::CsvIntoInnerError(format!("csv into inner error: {}", err)))?;
        let license_ref_csv = wtr_license_ref
            .into_inner()
            .map_err(|err| Error::CsvIntoInnerError(format!("csv into inner error: {}", err)))?;

        let mut compressed_data = Vec::new();
        {
            let encoder = GzEncoder::new(&mut compressed_data, Compression::default());

            let mut archive = Builder::new(encoder);

            let mut header = tar::Header::new_gnu();
            header.set_size(sbom_csv.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            header.set_mtime(
                std::time::UNIX_EPOCH
                    .elapsed()
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs(),
            );
            archive.append_data(
                &mut header,
                format!("{prefix}_sbom_licenses.csv"),
                &*sbom_csv,
            )?;

            let mut header = tar::Header::new_gnu();
            header.set_size(license_ref_csv.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            header.set_mtime(
                std::time::UNIX_EPOCH
                    .elapsed()
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs(),
            );
            archive.append_data(
                &mut header,
                format!("{prefix}_license_ref.csv",),
                &*license_ref_csv,
            )?;

            archive.finish()?;
        }
        Ok(compressed_data)
    }

    fn generate_csvs(self) -> Result<CSVs, Error> {
        let mut wtr_sbom = WriterBuilder::new()
            .delimiter(b'\t')
            .quote_style(csv::QuoteStyle::Always)
            .has_headers(true)
            .from_writer(vec![]);

        let mut wtr_license_ref = WriterBuilder::new()
            .delimiter(b'\t')
            .quote_style(csv::QuoteStyle::Always)
            .has_headers(true)
            .from_writer(vec![]);
        wtr_license_ref.write_record(["licenseId", "name", "extracted text", "comment"])?;
        wtr_sbom.write_record([
            "SBOM name",
            "SBOM id",
            "package name",
            "package group",
            "package version",
            "package purl",
            "package cpe",
            "license",
            "license type",
        ])?;

        for extracted_licensing_info in self.extracted_licensing_infos {
            wtr_license_ref.write_record([
                &extracted_licensing_info.license_id,
                &extracted_licensing_info.name,
                &extracted_licensing_info.extracted_text,
                &extracted_licensing_info.comment,
            ])?;
        }

        for package in self.sbom_license {
            let alternate_package_reference = package
                .cpe
                .iter()
                .map(|reference| format!("{}", reference))
                .collect::<Vec<_>>()
                .join("\n");

            let purl_list = package
                .purl
                .into_iter()
                .map(|purl| format!("{}", Purl::from(purl.purl)))
                .collect::<Vec<_>>()
                .join("\n");

            wtr_sbom.write_record([
                &self.sbom_name,
                &self.sbom_id,
                &package.name,
                &package.group.unwrap_or_default(),
                &package.version.unwrap_or_default(),
                &purl_list,
                &alternate_package_reference,
                &package.license_text.unwrap_or_else(String::default),
                &package
                    .license_type
                    .unwrap_or(LicenseCategory::Declared)
                    .to_string(),
            ])?;
        }

        Ok((wtr_sbom, wtr_license_ref))
    }
}
