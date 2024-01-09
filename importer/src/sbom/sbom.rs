use async_trait::async_trait;
use huevos_api::{db::Transactional, system::InnerSystem};
use sbom_walker::{
    retrieve::RetrievedSbom,
    validation::{ValidatedSbom, ValidatedVisitor, ValidationContext, ValidationError},
    Sbom,
};
use sha2::digest::Output;
use sha2::{Digest, Sha256};
use walker_common::{compression::decompress_opt, utils::hex::Hex};

pub struct ProcessVisitor {
    pub system: InnerSystem,
}

#[async_trait(?Send)]
impl ValidatedVisitor for ProcessVisitor {
    type Error = anyhow::Error;
    type Context = ();

    async fn visit_context(&self, _: &ValidationContext) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError>,
    ) -> Result<(), Self::Error> {
        self.store(&result?.retrieved).await?;
        Ok(())
    }
}

impl ProcessVisitor {
    async fn store(&self, doc: &RetrievedSbom) -> Result<(), anyhow::Error> {
        let (data, _compressed) = match decompress_opt(&doc.data, doc.url.path()).transpose()? {
            Some(data) => (data, true),
            None => (doc.data.clone(), false),
        };

        let sha256: String = match doc.sha256.clone() {
            Some(sha) => sha.expected.clone(),
            None => {
                let mut actual = Sha256::new();
                actual.update(&data);
                let digest: Output<Sha256> = actual.finalize();
                Hex(&digest).to_lower()
            }
        };

        if Sbom::try_parse_any(&data).is_ok() {
            println!(
                "Storing: {} (modified: {:?})",
                doc.url, doc.metadata.last_modification
            );

            let sbom = self
                .system
                .ingest_sbom(doc.url.as_ref(), &sha256, Transactional::None)
                .await?;

            sbom.ingest_spdx_data(data.as_ref()).await?;
        }

        Ok(())
    }
}
