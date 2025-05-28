pub use oci_client::Reference;

use crate::runner::common::Error;
use oci_client::{Client as OciClient, secrets::RegistryAuth};

pub struct Client {
    client: OciClient,
    auth: RegistryAuth,
}

impl Client {
    pub fn new() -> Self {
        Self {
            client: OciClient::default(),
            auth: RegistryAuth::Anonymous,
        }
    }

    pub async fn fetch(&self, reference: &Reference) -> Result<Vec<u8>, Error> {
        let mut out: Vec<u8> = Vec::new();
        let (manifest, _) = self
            .client
            .pull_image_manifest(reference, &self.auth)
            .await?;
        // per cosign source, sbom attachments should only have one layer
        self.client
            .pull_blob(reference, &manifest.layers[0], &mut out)
            .await?;
        Ok(out)
    }
}
