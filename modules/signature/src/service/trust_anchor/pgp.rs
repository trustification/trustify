use crate::model::Signature;
use anyhow::bail;
use sequoia_openpgp::{
    Cert, KeyHandle,
    parse::{
        Parse,
        stream::{DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper},
    },
    policy::StandardPolicy,
};
use std::{fs::File, io::Seek, time::SystemTime};
use trustify_entity::signature_type::SignatureType;

#[derive(Debug)]
pub enum Anchor {
    Pgp {
        certificates: Vec<Cert>,
        policy_time: SystemTime,
    },
}

impl Anchor {
    pub async fn validate(
        &self,
        signature: &Signature,
        content: File,
    ) -> Result<(), anyhow::Error> {
        match self {
            Self::Pgp {
                certificates,
                policy_time,
            } => {
                // TODO: proper check, once we have more.
                let SignatureType::Pgp = signature.r#type;

                // TODO: Use ValidCert instead
                for cert in certificates {
                    log::debug!(
                        "Cert: {} (attributes: {})",
                        cert.fingerprint(),
                        cert.user_attributes().len()
                    );
                    for ua in cert.userids() {
                        log::debug!("  @ {}", ua.userid());
                    }
                    for ua in cert.user_attributes() {
                        log::debug!("  - {:?}", ua);
                    }
                }

                validate_pgp(*policy_time, certificates, signature, content).await?;

                Ok(())
            }
        }
    }
}

/// A verify helper for `PublicKey`.
pub struct Helper {
    pub certificates: Vec<Cert>,
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(self.certificates.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        let mut good = false;

        for (i, layer) in structure.into_iter().enumerate() {
            log::trace!("Message ({i}): {layer:?}");

            match (i, layer) {
                (0, MessageLayer::SignatureGroup { results }) => match results.into_iter().next() {
                    Some(Ok(_)) => good = true,
                    Some(Err(err)) => {
                        return Err(sequoia_openpgp::Error::from(err).into());
                    }
                    None => {
                        bail!("No signature");
                    }
                },
                _ => {
                    bail!("Unexpected message structure");
                }
            }
        }

        if !good {
            bail!("Signature verification failed")
        }

        Ok(())
    }
}

async fn validate_pgp(
    policy_time: SystemTime,
    certificates: &[Cert],
    signature: &Signature,
    mut content: File,
) -> Result<(), anyhow::Error> {
    let policy = StandardPolicy::at(policy_time);

    let signature = signature.payload.clone();
    let certificates = certificates.to_vec();

    // the DetachedVerifierBuilder works with std files, which are blocking
    tokio::runtime::Handle::current()
        .spawn_blocking(move || {
            // reset to the beginning, as we have a shared file handle
            content.seek(std::io::SeekFrom::Start(0))?;

            // now verify
            let mut verifier = DetachedVerifierBuilder::from_bytes(&signature)?.with_policy(
                &policy,
                None,
                Helper { certificates },
            )?;

            verifier.verify_reader(content)
        })
        .await??;

    Ok(())
}
