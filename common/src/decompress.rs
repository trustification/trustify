use actix_web::http::header;
use anyhow::anyhow;
use bytes::Bytes;
use tokio::{runtime::Handle, task::JoinError};
use tracing::instrument;
use walker_common::compression::{Compression, DecompressionOptions, Detector};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown compression type")]
    UnknownType,
    #[error(transparent)]
    Detector(anyhow::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("payload too large")]
    PayloadTooLarge,
}

/// Take some bytes, and an optional content-type header and decompress, if required.
///
/// If a content type is present, then it is expected to indicate its compression type by appending
/// it using and extension to the subtype, like `+bz2`. If that's not present, or no content-type
/// is present altogether, then it will try detecting it based on some magic bytes.
///
/// If no magic bytes could be detected, it will assume the content is not compressed.
///
/// **NOTE:** Depending on the size of the payload, this method might take some time. In an async
/// context, it might be necessary to run this as a blocking function, or use [`decompress_async`]
/// instead.
#[instrument(skip(bytes), fields(bytes_len=bytes.len()), err(level=tracing::Level::INFO))]
pub fn decompress(
    bytes: Bytes,
    content_type: Option<header::ContentType>,
    limit: usize,
) -> Result<Bytes, Error> {
    let content_type = content_type.as_ref().map(|ct| ct.as_ref());

    // check what the user has declared

    let declared = content_type.map(|content_type| {
        if content_type.ends_with("+bzip2") {
            Compression::Bzip2
        } else if content_type.ends_with("+xz") {
            Compression::Xz
        } else {
            // The user provided a type, and it doesn't indicate a supported compression type,
            // So we just accept the payload as-is.
            Compression::None
        }
    });

    // otherwise, try to auto-detect

    let compression = match declared {
        Some(declared) => declared,
        None => {
            let detector = Detector::default();
            detector
                .detect(&bytes)
                .map_err(|err| Error::Detector(anyhow!("{err}")))?
        }
    };

    // decompress (or not)

    compression
        .decompress_with(bytes, &DecompressionOptions::default().limit(limit))
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::WriteZero => Error::PayloadTooLarge,
            _ => Error::from(err),
        })
}

/// An async version of [`decompress`].
#[instrument(skip(bytes), fields(bytes_len=bytes.len()), err(level=tracing::Level::INFO))]
pub async fn decompress_async(
    bytes: Bytes,
    content_type: Option<header::ContentType>,
    limit: usize,
) -> Result<Result<Bytes, Error>, JoinError> {
    Handle::current()
        .spawn_blocking(move || decompress(bytes, content_type, limit))
        .await
}

#[cfg(test)]
mod test {
    use crate::decompress::decompress_async;
    use actix_web::http::header::ContentType;
    use test_log::test;
    use trustify_test_context::document_bytes_raw;

    #[test(tokio::test)]
    async fn decompress_none() -> anyhow::Result<()> {
        let bytes = decompress_async(
            document_bytes_raw("ubi9-9.2-755.1697625012.json").await?,
            None,
            0,
        )
        .await??;

        // should decode as JSON

        let _json: serde_json::Value = serde_json::from_slice(&bytes)?;

        // done

        Ok(())
    }

    #[test(tokio::test)]
    async fn decompress_xz() -> anyhow::Result<()> {
        let bytes = decompress_async(
            document_bytes_raw("openshift-container-storage-4.8.z.json.xz").await?,
            None,
            0,
        )
        .await??;

        // should decode as JSON

        let _json: serde_json::Value = serde_json::from_slice(&bytes)?;

        // done

        Ok(())
    }

    #[test(tokio::test)]
    async fn decompress_xz_with_invalid_type() -> anyhow::Result<()> {
        let bytes = decompress_async(
            document_bytes_raw("openshift-container-storage-4.8.z.json.xz").await?,
            Some(ContentType::json()),
            0,
        )
        .await??;

        // should decode as JSON

        let result = serde_json::from_slice::<serde_json::Value>(&bytes);

        // must be an error, as we try to decode a xz encoded payload as JSON.

        assert!(result.is_err());

        // done

        Ok(())
    }

    #[test(tokio::test)]
    async fn decompress_xz_with_invalid_type_2() -> anyhow::Result<()> {
        let result = decompress_async(
            document_bytes_raw("openshift-container-storage-4.8.z.json.xz").await?,
            Some(ContentType("application/json+bzip2".parse().unwrap())),
            0,
        )
        .await?;

        // must be an error, as we indicated bzip2, but provided xz

        assert!(result.is_err());

        // done

        Ok(())
    }

    #[test(tokio::test)]
    async fn decompress_xz_with_correct_type() -> anyhow::Result<()> {
        let bytes = decompress_async(
            document_bytes_raw("openshift-container-storage-4.8.z.json.xz").await?,
            Some(ContentType("application/json+xz".parse().unwrap())),
            0,
        )
        .await??;

        // should decode as JSON

        let _json: serde_json::Value = serde_json::from_slice(&bytes)?;

        // done

        Ok(())
    }
}
