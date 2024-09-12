UPDATE sbom
SET
    sha256 = source_document.sha256,
    sha384 = source_document.sha384,
    sha512 = source_document.sha512
FROM
    source_document
WHERE
    sbom.source_document_id = source_document.id;
