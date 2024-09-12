WITH inserted AS (
  INSERT INTO source_document (sha256, sha384, sha512)
  SELECT sbom.sha256, sbom.sha384, sbom.sha512
  FROM sbom
  RETURNING id, sha256, sha384, sha512
)
UPDATE sbom
SET source_document_id = inserted.id
FROM inserted
WHERE sbom.sha256 = inserted.sha256
AND (sbom.sha384 IS NOT DISTINCT FROM inserted.sha384)
AND (sbom.sha512 IS NOT DISTINCT FROM inserted.sha512);

WITH inserted AS (
  INSERT INTO source_document (sha256, sha384, sha512)
  SELECT advisory.sha256, advisory.sha384, advisory.sha512
  FROM advisory
  RETURNING id, sha256, sha384, sha512
)
UPDATE advisory
SET source_document_id = inserted.id
FROM inserted
WHERE advisory.sha256 = inserted.sha256
AND (advisory.sha384 IS NOT DISTINCT FROM inserted.sha384)
AND (advisory.sha512 IS NOT DISTINCT FROM inserted.sha512);
