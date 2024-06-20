UPDATE
    sbom
SET location = labels ->> 'source';

UPDATE
    advisory
SET location = labels ->> 'source';
