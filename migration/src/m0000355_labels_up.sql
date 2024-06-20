UPDATE
    sbom
SET labels = json_build_object('source', location);

UPDATE
    advisory
SET labels = json_build_object('source', location);
