-- we should generate purl jsonb for existing qualified_purl
UPDATE qualified_purl
SET purl = jsonb_build_object(
        'ty', base_purl.type,
        'namespace', base_purl.namespace,
        'name', base_purl.name,
        'version', versioned_purl.version,
        'qualifiers', qualified_purl.qualifiers
           )
FROM versioned_purl
LEFT JOIN base_purl ON base_purl.id = versioned_purl.base_purl_id
WHERE versioned_purl.id = qualified_purl.versioned_purl_id;
