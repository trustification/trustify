CREATE OR REPLACE FUNCTION get_purl(qualified_purl_id UUID)
RETURNS TEXT AS $$
DECLARE
    result TEXT;
BEGIN
    SELECT
        'pkg:' || string_agg(base_purl.type, '') ||
        CASE
            WHEN base_purl.namespace IS NOT NULL THEN
                '/' || string_agg(base_purl.namespace, '') || '/'
            ELSE
                '/'
        END ||
        string_agg(base_purl.name, '') ||
        '@' || string_agg(versioned_purl.version, '') ||
        CASE
            WHEN qualified_purl.qualifiers IS NOT NULL AND qualified_purl.qualifiers <> '{}'::jsonb THEN
                '?' || (
                    SELECT string_agg(key || '=' || value, '&')
                    FROM (
                        SELECT *
                        FROM jsonb_each_text(qualified_purl.qualifiers)
                    ) AS qkey(key, value)
                )
            ELSE
                ''
        END
    INTO result
    FROM
        qualified_purl
        LEFT JOIN versioned_purl ON versioned_purl.id = qualified_purl.versioned_purl_id
        LEFT JOIN base_purl ON base_purl.id = versioned_purl.base_purl_id
    WHERE
        qualified_purl.id = qualified_purl_id
    GROUP BY
        base_purl.type,
        base_purl.namespace,
        base_purl.name,
        versioned_purl.version,
        qualified_purl.qualifiers;

    IF result IS NULL THEN
        RETURN qualified_purl_id::text;
    ELSE
        RETURN result;
    END IF;
END;
$$ LANGUAGE plpgsql immutable parallel safe;
