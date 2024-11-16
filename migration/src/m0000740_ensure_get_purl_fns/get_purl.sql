CREATE OR REPLACE FUNCTION get_purl(qualified_purl_id UUID)
RETURNS TEXT AS $$
DECLARE
result TEXT;
BEGIN
SELECT
    COALESCE(
            'pkg:' || bp.type ||
            '/' || COALESCE(bp.namespace, '') || '/' ||
            bp.name ||
            '@' || vp.version ||
            CASE
                WHEN qp.qualifiers IS NOT NULL AND qp.qualifiers <> '{}'::jsonb THEN
                    '?' || (
                        SELECT string_agg(key || '=' || value, '&')
                        FROM jsonb_each_text(qp.qualifiers)
                    )
                ELSE
                    ''
                END,
            qualified_purl_id::text
    )
INTO result
FROM
    qualified_purl qp
        LEFT JOIN versioned_purl vp ON vp.id = qp.versioned_purl_id
        LEFT JOIN base_purl bp ON bp.id = vp.base_purl_id
WHERE
    qp.id = qualified_purl_id;

RETURN result;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE;