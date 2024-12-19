CREATE OR REPLACE FUNCTION encode_uri_component(text) RETURNS text AS $$
    SELECT string_agg(
        CASE
            WHEN bytes > 1 or c !~ '[0-9a-zA-Z_.!~*''()-]+' THEN
                regexp_replace(encode(convert_to(c, 'utf-8')::bytea, 'hex'), '(..)', E'%\\1', 'g')
            ELSE
                c
            END,
        ''
    )
    FROM (
        SELECT c, octet_length(c) bytes
        FROM regexp_split_to_table($1, '') c
    ) q;
$$ LANGUAGE sql IMMUTABLE STRICT ;

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
                        SELECT string_agg(key || '=' || encode_uri_component(value), '&')
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
