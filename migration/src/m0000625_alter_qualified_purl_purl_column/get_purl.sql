CREATE OR REPLACE FUNCTION get_purl(qualified_purl_id UUID)
RETURNS TEXT AS $$
DECLARE
    result TEXT;
BEGIN
    SELECT
        'pkg://' ||
        CASE
            WHEN qualified_purl.purl->>'ty'  IS NOT NULL THEN
                string_agg(qualified_purl.purl->>'ty' , '')
        END ||
        CASE
            WHEN qualified_purl.purl->>'namespace' IS NOT NULL THEN
                '/' || string_agg(qualified_purl.purl->>'namespace', '') || '/'
            ELSE
                '/'
        END ||
        string_agg(qualified_purl.purl->>'name', '') ||
        CASE
            WHEN qualified_purl.purl->>'version' IS NOT NULL THEN
                 '@' || string_agg(qualified_purl.purl->>'version', '')
            ELSE
                ''
        END ||
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
    WHERE
        qualified_purl.id = qualified_purl_id
    GROUP BY
        qualified_purl.purl,
        qualified_purl.qualifiers;

    IF result IS NULL THEN
        RETURN qualified_purl_id::text;
    ELSE
        RETURN result;
    END IF;
END;
$$ LANGUAGE plpgsql immutable parallel safe;