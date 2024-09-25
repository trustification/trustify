CREATE OR REPLACE FUNCTION update_deprecated_advisory(identifier_input TEXT DEFAULT NULL)
    RETURNS VOID AS
$$
BEGIN
    WITH MostRecent AS (SELECT DISTINCT ON (identifier) id
                        FROM advisory
                        WHERE identifier = COALESCE(identifier_input, identifier)
                        ORDER BY identifier, modified DESC)
    UPDATE advisory
    SET deprecated = CASE
                         WHEN id IN (SELECT id FROM MostRecent) THEN FALSE
                         ELSE TRUE
        END
    WHERE identifier = COALESCE(identifier_input, identifier);
END;
$$ LANGUAGE plpgsql;
