CREATE OR REPLACE FUNCTION update_deprecated_advisory(identifier_input TEXT DEFAULT NULL)
    RETURNS VOID AS
$$
BEGIN
    UPDATE advisory
    SET deprecated = (id != (SELECT id
                             FROM advisory a
                             WHERE a.identifier = COALESCE(identifier_input, advisory.identifier)
                             ORDER BY a.modified DESC
                             LIMIT 1))
    WHERE identifier = COALESCE(identifier_input, identifier);
END;
$$ LANGUAGE plpgsql;
