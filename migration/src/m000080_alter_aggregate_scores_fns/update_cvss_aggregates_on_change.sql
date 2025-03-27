CREATE OR REPLACE FUNCTION update_cvss_aggregates_on_change()
RETURNS trigger AS $$
BEGIN
    -- Update advisory aggregate
    IF NEW.advisory_id IS NOT NULL THEN
        UPDATE advisory SET
            average_score = sub.avg_score,
            average_severity = cvss3_severity(sub.avg_score)
        FROM (
            SELECT AVG(score) AS avg_score
            FROM cvss3
            WHERE advisory_id = NEW.advisory_id
        ) AS sub
        WHERE advisory.id = NEW.advisory_id;
    END IF;

    -- Update vulnerability aggregate
    IF NEW.vulnerability_id IS NOT NULL THEN
        UPDATE vulnerability SET
            average_score = sub.avg_score,
            average_severity = cvss3_severity(sub.avg_score)
        FROM (
            SELECT AVG(score) AS avg_score
            FROM cvss3
            WHERE vulnerability_id = NEW.vulnerability_id
        ) AS sub
        WHERE vulnerability.id = NEW.vulnerability_id;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql
PARALLEL SAFE;

CREATE TRIGGER cvss3_insert_update_trigger
AFTER INSERT OR UPDATE OR DELETE ON cvss3
FOR EACH ROW
EXECUTE FUNCTION update_cvss_aggregates_on_change();