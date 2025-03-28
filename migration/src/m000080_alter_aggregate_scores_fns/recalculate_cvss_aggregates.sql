CREATE OR REPLACE FUNCTION recalculate_cvss_aggregates()
RETURNS void AS $$
BEGIN
    -- Update advisories
    UPDATE advisory SET
        average_score = sub.avg_score,
        average_severity = cvss3_severity(sub.avg_score)
    FROM (
        SELECT advisory_id, AVG(score) AS avg_score
        FROM cvss3
        GROUP BY advisory_id
    ) AS sub
    WHERE advisory.id = sub.advisory_id;

    -- Update vulnerabilities
    UPDATE vulnerability SET
        average_score = sub.avg_score,
        average_severity = cvss3_severity(sub.avg_score)
    FROM (
        SELECT vulnerability_id, AVG(score) AS avg_score
        FROM cvss3
        GROUP BY vulnerability_id
    ) AS sub
    WHERE vulnerability.id = sub.vulnerability_id;
END;
$$ LANGUAGE plpgsql;

SELECT recalculate_cvss_aggregates();