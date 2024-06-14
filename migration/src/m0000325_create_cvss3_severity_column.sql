
-- Calcuate a CVSS3 score from an *entire* row of the `cvss3` table
create or replace function cvss3_severity(score_p double precision)
    returns cvss3_severity
as
$$
declare
    exploitability decimal;
    iss decimal;
    iss_scoped decimal;
    score decimal;
begin
    if score_p is null then
        return null;
    end if;

    if score_p <= 3.9 then
        return 'low'::"cvss3_severity";
    end if;

    if score_p <= 6.9 then
        return 'medium'::"cvss3_severity";
    end if;

    if score_p <= 8.9 then
        return 'high'::"cvss3_severity";
    end if;

    return 'critical'::"cvss3_severity";
end
$$
    language 'plpgsql';
