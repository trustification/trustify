

create or replace function version_matches(version_p text, range_p version_range)
    returns bool
as
$$
declare
begin
    raise notice '%', range_p;
    return case
        when range_p.version_scheme_id = 'semver'
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'generic'
            then semver_version_matches(version_p, range_p)
        -- TODO when all other version schemes...
        else
            -- semver_version_matches(version_p, range_p)
            FALSE
    end;

end
$$
    language 'plpgsql';
