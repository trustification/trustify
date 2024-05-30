

create or replace function version_matches(version_p text, range_p version_range)
    returns bool
as
$$
declare
begin
    return case
        when range_p.version_scheme_id = 'semver'
            then semver_version_matches(version_p, range_p)
        -- TODO when all other version schemes...
        else
            -- when in doubt, at least try semver....
            semver_version_matches(version_p, range_p)
    end;

end
$$
    language 'plpgsql';
