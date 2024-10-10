-- this is just an exact version match
create or replace function generic_version_matches(version_p text, range_p version_range)
    returns bool
as
$$
begin
    if range_p.low_version is not null then
        if range_p.low_inclusive then
            if version_p = range_p.low_version then
                return true;
            end if;
        end if;
    end if;

    if range_p.high_version is not null then
        if range_p.high_inclusive then
            if version_p = range_p.high_version  then
                return true;
            end if;
        end if;
    end if;

    return false;

end
$$
    language plpgsql immutable;

