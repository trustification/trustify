
create or replace function rpmver_version_matches(version_p text, range_p version_range)
    returns bool
as
$$
declare
    low_end integer;
    high_end integer;
begin
    if range_p.low_version is not null then
        low_end := rpmver_cmp(version_p, range_p.low_version);
    end if;

    if low_end is not null then
        if range_p.low_inclusive then
            if low_end < 0 then
                return false;
            end if;
        else
            if low_end <= 0 then
                return false;
            end if;
        end if;

    end if;


    if range_p.high_version is not null then
        high_end := rpmver_cmp(version_p, range_p.high_version);
    end if;

    if high_end is not null then
        if range_p.high_inclusive then
            if high_end > 0 then
                return false;
            end if;
        else
            if high_end >= 0 then
                return false;
            end if;
        end if;
    end if;

    if low_end is null and high_end is null then
        return false;
    end if;

    return true;

end
$$
    language 'plpgsql' immutable parallel safe;

