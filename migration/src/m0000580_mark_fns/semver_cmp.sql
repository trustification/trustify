
create or replace function semver_cmp(left_p text, right_p text)
    returns integer
as
$$
declare
    left_parts text[];
    right_parts text[];

    left_major bigint;
    left_minor bigint;
    left_patch bigint;
    left_pre text;
    left_build text;

    right_major bigint;
    right_minor bigint;
    right_patch bigint;
    right_pre text;
    right_build text;

    left_numeric bool;
    right_numeric bool;

    cur integer;

begin

    raise notice 'semver_cmp % %', left_p, right_p;

    left_parts = regexp_split_to_array(left_p, E'\\+');
    left_build = left_parts[2];

    left_parts = regexp_split_to_array(left_parts[1], E'-');
    left_pre = left_parts[2];

    left_parts = regexp_split_to_array(left_parts[1], E'\\.');
    left_major = left_parts[1]::decimal;
    left_minor = left_parts[2]::decimal;
    left_patch = left_parts[3]::decimal;

    right_parts = regexp_split_to_array(right_p, E'\\+');
    right_build = right_parts[2];

    right_parts = regexp_split_to_array(right_parts[1], E'-');
    right_pre = right_parts[2];

    right_parts = regexp_split_to_array(right_parts[1], E'\\.');
    right_major = right_parts[1]::decimal;
    right_minor = right_parts[2]::decimal;
    right_patch = right_parts[3]::decimal;

    if left_major > right_major then
        return +1;
    elsif left_major < right_major then
        return -1;
    end if;

    if left_minor > right_minor then
        return +1;
    elsif left_minor < right_minor then
        return -1;
    end if;

    if left_patch > right_patch then
        return +1;
    elsif left_patch < right_patch then
        return -1;
    end if;

    if left_pre is null and right_pre is not null then
        return +1;
    elsif left_pre is not null and right_pre is null then
        return -1;
    elsif left_pre is not null and right_pre is not null then
        left_parts = regexp_split_to_array(left_pre, E'\\.');
        right_parts = regexp_split_to_array(right_pre, E'\\.');
        -- do the hard work

        cur := 0;
        loop
            cur := cur + 1;

            left_pre := left_parts[cur];
            right_pre := right_parts[cur];

            if left_pre is null and right_pre is null then
                return 0;
            end if;

            if left_pre is null and right_pre is not null then
                return -1;
            elsif left_pre is not null and right_pre is null then
                return +1;
            end if;

            left_numeric := is_numeric(left_pre);
            right_numeric := is_numeric(right_pre);

            if left_numeric and right_numeric then
                if left_pre::bigint < right_pre::bigint then
                    return -1;
                elsif left_pre::bigint > right_pre::bigint then
                    return +1;
                end if;
            else
                if left_pre < right_pre then
                    return -1;
                elsif left_pre > right_pre then
                    return +1;
                end if;
            end if;

            if cur > 10 then
                exit;
            end if;
        end loop;
    else
        return 0;
    end if;

    return null;
exception
    when others then
        return null;
end
$$
    language 'plpgsql' immutable parallel safe;
