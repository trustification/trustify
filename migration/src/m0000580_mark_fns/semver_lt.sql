create or replace function semver_lt(left_p text, right_p text)
    returns bool
as
$$
declare
    cmp integer;
begin
    cmp := semver_cmp(left_p, right_p);
    return cmp < 0;
end
$$
    language 'plpgsql' immutable parallel safe;
