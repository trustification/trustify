
create or replace function rpmver_cmp(a text, b text)
    returns integer as $$
declare
    a_segments varchar[];
    b_segments varchar[];
    a_len integer;
    b_len integer;
    a_seg varchar;
    b_seg varchar;
begin
    if a = b then return 0; end if;
    a_segments := array(select (regexp_matches(a, '(\\d+|[a-za-z]+|[~^])', 'g'))[1]);
    b_segments := array(select (regexp_matches(b, '(\\d+|[a-za-z]+|[~^])', 'g'))[1]);
    a_len := array_length(a_segments, 1);
    b_len := array_length(b_segments, 1);
    for i in 1..coalesce(least(a_len, b_len) + 1, 0) loop
        a_seg = a_segments[i];
        b_seg = b_segments[i];
        if a_seg ~ '^\\d' then
            if b_seg ~ '^\\d' then
                a_seg := ltrim(a_seg, '0');
                b_seg := ltrim(b_seg, '0');
                case
                    when length(a_seg) > length(b_seg) then return 1;
                    when length(a_seg) < length(b_seg) then return -1;
                    else null; -- equality -> fallthrough to string comparison
                end case;
            else
                return 1;
            end if;
        elsif b_seg ~ '^\\d' then
            return -1;
        elsif a_seg = '~' then
            if b_seg != '~' then
                return -1;
            end if;
        elsif b_seg = '~' then
            return 1;
        elsif a_seg = '^' then
            if b_seg != '^' then
                return 1;
            end if;
        elsif b_seg = '^' then
            return -1;
        end if;
        if a_seg != b_seg then
            if a_seg < b_seg then return -1; else return 1; end if;
        end if;
    end loop;
    if b_segments[a_len + 1] = '~' then return 1; end if;
    if a_segments[b_len + 1] = '~' then return -1; end if;
    if b_segments[a_len + 1] = '^' then return -1; end if;
    if a_segments[b_len + 1] = '^' then return 1; end if;
    if a_len > b_len then return 1; end if;
    if a_len < b_len then return -1; end if;
    return 0;
end $$
language plpgsql immutable parallel safe;