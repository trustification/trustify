CREATE OR REPLACE FUNCTION public.mavenver_cmp(left_p text, right_p text) RETURNS integer
    LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
    AS $_$
declare
left_parts text[];
    right_parts text[];

    left_major bigint;
    left_minor bigint;
    left_revision bigint;
    left_qualifier_or_build text;
    left_qualifier text;
    left_build bigint;

    left_cardinality integer;

    right_major bigint;
    right_minor bigint;
    right_revision bigint;
    right_qualifier_or_build text;
    right_qualifier text;
    right_build bigint;

    right_cardinality integer;

    left_numeric bool;
    right_numeric bool;

    cur integer;

begin
    left_qualifier_or_build = substring(left_p, E'-\\S+$');

    left_parts = regexp_split_to_array(substring(left_p, E'^[^-]+'), E'\\.');
    left_major = left_parts[1]::bigint;
    left_minor = coalesce(left_parts[2]::bigint, 0);
    left_revision = coalesce(left_parts[3]::bigint, 0);

    right_qualifier_or_build = substring(right_p, E'-\\S+$');

    right_parts = regexp_split_to_array(substring(right_p, E'^[^-]+'), E'\\.');
    right_major = right_parts[1]::bigint;
    right_minor = coalesce(right_parts[2]::bigint, 0);
    right_revision = coalesce(right_parts[3]::bigint, 0);

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

    if left_revision > right_revision then
        return +1;
    elsif left_revision < right_revision then
        return -1;
end if;

    left_cardinality := greatest(cardinality(left_parts), 3);
    right_cardinality := greatest(cardinality(right_parts), 3);

    if left_cardinality > right_cardinality then
        return +1;
    elsif left_cardinality < right_cardinality then
        return -1;
end if;

    if left_qualifier_or_build is null and right_qualifier_or_build is null then
        return 0;
end if;

    if left_qualifier_or_build is null then
        return +1;
end if;

    if right_qualifier_or_build is null then
        return -1;
end if;

    left_numeric := is_numeric(left_qualifier_or_build);
    right_numeric := is_numeric(left_qualifier_or_build);

    if left_numeric and right_numeric then
        left_build = left_qualifier_or_build::bigint;
        right_build = right_qualifier_or_build::bigint;
        if left_build < right_build then
            return -1;
        elseif left_build > right_build then
            return +1;
else
            return 0;
end if;
end if;

    left_qualifier = lower(left_qualifier_or_build);
    right_qualifier = lower(right_qualifier_or_build);

    if left_qualifier < right_qualifier then
        return -1;
    elsif left_qualifier > right_qualifier then
        return +1;
end if;

return 0;
exception
    when others then
        return null;
end
$_$;
