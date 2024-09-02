create or replace function is_numeric(str text)
    returns bool
as
$$
begin
    return str ~ e'^[0-9]+$';
end

$$
    language 'plpgsql' immutable parallel safe;
