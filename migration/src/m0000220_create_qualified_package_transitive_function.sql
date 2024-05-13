
create or replace function qualified_package_transitive(sbom_id_param uuid, start_package_id uuid, relationships_param integer[])
    returns table (
        left_package_id uuid,
        right_package_id uuid
    )
as $$
begin

    return query
    select
        left_id.qualified_package_id,
        right_id.qualified_package_id
    from (
        select
            node_id
        from
            sbom_package_purl_ref AS source
        where
            source.qualified_package_id = start_package_id
            and
            source.sbom_id = sbom_id_param
    ) AS t

     cross join lateral package_transitive(sbom_id_param, t.node_id, relationships_param) as result
     join sbom_package_purl_ref as left_id
            on
                left_id.node_id = result.left_node_id
                and left_id.sbom_id = sbom_id_param
     join sbom_package_purl_ref as right_id
            on
                right_id.node_id = result.right_node_id
                and right_id.sbom_id = sbom_id_param
    ;

end
$$

language 'plpgsql';

create or replace function package_transitive(sbom_id_param uuid, start_node_id text, relationships_param integer[])
    returns table (
        left_node_id text,
        right_node_id text
    )
as $$
    begin

        return query
        with recursive transitive as (
            select
                package_relates_to_package.left_node_id,
                package_relates_to_package.right_node_id,
                package_relates_to_package.relationship,
                package_relates_to_package.sbom_id
            from
                package_relates_to_package
            where
                package_relates_to_package.right_node_id = start_node_id
                and package_relates_to_package.relationship = any(relationships_param)
                and package_relates_to_package.sbom_id = sbom_id_param
            union
            select
                prp.left_node_id,
                prp.right_node_id,
                prp.relationship,
                prp.sbom_id
            from
                package_relates_to_package prp
                    inner join transitive transitive1
                        on
                            prp.right_node_id = transitive1.left_node_id
                            and prp.relationship = any(relationships_param)
                            and prp.sbom_id = transitive1.sbom_id
        )
        select
            cast(transitive.left_node_id as text),
            cast(transitive.right_node_id as text)
        from
            transitive;
end;
$$

language 'plpgsql';
