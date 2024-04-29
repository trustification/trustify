
create or replace function qualified_package_transitive(sbom_id_param integer, start_package_id uuid, relationships_param integer[])
    returns table (
        left_package_id uuid,
        right_package_id uuid
    )
as $$
    begin

        return query
        with recursive transitive as (
            select
                package_relates_to_package.left_package_id,
                package_relates_to_package.right_package_id,
                package_relates_to_package.relationship,
                package_relates_to_package.sbom_id
            from
                package_relates_to_package
            where
                package_relates_to_package.right_package_id = start_package_id
                and package_relates_to_package.relationship = any(relationships_param)
                and package_relates_to_package.sbom_id = sbom_id_param
            union
            select
                prp.left_package_id,
                prp.right_package_id,
                prp.relationship,
                prp.sbom_id
            from
                package_relates_to_package prp
            inner join transitive transitive1
                on
                    prp.right_package_id = transitive1.left_package_id
                    and prp.relationship = any(relationships_param)
                    and prp.sbom_id = transitive1.sbom_id
        )
        select
            transitive.left_package_id,
            transitive.right_package_id
        from
            transitive;
    end;
$$

language 'plpgsql';
