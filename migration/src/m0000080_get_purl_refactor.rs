use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "
                    CREATE OR REPLACE FUNCTION public.get_purl(qualified_purl_id uuid)
                    RETURNS text
                    LANGUAGE sql IMMUTABLE PARALLEL SAFE
                    AS $$
                        SELECT
                            COALESCE(
                                'pkg:'
                                || COALESCE(purl ->> 'ty','')
                                || '/' || COALESCE(purl ->> 'namespace','')
                                || '/' || COALESCE(purl ->> 'name','')
                                || '@' || COALESCE(purl ->> 'version','')
                                || COALESCE(
                                    '?' || string_agg(key || '=' || encode_uri_component(value), '&')
                                    FILTER (WHERE qualifiers IS NOT NULL AND qualifiers <> '{}'::jsonb),
                                    ''
                                ),
                                qualified_purl_id::text
                            )
                        FROM qualified_purl
                        LEFT JOIN LATERAL jsonb_each_text(qualifiers) AS qualifiers(key, value)
                          ON TRUE
                        WHERE id = qualified_purl_id
                        GROUP BY purl, qualifiers;
                    $$;
                ",
            )
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "
                    CREATE OR REPLACE FUNCTION public.get_purl(qualified_purl_id uuid) RETURNS text
                        LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
                        AS $$
                    DECLARE
                    result TEXT;
                    BEGIN
                    SELECT
                        COALESCE(
                                'pkg:' || bp.type ||
                                '/' || COALESCE(bp.namespace, '') || '/' ||
                                bp.name ||
                                '@' || vp.version ||
                                CASE
                                    WHEN qp.qualifiers IS NOT NULL AND qp.qualifiers <> '{}'::jsonb THEN
                                        '?' || (
                                            SELECT string_agg(key || '=' || encode_uri_component(value), '&')
                                            FROM jsonb_each_text(qp.qualifiers)
                                        )
                                    ELSE
                                        ''
                                    END,
                                qualified_purl_id::text
                        )
                    INTO result
                    FROM
                        qualified_purl qp
                            LEFT JOIN versioned_purl vp ON vp.id = qp.versioned_purl_id
                            LEFT JOIN base_purl bp ON bp.id = vp.base_purl_id
                    WHERE
                        qp.id = qualified_purl_id;

                    RETURN result;
                    END;
                    $$;
            ")
            .await
            .map(|_| ())?;
        Ok(())
    }
}
