CREATE INDEX IF NOT EXISTS advisory_identifier_version_document_id_title
    ON public.advisory USING gin
    (identifier public.gin_trgm_ops, version public.gin_trgm_ops, document_id public.gin_trgm_ops, title public.gin_trgm_ops);