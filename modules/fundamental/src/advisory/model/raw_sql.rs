pub const SEARCH_LABELS_SQL: &str = r#"
SELECT DISTINCT ON (kv.key, kv.value)
    kv.key,
    CASE
        WHEN kv.value IS NULL OR kv.value = '' THEN NULL
        ELSE kv.value
    END AS value
FROM advisory,
    LATERAL jsonb_each_text(labels) AS kv
WHERE
    CASE 
        WHEN kv.value IS NULL THEN kv.key
        ELSE kv.key || '=' || kv.value
    END ILIKE $1
ORDER BY
    kv.key, kv.value
"#;
