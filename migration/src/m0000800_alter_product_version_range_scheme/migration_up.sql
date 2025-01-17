WITH ranges_to_update AS (
    SELECT version_range.* FROM
    version_range
    JOIN product_version_range ON version_range.id = product_version_range.version_range_id
)
UPDATE version_range
SET version_scheme_id = 'rpm'
FROM ranges_to_update
WHERE version_range.id = ranges_to_update.id