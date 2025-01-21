ALTER TABLE "sbom"
ALTER COLUMN "data_licenses" TYPE text[] USING COALESCE("data_licenses", ARRAY[]::text[]),
ALTER COLUMN "data_licenses" SET NOT NULL,
ALTER COLUMN "data_licenses" SET DEFAULT ARRAY[]::text[]