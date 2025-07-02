--
-- Name: golang_version_matches(text, public.version_range); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.golang_version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    norm_version text := version_p;
BEGIN
    -- Strip leading 'v' from version_p if present
    IF version_p LIKE 'v%' THEN
        norm_version := substring(version_p FROM 2);
    END IF;

    RETURN semver_version_matches(norm_version, range_p);
END
$$;



--
-- Name: version_matches(text, public.version_range); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.version_matches(version_p text, range_p public.version_range) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
declare
begin
    -- for an authoritative list of support schemes, see the enum
    -- `trustify_entity::version_scheme::VersionScheme`
    return case
        when range_p.version_scheme_id = 'git'
            -- Git is git, and hard.
            then gitver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'semver'
            -- Semver is semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'gem'
            -- RubyGems claims to be semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'npm'
            -- NPM claims to be semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'golang'
            -- Golang claims to be semver
            then golang_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'nuget'
            -- NuGet claims to be semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'generic'
            -- Just check if it is equal
            then generic_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'rpm'
            -- Look at me! I'm an RPM! I'm special!
            then rpmver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'maven'
            -- Look at me! I'm a Maven! I'm kinda special!
            then maven_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'python'
            -- Python versioning
            then python_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'packagist'
            -- Packagist PHP strongly encourages semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'hex'
            -- Erlang Hex claims to be semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'swift'
            -- Swift Package Manager claims to be semver
            then semver_version_matches(version_p, range_p)
        when range_p.version_scheme_id = 'pub'
            -- Pub Dart Flutter claims to be semver
            then semver_version_matches(version_p, range_p)
        else
            false
    end;
end
$$;