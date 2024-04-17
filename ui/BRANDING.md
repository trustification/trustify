# Branding

The UI supports static branding at build time. Dynamically switching brands is not
possible with the current implementation.

## Summary

Each of the project modules need to do some branding enablement.

- `@trustify-ui/common` pulls in the branding assets and packages the configuration,
  strings and assets within the common package. The other modules pull branding
  from the common module.

- `@trustify-ui/client` uses branding from the common package:

  - The location of `favicon.ico`, `manifest.json` and any other branding
    assets that may be referenced in the `brandingStrings` are sourced from the
    common package.

  - The `brandingStrings` are used by the dev-server runtime, to fill out the
    `index.html` template.

  - The about modal and application masthead components use the branding strings
    provided by the common module to display brand appropriate logos, titles and
    about information. Since the common module provides all the information, it
    is packaged directly into the app at build time.

- `@trustify-ui/server` uses the `brandingStrings` from the common package to fill
  out the `index.html` template.

## Providing alternate branding

To provide an alternate branding to the build, specify the path to the branding assets
with the `BRANDING` environment variable. Relative paths in `BRANDING` are computed
from the project source root.

Each brand requires the presence of at least the following files:

- `strings.json`
- `favicon.ico`
- `manifest.json`

With a file path of `/alt/custom-branding`, a build that uses an alternate branding
is run as:

```sh
> BRANDING=/alt/custom-branding npm run build
```

The dev server can also be run this way. Since file watching of the branding assets
is not implemented in the common module's build watch mode, it may be necessary to
manually build the common module before running the dev server. When working on a
brand, it is useful to run the dev server like this:

```sh
> export BRANDING=/alt/custom-branding
> npm run build -w common
> npm run start:dev
> unset BRANDING # when you don't want to use the custom branding path anymore
```

### File details

#### strings.json

The expected shape of `strings.json` is defined in [branding.ts](./common/src/branding.ts).

The default version of the file is [branding/strings.json](./branding/strings.json).

A minimal viable example of the file is:

```json
{
  "application": {
    "title": "Konveyor"
  },
  "about": {
    "displayName": "Konveyor"
  },
  "masthead": {}
}
```

At build time, the json file is processed as an [ejs](https://ejs.co/) template. The
variable `brandingRoot` is provided as the relative root of the branding
assets within the build of the common module. Consider the location of `strings.json`
in your branding directory as the base `brandingRoot` when creating a new brand.

For example, to properly reference a logo within this branding structure:

```
  special-brand/
    images/
      masthead-logo.svg
      about-logo.svg
    strings.json
```

Use a url string like this:

```json
{
  "about": {
    "imageSrc": "<%= brandingRoot %>/images/about-logo.svg"
  }
}
```

and in the output of `BRANDING=special-brand npm run build -w common`, the `imageSrc`
will be `branding/images/about-logo.svg` with all of the files in `special-branding/*`
copied to and available to the client and server modules from
`@trustify-ui/common/branding/*`.

#### favicon.ico

A standard favorite icon file `favicon.ico` is required to be in the same directory
as `strings.json`

#### manifest.json

A standard [web app manifest](https://developer.mozilla.org/en-US/docs/Web/Manifest)
file `manifest.json` is required to be in the same directory as `strings.json`.

## Technical details

All branding strings and assets are pulled in to the common module. The client and
server modules access the branding from the common module build.

The `common` module relies on rollup packaging to embed all of the brand for easy
use. The use of branding strings in `client` and `server` modules is straight forward.
Pulling in `strings.json` and providing the base path to the brand assets is a
more complicated.

The `common` module provides the `brandingAssetPath()` function to let the build time
code find the root path to all brand assets. Webpack configuration files use this
function to source the favicon.ico, manifest.json and other brand assets to be copied
to the application bundle.

The `brandingStrings` is typed and sourced from a json file. To pass typescript builds,
a stub json file needs to be available at transpile time. By using a typescript paths
of `@branding/strings.json`, the stub json is found at transpile time. The generated
javascript will still import the path alias. The
[virtual rollup plugin](https://github.com/rollup/plugins/tree/master/packages/virtual)
further transform the javascript output by replacing the `@branding/strings.json` import
with a dynamically built module containing the contents of the brand's `strings.json`.
The brand json becomes a virtual module embedded in the common module.

A build for a custom brand will fail (1) if the expected files cannot be read, or (2)
if `strings.json` is not a valid JSON file. **Note:** The context of `stings.json` is
not currently validated. If something is missing or a url is malformed, it will only
be visible as a runtime error.
