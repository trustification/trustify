export interface MastheadBrand {
  src: string;
  alt: string;
  height: string;
}

export interface MastheadTitle {
  text: string;
  heading?: "h1" | "h2" | "h3" | "h4" | "h5" | "h6";
  size?: "md" | "lg" | "xl" | "2xl" | "3xl" | "4xl";
}

export interface BrandingStrings {
  application: {
    title: string;
    name?: string;
    description?: string;
  };

  about: {
    displayName: string;
    imageSrc?: string;
    documentationUrl?: string;
  };

  masthead: {
    leftBrand?: MastheadBrand;
    leftTitle?: MastheadTitle;
    rightBrand?: MastheadBrand;
  };
}

// Note: Typescript will look at the `paths` definition to resolve this import
//       to a stub JSON file.  In the next rollup build step, that import will
//       be replaced by the rollup virtual plugin with a dynamically generated
//       JSON import with the actual branding information.
import * as stringsJson from "@branding/strings.json";

export const brandingStrings =
  stringsJson.default as unknown as BrandingStrings;

/**
 * Return the `node_modules/` resolved path for the branding assets.
 */
export const brandingAssetPath = () =>
  require
    .resolve("@trustification-ui/common/package.json")
    .replace(/(.)\/package.json$/, "$1") + "/dist/branding";
