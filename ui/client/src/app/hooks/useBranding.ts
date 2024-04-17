import { BrandingStrings, brandingStrings } from "@trustify-ui/common";

/**
 * Wrap the branding strings in a hook so components access it in a standard
 * React way instead of a direct import.  This allows the branding implementation
 * to change in future with a minimal amount of refactoring in existing components.
 */
export const useBranding = (): BrandingStrings => {
  return brandingStrings;
};

export default useBranding;
