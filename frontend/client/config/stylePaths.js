/* eslint-env node */

import * as path from "path";

export const stylePaths = [
  // Include our sources
  path.resolve(__dirname, "../src"),

  // Include <PF4 paths
  path.resolve(__dirname, "../../node_modules/patternfly"),

  // Include >=PF4 paths, even if nested under another package because npm cannot hoist
  // a single package to the root node_modules/
  /node_modules\/@patternfly\/patternfly/,
  /node_modules\/@patternfly\/react-core\/.*\.css/,
  /node_modules\/@patternfly\/react-styles/,
];
