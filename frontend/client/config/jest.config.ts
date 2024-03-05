import type { JestConfigWithTsJest } from "ts-jest";

// For a detailed explanation regarding each configuration property, visit:
// https://jestjs.io/docs/en/configuration.html

const config: JestConfigWithTsJest = {
  // Automatically clear mock calls and instances between every test
  clearMocks: true,

  // Indicates whether the coverage information should be collected while executing the test
  collectCoverage: false,

  // The directory where Jest should output its coverage files
  coverageDirectory: "coverage",

  // Stub out resources and provide handling for tsconfig.json paths
  moduleNameMapper: {
    // stub out files that don't matter for tests
    "\\.(css|less)$": "<rootDir>/__mocks__/styleMock.js",
    "\\.(xsd)$": "<rootDir>/__mocks__/styleMock.js",
    "\\.(jpg|jpeg|png|gif|eot|otf|webp|svg|ttf|woff|woff2|mp4|webm|wav|mp3|m4a|aac|oga)$":
      "<rootDir>/__mocks__/fileMock.js",
    "@patternfly/react-icons/dist/esm/icons/":
      "<rootDir>/__mocks__/fileMock.js",

    // match the paths in tsconfig.json
    "@app/(.*)": "<rootDir>/src/app/$1",
    "@assets/(.*)":
      "<rootDir>../node_modules/@patternfly/react-core/dist/styles/assets/$1",
  },

  // A list of paths to directories that Jest should use to search for files
  roots: ["<rootDir>/src"],

  // The test environment that will be used for testing
  testEnvironment: "jest-environment-jsdom",

  // The pattern or patterns Jest uses to find test files
  testMatch: ["<rootDir>/src/**/*.{test,spec}.{js,jsx,ts,tsx}"],

  // Process js/jsx/mjs/mjsx/ts/tsx/mts/mtsx with `ts-jest`
  transform: {
    "^.+\\.(js|mjs|ts|mts)x?$": "ts-jest",
  },

  // Code to set up the testing framework before each test file in the suite is executed
  setupFilesAfterEnv: ["<rootDir>/src/app/test-config/setupTests.ts"],
};

export default config;
