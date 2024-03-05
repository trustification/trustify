import path from "path";
import { Configuration } from "webpack";
import CopyPlugin from "copy-webpack-plugin";
import Dotenv from "dotenv-webpack";
import { TsconfigPathsPlugin } from "tsconfig-paths-webpack-plugin";
import MonacoWebpackPlugin from "monaco-editor-webpack-plugin";

import { brandingAssetPath } from "@trustification-ui/common";
import { LANGUAGES_BY_FILE_EXTENSION } from "./monacoConstants";

const pathTo = (relativePath: string) => path.resolve(__dirname, relativePath);

const brandingPath = brandingAssetPath();
const manifestPath = path.resolve(brandingPath, "manifest.json");

const BG_IMAGES_DIRNAME = "images";

const config: Configuration = {
  entry: {
    app: [pathTo("../src/index.tsx")],
  },

  output: {
    path: pathTo("../dist"),
    publicPath: "auto",
    clean: true,
  },

  module: {
    rules: [
      {
        test: /\.[jt]sx?$/,
        exclude: /node_modules/,
        use: {
          loader: "ts-loader",
          options: {
            transpileOnly: true,
          },
        },
      },
      {
        test: /\.(svg|ttf|eot|woff|woff2)$/,
        // only process modules with this loader
        // if they live under a 'fonts' or 'pficon' directory
        include: [
          pathTo("../../node_modules/patternfly/dist/fonts"),
          pathTo(
            "../../node_modules/@patternfly/react-core/dist/styles/assets/fonts"
          ),
          pathTo(
            "../../node_modules/@patternfly/react-core/dist/styles/assets/pficon"
          ),
          pathTo("../../node_modules/@patternfly/patternfly/assets/fonts"),
          pathTo("../../node_modules/@patternfly/patternfly/assets/pficon"),
        ],
        use: {
          loader: "file-loader",
          options: {
            // Limit at 50k. larger files emited into separate files
            limit: 5000,
            outputPath: "fonts",
            name: "[name].[ext]",
          },
        },
      },
      {
        test: /\.(xsd)$/,
        include: [pathTo("../src")],
        use: {
          loader: "raw-loader",
          options: {
            esModule: true,
          },
        },
      },
      {
        test: /\.svg$/,
        include: (input) => input.indexOf("background-filter.svg") > 1,
        use: [
          {
            loader: "url-loader",
            options: {
              limit: 5000,
              outputPath: "svgs",
              name: "[name].[ext]",
            },
          },
        ],
        type: "javascript/auto",
      },
      {
        test: /\.svg$/,
        // only process SVG modules with this loader if they live under a 'bgimages' directory
        // this is primarily useful when applying a CSS background using an SVG
        include: (input) => input.indexOf(BG_IMAGES_DIRNAME) > -1,
        use: {
          loader: "svg-url-loader",
          options: {},
        },
      },
      {
        test: /\.svg$/,
        // only process SVG modules with this loader when they don't live under a 'bgimages',
        // 'fonts', or 'pficon' directory, those are handled with other loaders
        include: (input) =>
          input.indexOf(BG_IMAGES_DIRNAME) === -1 &&
          input.indexOf("fonts") === -1 &&
          input.indexOf("background-filter") === -1 &&
          input.indexOf("pficon") === -1,
        use: {
          loader: "raw-loader",
          options: {},
        },
        type: "javascript/auto",
      },
      {
        test: /\.(jpg|jpeg|png|gif)$/i,
        include: [
          pathTo("../src"),
          pathTo("../../node_modules/patternfly"),
          pathTo("../../node_modules/@patternfly/patternfly/assets/images"),
          pathTo(
            "../../node_modules/@patternfly/react-styles/css/assets/images"
          ),
          pathTo(
            "../../node_modules/@patternfly/react-core/dist/styles/assets/images"
          ),
          pathTo(
            "../../node_modules/@patternfly/react-core/node_modules/@patternfly/react-styles/css/assets/images"
          ),
          pathTo(
            "../../node_modules/@patternfly/react-table/node_modules/@patternfly/react-styles/css/assets/images"
          ),
          pathTo(
            "../../node_modules/@patternfly/react-inline-edit-extension/node_modules/@patternfly/react-styles/css/assets/images"
          ),
        ],
        use: [
          {
            loader: "url-loader",
            options: {
              limit: 5000,
              outputPath: "images",
              name: "[name].[ext]",
            },
          },
        ],
        type: "javascript/auto",
      },
      {
        test: pathTo("../../node_modules/xmllint/xmllint.js"),
        loader: "exports-loader",
        options: {
          exports: "xmllint",
        },
      },
      {
        test: /\.yaml$/,
        use: "raw-loader",
      },

      // For monaco-editor-webpack-plugin
      {
        test: /\.css$/,
        include: [pathTo("../../node_modules/monaco-editor")],
        use: ["style-loader", "css-loader"],
      },
      {
        test: /\.ttf$/,
        type: "asset/resource",
      },
      // <--- For monaco-editor-webpack-plugin
    ],
  },

  plugins: [
    // new CaseSensitivePathsWebpackPlugin(),
    new Dotenv({
      systemvars: true,
      silent: true,
    }),
    new CopyPlugin({
      patterns: [
        {
          from: manifestPath,
          to: ".",
        },
        {
          from: brandingPath,
          to: "./branding/",
        },
      ],
    }),
    new MonacoWebpackPlugin({
      filename: "monaco/[name].worker.js",
      languages: Object.values(LANGUAGES_BY_FILE_EXTENSION),
    }),
  ],

  resolve: {
    // alias: {
    //   "react-dom": "@hot-loader/react-dom",
    // },
    extensions: [".js", ".ts", ".tsx", ".jsx"],
    plugins: [
      new TsconfigPathsPlugin({
        configFile: pathTo("../tsconfig.json"),
      }),
    ],
    symlinks: false,
    cacheWithContext: false,
    fallback: { crypto: false, fs: false, path: false },
  },

  externals: {
    // required by xmllint (but not really used in the browser)
    ws: "{}",
  },
};

export default config;
