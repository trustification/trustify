import path from "path";
import { mergeWithRules } from "webpack-merge";
import type { Configuration as WebpackConfiguration } from "webpack";
import type { Configuration as DevServerConfiguration } from "webpack-dev-server";
import CopyPlugin from "copy-webpack-plugin";
import HtmlWebpackPlugin from "html-webpack-plugin";
import ReactRefreshTypeScript from "react-refresh-typescript";
import ReactRefreshWebpackPlugin from "@pmmmwh/react-refresh-webpack-plugin";
import ForkTsCheckerWebpackPlugin from "fork-ts-checker-webpack-plugin";

import {
  encodeEnv,
  TRUSTIFICATION_ENV,
  SERVER_ENV_KEYS,
  proxyMap,
  brandingStrings,
  brandingAssetPath,
} from "@trustification-ui/common";
import { stylePaths } from "./stylePaths";
import commonWebpackConfiguration from "./webpack.common";

const pathTo = (relativePath: string) => path.resolve(__dirname, relativePath);
const faviconPath = path.resolve(brandingAssetPath(), "favicon.ico");

interface Configuration extends WebpackConfiguration {
  devServer?: DevServerConfiguration;
}

const devServer: DevServerConfiguration = {
  port: 3000,
  historyApiFallback: {
    disableDotRule: true,
  },
  hot: true,
  proxy: proxyMap,
};

const config: Configuration = mergeWithRules({
  module: {
    rules: {
      test: "match",
      use: {
        loader: "match",
        options: "replace",
      },
    },
  },
})(commonWebpackConfiguration, {
  mode: "development",
  devtool: "eval-source-map",
  output: {
    filename: "[name].js",
    chunkFilename: "js/[name].js",
    assetModuleFilename: "assets/[name][ext]",
  },

  devServer,

  module: {
    rules: [
      {
        test: /\.[jt]sx?$/,
        exclude: /node_modules/,
        use: {
          loader: "ts-loader",
          options: {
            transpileOnly: true, // HMR in webpack-dev-server requires transpileOnly
            getCustomTransformers: () => ({
              before: [ReactRefreshTypeScript()],
            }),
          },
        },
      },
      {
        test: /\.css$/,
        include: [...stylePaths],
        use: ["style-loader", "css-loader"],
      },
    ],
  },

  plugins: [
    new ReactRefreshWebpackPlugin(),
    new ForkTsCheckerWebpackPlugin({
      typescript: {
        mode: "readonly",
      },
    }),
    new CopyPlugin({
      patterns: [
        {
          from: pathTo("../public/mockServiceWorker.js"),
        },
      ],
    }),

    // index.html generated at compile time to inject `_env`
    new HtmlWebpackPlugin({
      filename: "index.html",
      template: pathTo("../public/index.html.ejs"),
      templateParameters: {
        _env: encodeEnv(TRUSTIFICATION_ENV, SERVER_ENV_KEYS),
        branding: brandingStrings,
      },
      favicon: faviconPath,
      minify: {
        collapseWhitespace: false,
        keepClosingSlash: true,
        minifyJS: true,
        removeEmptyAttributes: true,
        removeRedundantAttributes: true,
      },
    }),
  ],

  watchOptions: {
    // ignore watching everything except @trustification-ui packages
    ignored: /node_modules\/(?!@trustification-ui\/)/,
  },
} as Configuration);
export default config;
