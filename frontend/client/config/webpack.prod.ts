import path from "path";
import merge from "webpack-merge";
import webpack, { Configuration } from "webpack";
import MiniCssExtractPlugin from "mini-css-extract-plugin";
import CssMinimizerPlugin from "css-minimizer-webpack-plugin";
import HtmlWebpackPlugin from "html-webpack-plugin";

import { brandingAssetPath } from "@trustification-ui/common";
import { stylePaths } from "./stylePaths";
import commonWebpackConfiguration from "./webpack.common";

const pathTo = (relativePath: string) => path.resolve(__dirname, relativePath);
const faviconPath = path.resolve(brandingAssetPath(), "favicon.ico");

const config = merge<Configuration>(commonWebpackConfiguration, {
  mode: "production",
  devtool: "nosources-source-map", // used to map stack traces on the client without exposing all of the source code
  output: {
    filename: "[name].[contenthash:8].min.js",
    chunkFilename: "js/[name].[chunkhash:8].min.js",
    assetModuleFilename: "assets/[name].[contenthash:8][ext]",
  },

  optimization: {
    minimize: true,
    minimizer: [
      "...", // The '...' string represents the webpack default TerserPlugin instance
      new CssMinimizerPlugin(),
    ],
  },

  module: {
    rules: [
      {
        test: /\.css$/,
        include: [...stylePaths],
        use: [MiniCssExtractPlugin.loader, "css-loader"],
      },
    ],
  },

  plugins: [
    new MiniCssExtractPlugin({
      filename: "[name].[contenthash:8].css",
      chunkFilename: "css/[name].[chunkhash:8].min.css",
    }),
    new CssMinimizerPlugin({
      minimizerOptions: {
        preset: ["default", { mergeLonghand: false }],
      },
    }),
    new webpack.EnvironmentPlugin({
      NODE_ENV: "production",
    }),

    // index.html generated at runtime via the express server to inject `_env`
    new HtmlWebpackPlugin({
      filename: "index.html.ejs",
      template: `!!raw-loader!${pathTo("../public/index.html.ejs")}`,
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
});

export default config;
