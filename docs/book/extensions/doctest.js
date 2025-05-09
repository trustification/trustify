"use strict";

const assert = require("node:assert");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const axios = require("axios");

const $contentClassified = "contentClassified";
const $info = "info";
const $listing = "listing";
const $name = "name";
const $skip = "skip";
const $strict = "strict";
const $test = "test";
const $timeout = "timeout";
const $topdir = path.join(__dirname, "../../..");

const oneOf = (val, choices) => choices.filter((item) => val === item).pop();

const ISSUER_URL =
  process.env.ISSUER_URL ?? "http://localhost:8090/realms/chicken";
const TRUST_ID = process.env.TRUST_ID ?? "testing-manager";
const TRUST_SECRET =
  process.env.TRUST_SECRET ?? "R8A6KFeyxJsMDBhjfHbpZTIF0GWt43HP";
const BOMBASTIC_URL = process.env.BOMBASTIC_URL ?? "http://localhost:8082";
const TRUSTIFY_URL = process.env.TRUSTIFY_URL ?? "http://localhost:8080";
const TEST_MODE =
  oneOf(process.env.TEST_MODE, [$info, $skip, $strict]) ?? $skip;
const TEST_TIMEOUT = process.env.TEST_TIMEOUT ?? "30000";
const RETRY_LIMIT = parseInt(process.env.RETRY_LIMIT ?? "5");

class TokenProvider {
  constructor(issuerURL, clientId, clientSecret) {
    this.issuerURL = issuerURL;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.token = null;
  }

  async requestToken(timeout, force) {
    if (!force && !!this.token) return this.token;
    const response = await axios({
      baseURL: this.issuerURL,
      url: "/protocol/openid-connect/token",
      method: "post",
      timeout,
      data: {
        client_id: this.clientId,
        client_secret: this.clientSecret,
        grant_type: "client_credentials",
      },
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });
    return (this.token = response.data.access_token);
  }

  async injectToken(config, refreshToken) {
    await this.requestToken(config.timeout ?? 0, refreshToken);
    return {
      ...config,
      headers: {
        ...config.headers,
        Authorization: `Bearer ${this.token}`,
      },
    };
  }
}

const axiosInstance = (baseURL, timeout, provider) => {
  const instance = axios.create({
    baseURL,
    timeout,
  });

  instance.interceptors.request.use(
    async (config) => (await provider?.injectToken(config, false)) ?? config,
    (error) => Promise.reject(error)
  );

  instance.interceptors.response.use(
    (response) => response,
    async (error) => {
      if (error.response && error.response.status == 401) {
        const retryCounter = error.config.retryCounter || 1;
        const retryConfig =
          (await provider?.injectToken(error.config, true)) ?? error.config;

        if (retryCounter < RETRY_LIMIT) {
          return axios({
            ...retryConfig,
            retryCounter: retryCounter + 1,
          });
        }
      }
      return Promise.reject(error);
    }
  );

  return instance;
};

class Test {
  constructor(snippet, numid, config) {
    this.numid = numid;
    this.source = snippet.getSource();
    this.location = snippet.getSourceLocation();
    this.name = snippet.getAttribute($name, `#${this.numid}`);
    this.config = config;
    this.timeout = parseInt(snippet.getAttribute($timeout, TEST_TIMEOUT));
  }

  async run() {
    const { providers } = this.config;
    const context = {
      topdir: $topdir,
      bombastic: axiosInstance(BOMBASTIC_URL, this.timeout, providers.v1),
      trustify: axiosInstance(TRUSTIFY_URL, this.timeout, providers.v2),
      assert,
      console,
      crypto,
      fs,
      path,
      JSON,
    };
    vm.createContext(context);

    try {
      console.log(
        "Running test %s%s",
        this.name,
        this.location
          ? ` at ${this.location.getFile()}:${this.location.getLineNumber()}`
          : ""
      );
      await vm.runInContext(this.source, context, {
        filename: this.location?.getFile() ?? "evalmachine.<anonymous>",
        lineOffset: this.location?.getLineNumber() ?? 0,
        timeout: this.timeout,
      });
    } catch (error) {
      console.error("Test %s has failed. Error:\n%s\n", this.name, error);
      return false;
    }
    console.log("Test %s has passed", this.name);
    return true;
  }

  toString() {
    return (
      "==== Test ====\n" +
      `| File: ${this.location?.getFile()}\n` +
      `| Line number: ${this.location?.getLineNumber()}\n` +
      `| Timeout: ${this.timeout}\n` +
      "--------\n" +
      `${this.source}\n` +
      "--------\n"
    );
  }
}

class Doctest {
  static register() {
    return new Doctest(this);
  }

  constructor(generatorContext) {
    if (TEST_MODE === $skip) return;
    this.config = {
      providers: {
        v1: new TokenProvider(ISSUER_URL, TRUST_ID, TRUST_SECRET),
        v2: null,
      },
    };
    this.tests = [];
    this.result = true;
    (this.context = generatorContext).once(
      $contentClassified,
      this.onContentClassified.bind(this)
    );
  }

  onContentClassified({ siteAsciiDocConfig, contentCatalog }) {
    contentCatalog.getPages((page) => {
      const { loadAsciiDoc } = this.context.getFunctions();
      const scopedAsciiDocConfig = contentCatalog.getComponentVersion(
        page.src.component,
        page.src.version
      ).asciidoc;
      const doc = loadAsciiDoc(
        page,
        contentCatalog,
        scopedAsciiDocConfig || siteAsciiDocConfig
      );
      doc.findBy({ context: $listing }).forEach((item) => {
        if (item.isOption($test)) {
          const numid = this.tests.length + 1;
          this.tests.push(new Test(item, numid, this.config).run());
        }
      });
    });

    Promise.all(this.tests)
      .then((results) => {
        this.result = results.every((result) => !!result);
      })
      .catch((error) => console.error(error))
      .then(() => {
        if (TEST_MODE === $strict && !this.result) this.context.stop(1);
      });
  }
}

module.exports = Doctest;
