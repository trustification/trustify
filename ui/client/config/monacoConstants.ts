import { EditorLanguage } from "monaco-editor/esm/metadata";

export const LANGUAGES_BY_FILE_EXTENSION = {
  java: "java",
  go: "go",
  xml: "xml",
  js: "javascript",
  ts: "typescript",
  html: "html",
  htm: "html",
  css: "css",
  yaml: "yaml",
  yml: "yaml",
  json: "json",
  md: "markdown",
  php: "php",
  py: "python",
  pl: "perl",
  rb: "ruby",
  sh: "shell",
  bash: "shell",
} as const satisfies Record<string, EditorLanguage>;
