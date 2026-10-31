/**
 * Syntax highlighting for the message and file panes.
 *
 * highlight.js escapes the source before tokenising, so the HTML it returns is safe to
 * inject — none of a body's own markup can execute. The registered languages cover what a
 * tester actually reads: web bodies (JSON/HTML/XML/JS/TS/CSS) and the source, config and
 * decompiled code met when pentesting Android, iOS and desktop apps (Java, Kotlin, Smali-
 * adjacent, Swift, Objective-C, C#, C/C++, Go, Rust, Python, Ruby, PHP, shell, SQL, YAML,
 * .properties, Gradle/Groovy, plists, Dockerfiles, INI). Large bodies are left un-
 * highlighted: colouring megabytes stalls the pane for no gain, and the raw text still reads.
 */

import hljs from "highlight.js/lib/core";
import javascript from "highlight.js/lib/languages/javascript";
import typescript from "highlight.js/lib/languages/typescript";
import json from "highlight.js/lib/languages/json";
import xml from "highlight.js/lib/languages/xml";
import css from "highlight.js/lib/languages/css";
import java from "highlight.js/lib/languages/java";
import kotlin from "highlight.js/lib/languages/kotlin";
import swift from "highlight.js/lib/languages/swift";
import objectivec from "highlight.js/lib/languages/objectivec";
import csharp from "highlight.js/lib/languages/csharp";
import cpp from "highlight.js/lib/languages/cpp";
import c from "highlight.js/lib/languages/c";
import go from "highlight.js/lib/languages/go";
import rust from "highlight.js/lib/languages/rust";
import python from "highlight.js/lib/languages/python";
import ruby from "highlight.js/lib/languages/ruby";
import php from "highlight.js/lib/languages/php";
import bash from "highlight.js/lib/languages/bash";
import sql from "highlight.js/lib/languages/sql";
import yaml from "highlight.js/lib/languages/yaml";
import properties from "highlight.js/lib/languages/properties";
import groovy from "highlight.js/lib/languages/groovy";
import dockerfile from "highlight.js/lib/languages/dockerfile";
import ini from "highlight.js/lib/languages/ini";

import type { BodyLang } from "./beautify";

const LANGS: [string, Parameters<typeof hljs.registerLanguage>[1]][] = [
  ["javascript", javascript],
  ["typescript", typescript],
  ["json", json],
  ["xml", xml], // also covers HTML and plists
  ["css", css],
  ["java", java],
  ["kotlin", kotlin],
  ["swift", swift],
  ["objectivec", objectivec],
  ["csharp", csharp],
  ["cpp", cpp],
  ["c", c],
  ["go", go],
  ["rust", rust],
  ["python", python],
  ["ruby", ruby],
  ["php", php],
  ["bash", bash],
  ["sql", sql],
  ["yaml", yaml],
  ["properties", properties],
  ["groovy", groovy],
  ["dockerfile", dockerfile],
  ["ini", ini],
];
for (const [name, def] of LANGS) hljs.registerLanguage(name, def);

const MAX = 200_000;

/** Map a detected body language to the highlight.js grammar that renders it. */
const HLJS_LANG: Record<Exclude<BodyLang, null>, string> = {
  json: "json",
  html: "xml",
  xml: "xml",
  plist: "xml",
  js: "javascript",
  ts: "typescript",
  css: "css",
  java: "java",
  kotlin: "kotlin",
  swift: "swift",
  objc: "objectivec",
  csharp: "csharp",
  cpp: "cpp",
  c: "c",
  go: "go",
  rust: "rust",
  python: "python",
  ruby: "ruby",
  php: "php",
  bash: "bash",
  sql: "sql",
  yaml: "yaml",
  properties: "properties",
  groovy: "groovy",
  dockerfile: "dockerfile",
  ini: "ini",
};

/** Highlighted HTML for the body, or null to render it as plain text. */
export function highlightCode(text: string, lang: BodyLang): string | null {
  if (!lang || text.length > MAX) return null;
  try {
    return hljs.highlight(text, { language: HLJS_LANG[lang], ignoreIllegals: true }).value;
  } catch {
    return null;
  }
}
