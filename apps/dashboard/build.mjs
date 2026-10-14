/**
 * esbuild bundler for the Agent Drift dashboard.
 *
 * Vite is not installable in the build environment (the npm registry is blocked by
 * egress policy -- see docs/DECISIONS.md D-004), so esbuild is driven directly. The
 * result is a real production bundle plus a watch mode for development; there is no
 * hidden build step and no CDN dependency at runtime.
 */
import { build, context } from "esbuild";
import { cpSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const outdir = join(here, "dist");
const watch = process.argv.includes("--watch");

mkdirSync(outdir, { recursive: true });

/** Shared esbuild options. */
const options = {
  entryPoints: [join(here, "src", "main.tsx")],
  bundle: true,
  format: "esm",
  target: ["es2022", "chrome120", "firefox120", "safari17"],
  platform: "browser",
  jsx: "automatic",
  sourcemap: true,
  minify: !watch,
  outfile: join(outdir, "app.js"),
  define: { "process.env.NODE_ENV": watch ? '"development"' : '"production"' },
  logLevel: "info",
};

/** Copy static files into dist. */
function copyStatic() {
  cpSync(join(here, "src", "styles.css"), join(outdir, "styles.css"));
  writeFileSync(join(outdir, "index.html"), readFileSync(join(here, "src", "index.html"), "utf8"));
}

copyStatic();

if (watch) {
  const ctx = await context(options);
  await ctx.watch();
  console.log("dashboard: watching for changes");
} else {
  const result = await build(options);
  if (result.errors.length > 0) {
    process.exit(1);
  }
  console.log("dashboard: production bundle written to dist/");
}
