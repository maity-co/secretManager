import { build } from "esbuild";
import { mkdir, copyFile } from "node:fs/promises";
await mkdir("dist", { recursive: true });
await build({
  entryPoints: ["web/app.jsx"],
  bundle: true,
  minify: true,
  sourcemap: false,
  outdir: "dist",
  target: ["es2022"],
  define: { "process.env.NODE_ENV": '"production"' },
});
await copyFile("web/index.html", "dist/index.html");
