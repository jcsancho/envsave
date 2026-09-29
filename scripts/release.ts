// Cut a release: bump version, test, build, commit, tag, push.
// Pushing the tag triggers .github/workflows/release.yml, which publishes to
// npm via trusted publishing (OIDC).
//
// Usage: bun run release [patch|minor|major|x.y.z]   (default: patch)
import { $ } from "bun";

const arg = process.argv[2] ?? "patch";

if ((await $`git status --porcelain`.text()).trim()) {
  console.error("Working tree is not clean — commit or stash first.");
  process.exit(1);
}
if ((await $`git branch --show-current`.text()).trim() !== "main") {
  console.error("Releases must be cut from main.");
  process.exit(1);
}

const pkgFile = Bun.file("package.json");
const pkg = await pkgFile.json();
const [major, minor, patch] = pkg.version.split(".").map(Number);

let next: string;
if (arg === "patch") next = `${major}.${minor}.${patch + 1}`;
else if (arg === "minor") next = `${major}.${minor + 1}.0`;
else if (arg === "major") next = `${major + 1}.0.0`;
else if (/^\d+\.\d+\.\d+$/.test(arg)) next = arg;
else {
  console.error(`Invalid version argument: ${arg}`);
  process.exit(1);
}

await $`bun test`;
pkg.version = next;
await Bun.write(pkgFile, JSON.stringify(pkg, null, 2) + "\n");
await $`bun run build`;

const tag = `v${next}`;
await $`git commit -am ${`release ${tag}`}`;
await $`git tag ${tag}`;
await $`git push origin main ${tag}`;

console.log(`\nPushed ${tag}. Watch the publish: gh run watch`);
console.log(`Then install: npm install -g @envsave/cli@${next}`);
