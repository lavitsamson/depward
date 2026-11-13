// Express + Prisma-like fixture server (synthetic packages in ./node_modules).
// Routes: /users (ORM query: fs.promises + crypto + JSON), / (static file stream),
// /health (JSON only).
//   node server.mjs            prints its port, serves until killed (benchmark)
//   node server.mjs <n>        serves n requests from an in-process client, then exits
import { createRequire } from "node:module";
import http from "node:http";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const createApp = require("web-framework");
const { OrmClient } = require("orm-client");
const dir = fileURLToPath(new URL("./data/", import.meta.url));
const orm = new OrmClient(dir);
const file = createApp.static(dir);

const app = createApp()
  .get("/users", async (_req, res) => res.json(await orm.findMany("users")))
  .get("/", (_req, res) => res.sendFile(file("index.html")))
  .get("/health", (_req, res) => res.json({ ok: true, env: app.env }));

const total = Number(process.argv[2] ?? 0);
app.listen(0, async (server) => {
  const { port } = server.address();
  if (total === 0) {
    process.stdout.write(`${port}\n`);
    return;
  }
  const paths = ["/users", "/", "/health"];
  const agent = new http.Agent({ keepAlive: true, maxSockets: 4 });
  for (let i = 0; i < total; i++) {
    await new Promise((resolve, reject) => {
      http.get({ host: "127.0.0.1", port, path: paths[i % 3], agent }, (res) => {
        res.resume();
        res.on("end", () => (res.statusCode === 200 ? resolve() : reject(new Error(`${paths[i % 3]}: ${res.statusCode}`))));
      }).on("error", reject);
    });
  }
  agent.destroy();
  server.close();
});
