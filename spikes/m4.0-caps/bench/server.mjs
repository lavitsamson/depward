// Express + Prisma-like fixture server. Prints its port, then serves until killed.
// Routes: /users (orm query via fs.promises + crypto + JSON), / (static file stream),
// /health (JSON only).
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(new URL("../app/", import.meta.url));
const createApp = require("web-framework");
const { OrmClient } = require("orm-client");
const dir = fileURLToPath(new URL("../app/data/", import.meta.url));
const orm = new OrmClient(dir);
const file = createApp.static(dir);

const app = createApp()
  .get("/users", async (_req, res) => res.json(await orm.findMany("users")))
  .get("/", (_req, res) => res.sendFile(file("index.html")))
  .get("/health", (_req, res) => res.json({ ok: true, env: app.env }));

app.listen(0, (server) => process.stdout.write(`${server.address().port}\n`));
