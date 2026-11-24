"use strict";

const { startFakeDiscord, buildTestApp } = require("./helpers");

(async () => {
  const fake = await startFakeDiscord();
  const t = await buildTestApp({ fake });
  const webhook = fake.addWebhook("Research Vault");
  const enc = t.encrypt(webhook);
  for (let i = 0; i < 23; i++) {
    await t.post("/send", { webhook_url: enc, raw_message: i === 22 ? "Latest: see https://example.com/docs?x=1 for the spec.\nSecond line <script>alert(1)</script>" : `Seed note #${i + 1}` });
  }
  process.stdout.write(JSON.stringify({ base: t.base, webhook }) + "\n");
  process.on("SIGTERM", async () => {
    await t.close();
    await fake.close();
    process.exit(0);
  });
})();
