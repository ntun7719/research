const { chromium } = require("playwright");
const fs = require("fs");

const base = process.env.LATTICE_URL || "http://127.0.0.1:18080";
const password = process.env.LATTICE_PASSWORD || "integration-password-2468";

(async () => {
  fs.mkdirSync("artifacts", { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });

  await page.goto(base, { waitUntil: "networkidle" });
  await page.locator("#password").fill(password);
  await page.locator("#auth-form button[type=submit]").click();
  await page.waitForSelector("#shell:not(.hidden)");
  await page.waitForSelector("#page-dashboard.active");

  const navLabels = await page.locator(".nav-item").allTextContents();
  for (const expected of ["Dashboard", "Query Log", "Blocking", "DNS Settings", "Private DNS", "System"]) {
    if (!navLabels.some(text => text.includes(expected))) throw new Error("Missing nav item: " + expected);
  }

  if (!(await page.locator("#queries-total").isVisible())) throw new Error("Dashboard stats are not visible");
  await page.screenshot({ path: "artifacts/dashboard-desktop.png", fullPage: true });

  await page.locator('#sidebar .nav-item[data-page="blocking"]').click();
  await page.waitForSelector("#page-blocking.active");
  if (!(await page.locator("#category-grid").isVisible())) throw new Error("Protection categories are not visible");
  if (!(await page.locator("#feed-form").isVisible())) throw new Error("Blocklist form is not visible");
  await page.screenshot({ path: "artifacts/blocking-desktop.png", fullPage: true });

  await page.locator('#sidebar .nav-item[data-page="dns"]').click();
  await page.waitForSelector("#page-dns.active");
  if (!(await page.locator("#upstream-editor").isVisible())) throw new Error("Upstream editor is not visible");

  await page.locator('#sidebar .nav-item[data-page="private"]').click();
  await page.waitForSelector("#page-private.active");
  if (!(await page.locator("#private-hostname").isVisible())) throw new Error("Private DNS hostname field is not visible");
  if (!(await page.locator("#issue-cert").isVisible())) throw new Error("Certificate action is not visible");

  await page.locator('#sidebar .nav-item[data-page="system"]').click();
  await page.waitForSelector("#page-system.active");
  if (!(await page.locator("#privacy-mode").isVisible())) throw new Error("Privacy settings are not visible");
  if (!(await page.locator("#config-editor").isHidden())) throw new Error("Advanced JSON editor should be collapsed by default");

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(base, { waitUntil: "networkidle" });
  await page.waitForSelector("#shell:not(.hidden)");
  if (!(await page.locator("#open-nav").isVisible())) throw new Error("Mobile menu button is not visible");
  await page.locator("#open-nav").click();
  if (!(await page.locator("#sidebar.open").isVisible())) throw new Error("Mobile navigation did not open");
  await page.screenshot({ path: "artifacts/dashboard-mobile.png", fullPage: true });

  await browser.close();
  console.log("UI smoke passed");
})().catch(error => {
  console.error(error);
  process.exit(1);
});
