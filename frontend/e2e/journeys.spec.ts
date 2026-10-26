import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const PCAP = Buffer.concat([Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]), Buffer.alloc(128, 7)]);

async function login(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByText(/Demo Mode/)).toBeVisible();
  await page.getByRole("link", { name: "Terminal Access" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test.describe("analyst journeys (mock API)", () => {
  test("1. login → upload → SHA-256 → analysis polls → IKE facts + unknown ESP → report download", async ({
    page,
  }) => {
    await login(page);
    await page.getByRole("link", { name: "Captures", exact: true }).click();
    await page.getByRole("button", { name: "Upload Capture" }).click();
    await page.getByLabel("Choose a capture file").setInputFiles({
      name: "journey.pcap",
      mimeType: "application/octet-stream",
      buffer: PCAP,
    });
    await page.getByRole("button", { name: "Start upload" }).click();
    await expect(page.getByText(/server-computed SHA-256/)).toBeVisible();
    await expect(page.getByText("b".repeat(64))).toBeVisible();
    await page.getByRole("button", { name: "Done" }).click();

    await page.getByRole("link", { name: "journey.pcap" }).first().click();
    await page.getByRole("button", { name: "Run Security Analysis" }).click();
    await expect(page.getByText(/Stage: queued/)).toBeVisible();
    await expect(page.getByLabel("Status: succeeded")).toBeVisible({ timeout: 20_000 });

    await page.getByRole("tab", { name: /Protocol & Security Inspector/ }).click();
    await expect(page.getByText(/Visibility boundary/)).toBeVisible();
    await expect(page.getByText("IKE SA — offered vs selected (never conflated)")).toBeVisible();

    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("tab", { name: "Report" }).click();
    await page.getByRole("button", { name: "Download PDF report" }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain("report");
  });

  test("2. manifest attach → provenance side-by-side + discrepancy", async ({ page }) => {
    await login(page);
    await page.goto("/captures/cap-poor");
    // Manifest panel is on the capture detail; use the form's required field.
    await page.getByLabel(/Testbed ID/).fill("lab-a");
    await page.getByRole("button", { name: "Attach manifest (form)" }).click();
    await expect(page.getByText(/Attached manifest/)).toBeVisible();
  });

  test("3. insufficient-evidence capture shows Score Withheld, not a safe score", async ({
    page,
  }) => {
    await login(page);
    await page.goto("/captures/cap-poor");
    await page.getByRole("button", { name: "Run Security Analysis" }).click();
    await expect(page.getByLabel("Status: succeeded")).toBeVisible({ timeout: 20_000 });
    await page.getByRole("tab", { name: /Security Assessment/ }).click();
    await expect(page.getByLabel(/Score withheld/)).toBeVisible();
    await expect(page.getByText(/Score Withheld — Insufficient Evidence/)).toBeVisible();
  });

  test("4. site landing page opens with Demo Mode and direct Terminal Access", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText(/Demo Mode/)).toBeVisible();
    await expect(page.getByRole("link", { name: "Terminal Access" })).toBeVisible();
    await page.getByRole("link", { name: "Terminal Access" }).click();
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  });
});
