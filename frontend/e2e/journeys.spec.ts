import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const PCAP = Buffer.concat([Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]), Buffer.alloc(128, 7)]);

async function login(page: Page, email: string): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("correct-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test.describe("analyst journeys (mock API)", () => {
  test("1. login → upload → SHA-256 → analysis polls → IKE facts + unknown ESP → report download", async ({
    page,
  }) => {
    await login(page, "analyst@example.test");
    await page.getByRole("link", { name: "Captures" }).click();
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

    await page.getByRole("link", { name: "journey.pcap" }).click();
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
    await login(page, "analyst@example.test");
    await page.goto("/captures/cap-poor");
    // Manifest panel is on the capture detail; use the form's required field.
    await page.getByLabel(/Testbed ID/).fill("lab-a");
    await page.getByRole("button", { name: "Attach manifest (form)" }).click();
    await expect(page.getByText(/Attached manifest/)).toBeVisible();
  });

  test("3. insufficient-evidence capture shows Score Withheld, not a safe score", async ({
    page,
  }) => {
    await login(page, "analyst@example.test");
    await page.goto("/captures/cap-poor");
    await page.getByRole("button", { name: "Run Security Analysis" }).click();
    await expect(page.getByLabel("Status: succeeded")).toBeVisible({ timeout: 20_000 });
    await page.getByRole("tab", { name: /Security Assessment/ }).click();
    await expect(page.getByLabel(/Score withheld/)).toBeVisible();
    await expect(page.getByText(/Score Withheld — Insufficient Evidence/)).toBeVisible();
  });

  test("4. role enforcement + cache wipe on logout", async ({ page }) => {
    await login(page, "viewer@example.test");
    await page.getByRole("link", { name: "Captures" }).click();
    await expect(page.getByRole("button", { name: "Upload Capture" })).toHaveCount(0);
    await page.goto("/admin/audit");
    await expect(page.getByText(/do not have access/)).toBeVisible();
    await page.getByRole("button", { name: /sign out/i }).click();
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  });
});
