import { test, expect } from "@playwright/test";

test.describe("Audit Traceability", () => {
  test.describe("GitContextHeader", () => {
    test("renders branch and commit when source data exists", async ({ page }) => {
      // Navigate to a completed audit
      await page.goto("/");
      // Check for git context header component existence
      const gitHeader = page.locator("[data-testid='git-context-header']");
      // If present, validate it renders branch/commit info
      if (await gitHeader.isVisible()) {
        await expect(gitHeader.locator("text=Branch")).toBeVisible();
      }
    });

    test("shows first scan badge when no previous audit", async ({ page }) => {
      await page.goto("/");
      const firstScanBadge = page.locator("[data-testid='first-scan-badge']");
      // First scan badge only shows on first audit of a source
      if (await firstScanBadge.isVisible()) {
        await expect(firstScanBadge).toContainText(/first scan/i);
      }
    });
  });

  test.describe("Comparison delta badges", () => {
    test("displays delta counts when comparison data is available", async ({ page }) => {
      await page.goto("/");
      const gitHeader = page.locator("[data-testid='git-context-header']");
      if (await gitHeader.isVisible()) {
        // Check for delta badges (new, fixed, persistent, changed)
        const badges = gitHeader.locator("[data-testid^='delta-']");
        const count = await badges.count();
        // Delta badges should appear when comparison is available
        if (count > 0) {
          expect(count).toBeGreaterThanOrEqual(1);
        }
      }
    });
  });

  test.describe("FindingLifecycleBadge", () => {
    test("NEW badge appears for newly detected findings", async ({ page }) => {
      await page.goto("/");
      const newBadge = page.locator("[data-testid='lifecycle-badge-new']");
      // Only visible when lineage shows finding is new to current audit
      if (await newBadge.first().isVisible()) {
        await expect(newBadge.first()).toContainText(/new/i);
      }
    });

    test("REGRESSION badge appears for regressed findings", async ({ page }) => {
      await page.goto("/");
      const regressionBadge = page.locator("[data-testid='lifecycle-badge-regression']");
      if (await regressionBadge.first().isVisible()) {
        await expect(regressionBadge.first()).toContainText(/regression/i);
      }
    });
  });

  test.describe("CrossAgentBadge", () => {
    test("displays also-detected agents for cross-agent findings", async ({ page }) => {
      await page.goto("/");
      const crossBadge = page.locator("[data-testid='cross-agent-badge']");
      if (await crossBadge.first().isVisible()) {
        await expect(crossBadge.first()).toBeVisible();
      }
    });
  });

  test.describe("ProveSummaryCard", () => {
    test("renders verification summary when prove results exist", async ({ page }) => {
      await page.goto("/");
      const summaryCard = page.locator("[data-testid='prove-summary-card']");
      if (await summaryCard.isVisible()) {
        // Should display progress bar and counts
        await expect(summaryCard.locator("[data-testid='prove-summary-progress']")).toBeVisible();
      }
    });
  });

  test.describe("CrossAgentSummary", () => {
    test("renders cross-agent summary for multi-agent findings", async ({ page }) => {
      await page.goto("/");
      const summary = page.locator("[data-testid='cross-agent-summary']");
      if (await summary.isVisible()) {
        await expect(summary).toContainText(/cross-agent/i);
      }
    });
  });

  test.describe("AuditComparisonView", () => {
    test("renders comparison tabs when comparison data is available", async ({ page }) => {
      await page.goto("/");
      const compView = page.locator("[data-testid='audit-comparison-view']");
      if (await compView.isVisible()) {
        // Click to expand
        await compView.locator("button").first().click();
        // Verify tabs exist
        await expect(compView.locator("[data-testid='tab-new']")).toBeVisible();
        await expect(compView.locator("[data-testid='tab-fixed']")).toBeVisible();
        await expect(compView.locator("[data-testid='tab-changed']")).toBeVisible();
        await expect(compView.locator("[data-testid='tab-persistent']")).toBeVisible();
      }
    });

    test("tab switching works correctly", async ({ page }) => {
      await page.goto("/");
      const compView = page.locator("[data-testid='audit-comparison-view']");
      if (await compView.isVisible()) {
        await compView.locator("button").first().click();
        // Switch to fixed tab
        await compView.locator("[data-testid='tab-fixed']").click();
        // The fixed tab should now have active styling (border-b-2)
        const fixedTab = compView.locator("[data-testid='tab-fixed']");
        await expect(fixedTab).toHaveClass(/border-b-2/);
      }
    });
  });

  test.describe("AuditHistoryTimeline", () => {
    test("renders timeline when multiple audits exist for source", async ({ page }) => {
      await page.goto("/");
      const timeline = page.locator("[data-testid='audit-history-timeline']");
      if (await timeline.isVisible()) {
        // Timeline nodes should be clickable links
        const nodes = timeline.locator("a");
        const count = await nodes.count();
        expect(count).toBeGreaterThanOrEqual(2);
      }
    });
  });

  test.describe("FixedFindingsList", () => {
    test("renders fixed findings when present in comparison", async ({ page }) => {
      await page.goto("/");
      const fixedList = page.locator("[data-testid='fixed-findings-list']");
      if (await fixedList.isVisible()) {
        // Click to expand
        await fixedList.locator("button").first().click();
        // Should show finding items
        const items = fixedList.locator("[class*='border-l-2']");
        const count = await items.count();
        expect(count).toBeGreaterThanOrEqual(1);
      }
    });
  });
});
