import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import App from "@/app/App";
import { SeverityBadge, SourceBadge } from "@/components/badges";

describe("application smoke test", () => {
  it("opens into the dope.security landing page with Demo Mode and Terminal Access", async () => {
    render(<App />);
    expect(await screen.findByText(/Demo Mode/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Terminal Access" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /🛡️.*Admin/ })).toBeInTheDocument();
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();

    await userEvent.setup().click(screen.getByRole("link", { name: "Terminal Access" }));
    expect(await screen.findByRole("navigation", { name: "Primary" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
  });

  it("renders provenance and severity badges with text labels (never color-only)", () => {
    render(
      <>
        <SourceBadge source="packet_observed" />
        <SourceBadge source="unknown" />
        <SeverityBadge severity="high" />
      </>,
    );
    expect(screen.getByLabelText("Source: Packet-observed")).toHaveTextContent("Packet-observed");
    expect(screen.getByLabelText("Source: Unknown")).toHaveTextContent("Unknown");
    expect(screen.getByLabelText("Severity: High")).toHaveTextContent("High");
  });
});
