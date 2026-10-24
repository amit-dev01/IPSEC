import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import App from "@/app/App";
import { SeverityBadge, SourceBadge } from "@/components/badges";

describe("application smoke test", () => {
  it("opens directly into the app in Demo Mode (no login screen)", async () => {
    render(<App />);
    expect(await screen.findByText(/Demo Mode/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Email")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
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
