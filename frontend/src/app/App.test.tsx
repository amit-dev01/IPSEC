import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import App from "@/app/App";
import { SeverityBadge, SourceBadge } from "@/components/badges";

describe("application smoke test", () => {
  it("renders the login screen when unauthenticated", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "IPsec Analyzer" })).toBeInTheDocument();
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByText(/held in memory only/)).toBeInTheDocument();
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
