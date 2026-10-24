import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ConfidenceMeter, FrameReferenceList, ProvenanceBadge, UnknownValue } from "./epistemic";

describe("epistemic primitives", () => {
  it("labels provenance and encrypted visibility non-color-only", () => {
    render(<ProvenanceBadge source="unknown" visibility="encrypted_or_unavailable" />);
    expect(screen.getByLabelText("Source: Unknown")).toBeInTheDocument();
    expect(screen.getByLabelText(/Encrypted \/ not observable/)).toBeInTheDocument();
  });

  it("distinguishes protocol confidence from ML probability", () => {
    render(
      <>
        <ConfidenceMeter value={0.9} kind="protocol" />
        <ConfidenceMeter value={0.87} kind="ml_traffic" />
      </>,
    );
    expect(screen.getByText(/Protocol-evidence confidence \(deterministic\)/)).toBeInTheDocument();
    expect(screen.getByText(/calibrated probability/)).toBeInTheDocument();
    expect(screen.getByText(/not payload inspection/)).toBeInTheDocument();
  });

  it("renders unknown explicitly, never N/A or a pass", () => {
    render(<UnknownValue reason="ESP payloads are encrypted." />);
    const el = screen.getByText(/Unknown\./);
    expect(el.textContent).not.toMatch(/N\/A|None|Secure/);
    expect(screen.getByText(/ESP payloads are encrypted/)).toBeInTheDocument();
  });

  it("lists frame references in mono chips", () => {
    render(<FrameReferenceList frames={[{ frame: 3 }, { frame: 7 }]} />);
    expect(screen.getByLabelText("Packet frame references")).toBeInTheDocument();
    expect(screen.getByText("#3")).toBeInTheDocument();
    expect(screen.getByText("#7")).toBeInTheDocument();
  });
});
