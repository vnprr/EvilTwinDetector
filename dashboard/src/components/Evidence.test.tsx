import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Evidence as EvidenceItem } from "../api/types";
import { Evidence } from "./Evidence";

const storm: EvidenceItem = {
  module: "deauth_storm",
  bssid: "02:de:ad:be:ef:01",
  ssid: "HomeNet",
  strength: 1,
  signal_names: ["broadcast_flood"],
  signals: [{ name: "broadcast_flood", severity: "high", message: "Clients are being disconnected", details: {} }],
  last_seen: 0,
  context: { linked_from: "00:11:22:aa:00:01" },
};

describe("Evidence", () => {
  it("names the detector, each signal with its severity, and where linked evidence came from", () => {
    render(<Evidence items={[storm]} />);
    expect(screen.getByText("Deauth storm")).toBeTruthy();
    expect(screen.getByText("high")).toBeTruthy();
    expect(screen.getByText(/Clients are being disconnected/)).toBeTruthy();
    expect(screen.getByText("00:11:22:aa:00:01")).toBeTruthy();
  });
});
