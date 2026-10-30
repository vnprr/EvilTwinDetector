import { describe, expect, it } from "vitest";
import { age, byVerdict, dbm, ppm, score, ssidLabel } from "./format";

describe("format", () => {
  it("shows scores out of 100, never as a percentage", () => {
    expect(score(0.865)).toBe("87/100");
    expect(score(0)).toBe("0/100");
  });

  it("formats radio values and missing data", () => {
    expect(dbm(-45.4)).toBe("-45 dBm");
    expect(dbm(null)).toBe("–");
    expect(ppm(21)).toBe("+21.0 ppm");
    expect(ppm(-7.51)).toBe("-7.5 ppm");
    expect(ssidLabel("")).toBe("<hidden>");
  });

  it("describes ages in the largest sensible unit", () => {
    expect(age(30)).toBe("30 s");
    expect(age(600)).toBe("10 min");
    expect(age(7200)).toBe("2 h");
    expect(age(null)).toBe("unknown");
  });

  it("sorts the most serious verdict first", () => {
    const aps = [{ status: "clean" }, { status: "evil_twin" }, { status: "info" }] as const;
    expect([...aps].sort(byVerdict).map((ap) => ap.status)).toEqual(["evil_twin", "info", "clean"]);
  });
});
