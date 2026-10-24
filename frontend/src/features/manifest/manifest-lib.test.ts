import { describe, expect, it } from "vitest";

import { buildManifestFromForm, emptyForm, findSecretKeys } from "./manifest-lib";

describe("manifest client validation", () => {
  it("rejects secret-like keys anywhere in the document", () => {
    expect(findSecretKeys({ psk: "x" })).toEqual(["$.psk"]);
    expect(findSecretKeys({ nested: { private_key: "x" } })).toEqual(["$.nested.private_key"]);
    expect(findSecretKeys({ auth: { secret: "x", session_key: "y" } })).toEqual([
      "$.auth.secret",
      "$.auth.session_key",
    ]);
  });

  it("builds a schema-conformant manifest with capture + run ids", () => {
    const manifest = buildManifestFromForm({ ...emptyForm, testbed_id: "lab-a" }, "capture-1");
    expect(manifest.capture_id).toBe("capture-1");
    expect(manifest.run_id).toBe("unspecified-run");
    expect(manifest.testbed_id).toBe("lab-a");
    expect(manifest.esp?.pfs_enabled).toBe(true);
    expect(findSecretKeys(manifest)).toEqual([]);
  });
});
