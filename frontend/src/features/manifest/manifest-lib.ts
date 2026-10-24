import type { components } from "@/api/schema";

export type LabManifest = components["schemas"]["LabManifestV1"];

/**
 * Client-side mirror of the backend's structural secret-key rejection.
 * Manifests describe lab configuration only; credentials must never appear.
 */
const SECRET_KEY_PATTERN = /psk|private[_-]?key|secret|password|passwd|token|session[_-]?key/i;

export function findSecretKeys(value: unknown, path = "$"): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((item, i) => findSecretKeys(item, `${path}[${i}]`));
  }
  if (value !== null && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => {
      const hits = SECRET_KEY_PATTERN.test(key) ? [`${path}.${key}`] : [];
      return [...hits, ...findSecretKeys(child, `${path}.${key}`)];
    });
  }
  return [];
}

export interface ManifestFormState {
  testbed_id: string;
  run_id: string;
  ike_version: string;
  mode: string;
  ip_version: string;
  enc: string;
  key_length: string;
  integrity: string;
  prf: string;
  dh_group: string;
  esp_enc: string;
  esp_key_length: string;
  esp_integrity: string;
  esp_aead: boolean;
  pfs_enabled: boolean;
  esp_dh_group: string;
  lifetime: string;
  replay_enabled: boolean;
  replay_window: string;
  traffic_category: string;
  application_label: string;
}

export const emptyForm: ManifestFormState = {
  testbed_id: "",
  run_id: "",
  ike_version: "2",
  mode: "tunnel",
  ip_version: "4",
  enc: "aes-gcm",
  key_length: "256",
  integrity: "none (AEAD)",
  prf: "prf-hmac-sha256",
  dh_group: "19",
  esp_enc: "aes-gcm",
  esp_key_length: "256",
  esp_integrity: "none (AEAD)",
  esp_aead: true,
  pfs_enabled: true,
  esp_dh_group: "19",
  lifetime: "3600",
  replay_enabled: true,
  replay_window: "1024",
  traffic_category: "web",
  application_label: "",
};

function parsePositiveInt(raw: string, field: string): number {
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${field} must be a positive integer.`);
  }
  return value;
}

/** Build a schema-conformant manifest from the guided form (validated). */
export function buildManifestFromForm(form: ManifestFormState, captureId: string): LabManifest {
  if (form.testbed_id.trim() === "") throw new Error("Testbed ID is required.");
  const manifest: LabManifest = {
    schema_version: "1.0",
    testbed_id: form.testbed_id.trim(),
    run_id: form.run_id.trim() === "" ? "unspecified-run" : form.run_id.trim(),
    capture_id: captureId,
    ike_version: parsePositiveInt(form.ike_version, "IKE version"),
    selected_ike: {
      encryption: form.enc.trim(),
      key_length: parsePositiveInt(form.key_length, "IKE key length"),
      integrity: form.integrity.trim(),
      prf: form.prf.trim(),
      dh_group: form.dh_group.trim(),
    },
    mode: form.mode === "transport" ? "transport" : "tunnel",
    ip_version: form.ip_version === "6" ? 6 : 4,
    esp: {
      encryption: form.esp_enc.trim(),
      key_length: parsePositiveInt(form.esp_key_length, "ESP key length"),
      integrity: form.esp_integrity.trim(),
      aead: form.esp_aead,
      dh_group: form.pfs_enabled ? form.esp_dh_group.trim() : null,
      pfs_enabled: form.pfs_enabled,
    },
    configured_sa_lifetime_seconds: parsePositiveInt(form.lifetime, "Configured SA lifetime"),
    replay_protection_enabled: form.replay_enabled,
    replay_window_size: form.replay_enabled
      ? parsePositiveInt(form.replay_window, "Replay window size")
      : null,
    traffic_category: (form.traffic_category || "other") as NonNullable<
      LabManifest["traffic_category"]
    >,
    lab_application_label:
      form.application_label.trim() === "" ? null : form.application_label.trim(),
  };
  const secretHits = findSecretKeys(manifest);
  if (secretHits.length > 0) {
    throw new Error(`Secret-like keys are forbidden in manifests: ${secretHits.join(", ")}`);
  }
  return manifest;
}
