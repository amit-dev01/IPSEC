import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { FormEvent, ReactNode } from "react";
import { useState } from "react";

import { ApiError, attachManifest, getManifest } from "@/api/client";
import { useToast } from "@/app/toast-context";
import { useAuth } from "@/features/auth/auth-context";
import { RequireAction } from "@/features/auth/guards";

import type { LabManifest, ManifestFormState } from "./manifest-lib";
import { buildManifestFromForm, emptyForm, findSecretKeys } from "./manifest-lib";

export default function ManifestPanel({ captureId }: { captureId: string }): ReactNode {
  const { organizationId } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<ManifestFormState>(emptyForm);
  const [jsonText, setJsonText] = useState("");
  const [editorError, setEditorError] = useState<string | null>(null);

  const manifestQuery = useQuery({
    queryKey: ["org", organizationId, "captures", captureId, "manifest"],
    queryFn: ({ signal }) => getManifest(captureId, { signal }),
    enabled: organizationId !== null && captureId !== "",
    retry: (count, error) => !(error instanceof ApiError && error.status === 404) && count < 1,
  });

  const attachMutation = useMutation({
    mutationFn: (manifest: LabManifest) => attachManifest(captureId, manifest),
    onSuccess: async () => {
      toast.push("success", "Lab manifest attached.");
      await queryClient.invalidateQueries({
        queryKey: ["org", organizationId, "captures", captureId, "manifest"],
      });
    },
    onError: (error: Error) =>
      toast.push("error", error instanceof ApiError ? error.userMessage() : "Attach failed."),
  });

  const set = (key: keyof ManifestFormState, value: string | boolean): void =>
    setForm((f) => ({ ...f, [key]: value }));

  const onFormSubmit = (event: FormEvent): void => {
    event.preventDefault();
    try {
      attachMutation.mutate(buildManifestFromForm(form, captureId));
    } catch (error) {
      toast.push("error", error instanceof Error ? error.message : "Invalid manifest form.");
    }
  };

  const onJsonValidate = (): void => {
    setEditorError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(jsonText) as unknown;
    } catch {
      setEditorError("Invalid JSON — fix syntax before attaching.");
      return;
    }
    const secretHits = findSecretKeys(parsed);
    if (secretHits.length > 0) {
      setEditorError(
        `Secret-like keys are rejected (the backend rejects them too): ${secretHits.join(", ")}. ` +
          "Manifests must never contain PSKs, private keys, or session secrets.",
      );
      return;
    }
    attachMutation.mutate(parsed as LabManifest);
  };

  const inputClass =
    "w-full rounded-full border border-[#d6d6d6] bg-white px-3.5 py-1.5 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3] focus:ring-1 focus:ring-[#0071e3]";

  return (
    <section aria-labelledby="manifest-heading" className="mt-8 space-y-4">
      <div>
        <h2
          id="manifest-heading"
          className="font-display text-lg font-semibold tracking-tight text-[#1d1d1f]"
        >
          Lab Ground Truth Manifest
        </h2>
        <p className="mt-1 max-w-3xl text-xs text-[#707070]">
          Lab manifests are self-reported lab ground truth (
          <strong className="text-[#1d1d1f]">lab_manifest</strong> provenance). They are reconciled
          against packet-observed evidence but{" "}
          <strong className="text-[#1d1d1f]">never overwrite wire observations</strong>. Never
          include PSKs, private keys, or session secrets — such keys are strictly rejected.
        </p>
      </div>

      {manifestQuery.isSuccess && (
        <div className="apple-card p-6 text-xs">
          <p className="font-semibold text-[#1d1d1f]">
            Attached manifest · schema{" "}
            <span className="font-mono text-[#0066cc]">{manifestQuery.data.schema_version}</span> ·
            source {manifestQuery.data.source} · attached {manifestQuery.data.created_at}
          </p>
          <pre className="font-mono mt-3 max-h-64 overflow-auto rounded-[16px] border border-[#e6e6e8] bg-[#fafafc] p-3 text-[11px] text-[#1d1d1f] whitespace-pre-wrap">
            {JSON.stringify(manifestQuery.data.manifest, null, 2)}
          </pre>
        </div>
      )}
      {manifestQuery.isError &&
        manifestQuery.error instanceof ApiError &&
        manifestQuery.error.status === 404 && (
          <p className="text-xs text-[#707070]">No lab manifest attached to this capture yet.</p>
        )}

      <RequireAction action="manifests:edit">
        <div className="apple-card p-6">
          <form onSubmit={onFormSubmit} className="grid gap-3 text-sm md:grid-cols-3">
            <label>
              Testbed ID (required)
              <input
                required
                value={form.testbed_id}
                onChange={(e) => set("testbed_id", e.target.value)}
                className={inputClass}
              />
            </label>
            <label>
              Testbed run ID
              <input
                value={form.run_id}
                onChange={(e) => set("run_id", e.target.value)}
                className={inputClass}
              />
            </label>
            <label>
              IKE version
              <select
                value={form.ike_version}
                onChange={(e) => set("ike_version", e.target.value)}
                className={inputClass}
              >
                <option value="2">IKEv2</option>
                <option value="1">IKEv1</option>
              </select>
            </label>
            <label>
              VPN mode
              <select
                value={form.mode}
                onChange={(e) => set("mode", e.target.value)}
                className={inputClass}
              >
                <option value="tunnel">tunnel</option>
                <option value="transport">transport</option>
              </select>
            </label>
            <label>
              IP version
              <select
                value={form.ip_version}
                onChange={(e) => set("ip_version", e.target.value)}
                className={inputClass}
              >
                <option value="4">IPv4</option>
                <option value="6">IPv6</option>
              </select>
            </label>
            <label>
              Traffic category (lab ground truth)
              <select
                value={form.traffic_category}
                onChange={(e) => set("traffic_category", e.target.value)}
                className={inputClass}
              >
                {["web", "email", "voice", "video", "messaging", "icmp", "other"].map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </label>

            <fieldset className="rounded border border-line p-2 md:col-span-3">
              <legend className="px-1 font-medium">Selected IKE SA configuration</legend>
              <div className="grid gap-2 md:grid-cols-5">
                <label>
                  Encryption
                  <input
                    value={form.enc}
                    onChange={(e) => set("enc", e.target.value)}
                    className={inputClass}
                  />
                </label>
                <label>
                  Key length (bits)
                  <input
                    value={form.key_length}
                    onChange={(e) => set("key_length", e.target.value)}
                    className={inputClass}
                  />
                </label>
                <label>
                  Integrity
                  <input
                    value={form.integrity}
                    onChange={(e) => set("integrity", e.target.value)}
                    className={inputClass}
                  />
                </label>
                <label>
                  PRF
                  <input
                    value={form.prf}
                    onChange={(e) => set("prf", e.target.value)}
                    className={inputClass}
                  />
                </label>
                <label>
                  DH group
                  <input
                    value={form.dh_group}
                    onChange={(e) => set("dh_group", e.target.value)}
                    className={inputClass}
                  />
                </label>
              </div>
            </fieldset>

            <fieldset className="rounded border border-line p-2 md:col-span-3">
              <legend className="px-1 font-medium">ESP configuration (Child SA)</legend>
              <div className="grid gap-2 md:grid-cols-5">
                <label>
                  Encryption
                  <input
                    value={form.esp_enc}
                    onChange={(e) => set("esp_enc", e.target.value)}
                    className={inputClass}
                  />
                </label>
                <label>
                  Key length (bits)
                  <input
                    value={form.esp_key_length}
                    onChange={(e) => set("esp_key_length", e.target.value)}
                    className={inputClass}
                  />
                </label>
                <label>
                  Integrity / HMAC
                  <input
                    value={form.esp_integrity}
                    onChange={(e) => set("esp_integrity", e.target.value)}
                    className={inputClass}
                  />
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.esp_aead}
                    onChange={(e) => set("esp_aead", e.target.checked)}
                  />
                  AEAD cipher
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.pfs_enabled}
                    onChange={(e) => set("pfs_enabled", e.target.checked)}
                  />
                  PFS enabled
                </label>
                <label>
                  PFS DH group
                  <input
                    value={form.esp_dh_group}
                    onChange={(e) => set("esp_dh_group", e.target.value)}
                    className={inputClass}
                  />
                </label>
              </div>
            </fieldset>

            <label>
              Configured SA lifetime (seconds)
              <input
                value={form.lifetime}
                onChange={(e) => set("lifetime", e.target.value)}
                className={inputClass}
              />
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={form.replay_enabled}
                onChange={(e) => set("replay_enabled", e.target.checked)}
              />
              Replay protection enabled
            </label>
            <label>
              Replay window size
              <input
                value={form.replay_window}
                onChange={(e) => set("replay_window", e.target.value)}
                className={inputClass}
              />
            </label>
            <label className="md:col-span-3">
              Lab-only application label (optional; not a vendor claim)
              <input
                value={form.application_label}
                onChange={(e) => set("application_label", e.target.value)}
                className={inputClass}
                placeholder="e.g. synthetic-https-browsing"
              />
            </label>

            <button
              type="submit"
              disabled={attachMutation.isPending}
              className="apple-btn-primary text-xs md:col-span-3"
            >
              Attach Manifest (Form)
            </button>
          </form>
        </div>

        <div className="apple-card p-6 mt-4">
          <label className="text-xs font-semibold text-[#1d1d1f] block" htmlFor="manifest-json">
            …or paste a validated lab manifest JSON document (schema 1.0)
          </label>
          <textarea
            id="manifest-json"
            value={jsonText}
            onChange={(e) => setJsonText(e.target.value)}
            rows={8}
            className="font-mono mt-2 w-full rounded-[16px] border border-[#d6d6d6] bg-[#fafafc] p-3 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
            placeholder='{"schema_version":"1.0","testbed_id":"lab-a","run_id":"run-1","capture_id":"…"}'
          />
          {editorError !== null && (
            <p role="alert" className="mt-2 text-xs text-[#d70015]">
              {editorError}
            </p>
          )}
          <div className="mt-3">
            <button
              type="button"
              onClick={onJsonValidate}
              disabled={attachMutation.isPending}
              className="apple-btn-secondary text-xs"
            >
              Validate JSON &amp; attach
            </button>
          </div>
        </div>
      </RequireAction>
    </section>
  );
}
