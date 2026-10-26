import type { FormEvent, ReactNode } from "react";
import { useId, useState } from "react";
import { Link } from "react-router";

import { ApiError } from "@/api/client";
import { useAuth } from "@/features/auth/auth-context";

export function LoginPage(): ReactNode {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const emailId = useId();
  const passwordId = useId();
  const errorId = useId();

  async function performLogin(targetEmail: string, targetPass: string): Promise<void> {
    setError(null);
    if (targetEmail.trim() === "" || targetPass === "") {
      setError("Email and password are required.");
      return;
    }
    setSubmitting(true);
    try {
      await login(targetEmail.trim(), targetPass);
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 429) {
        const wait =
          caught.retryAfterSeconds !== null
            ? ` Try again in ${caught.retryAfterSeconds} seconds.`
            : "";
        setError(`Too many sign-in attempts. Please wait before trying again.${wait}`);
      } else if (caught instanceof ApiError && (caught.status === 401 || caught.status === 403)) {
        setError("Invalid credentials or inactive account.");
      } else {
        setError("Sign-in failed. Please check your connection and try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function onSubmit(event: FormEvent): Promise<void> {
    event.preventDefault();
    await performLogin(email, password);
  }

  function handleQuickRole(roleEmail: string): void {
    setEmail(roleEmail);
    setPassword("demo123");
    void performLogin(roleEmail, "demo123");
  }

  return (
    <div className="min-h-screen bg-[#ffffff] text-[#1d1d1f] antialiased selection:bg-[#0071e3] selection:text-[#ffffff]">
      {/* Apple Global Store Navigation Bar — 44px white frosted header */}
      <nav
        aria-label="Landing Navigation"
        className="fixed top-0 left-0 right-0 z-50 flex h-14 items-center justify-between border-b border-[#e6e6e8] bg-white/80 px-6 backdrop-blur-xl md:px-12"
      >
        <Link to="/" className="flex items-center gap-2.5 transition hover:opacity-85">
          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-[#1d1d1f] text-white text-xs font-semibold">
            ⚡
          </span>
          <span className="font-display text-sm font-semibold tracking-tight text-[#1d1d1f]">
            IPsec Analyzer
          </span>
        </Link>

        <div className="hidden items-center gap-8 text-[12px] font-normal text-[#1d1d1f] lg:flex">
          <Link to="/captures" className="hover:text-[#0066cc] transition-colors">
            Inspection
          </Link>
          <Link to="/analyses" className="hover:text-[#0066cc] transition-colors">
            Evidence Engine
          </Link>
          <Link to="/analyses" className="hover:text-[#0066cc] transition-colors">
            Compliance Policy
          </Link>
          <Link to="/dataset" className="hover:text-[#0066cc] transition-colors">
            Benchmark Lab
          </Link>
        </div>

        <div className="flex items-center gap-3">
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#b64400]">
            <span className="h-1.5 w-1.5 rounded-full bg-[#b64400]" />
            Demo Mode
          </span>
          <Link to="/app" className="apple-btn-primary shadow-sm hover:shadow">
            Terminal Access
          </Link>
        </div>
      </nav>

      {/* Hero Product Stage — Pure Apple White Gallery */}
      <section className="relative pt-28 pb-20 md:pt-36 md:pb-28 overflow-hidden bg-[#ffffff]">
        <div className="mx-auto max-w-[1200px] px-6 md:px-12">
          <div className="grid grid-cols-1 items-center gap-12 lg:grid-cols-12 lg:gap-16">
            {/* Left Column: Apple Editorial Typography */}
            <div className="lg:col-span-7">
              <p className="text-xs font-semibold uppercase tracking-wider text-[#707070] mb-3">
                Passive Cryptographic Assessment
              </p>

              <h1 className="font-display text-4xl md:text-6xl lg:text-7xl font-semibold tracking-[-1.2px] text-[#1d1d1f] leading-[1.05]">
                Cryptographic posture. Purely verified.
              </h1>

              <p className="mt-6 text-base md:text-lg text-[#707070] font-normal leading-relaxed max-w-xl">
                Automated cryptographic audit of IKEv2 and ESP network captures. Every transform,
                SPI exchange, lifetime, and threat vector verified directly against packet-observed
                truth — never through epistemic fabrication.
              </p>

              {/* 1-Click Role Instant Profiles */}
              <div className="mt-8">
                <p className="text-xs font-medium text-[#707070] mb-3">Quick Access Profiles</p>
                <div className="flex flex-wrap items-center gap-2.5">
                  <button
                    type="button"
                    onClick={() => handleQuickRole("admin@ipsec.lab")}
                    className="apple-btn-secondary"
                  >
                    <span>🛡️</span>
                    <span>Admin</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleQuickRole("analyst@ipsec.lab")}
                    className="apple-btn-secondary"
                  >
                    <span>🔬</span>
                    <span>Analyst</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleQuickRole("viewer@ipsec.lab")}
                    className="apple-btn-secondary"
                  >
                    <span>👁️</span>
                    <span>Viewer</span>
                  </button>

                  <Link
                    to="/app"
                    className="inline-flex items-center gap-1 text-xs font-medium text-[#0066cc] ml-2 hover:underline"
                  >
                    Direct Terminal Access →
                  </Link>
                </div>
              </div>

              {/* Standards Indicator */}
              <div className="mt-10 border-t border-[#e6e6e8] pt-6 flex flex-wrap items-center gap-6 text-xs text-[#707070]">
                <span>RFC 7296 (IKEv2)</span>
                <span>·</span>
                <span>RFC 4303 (ESP)</span>
                <span>·</span>
                <span>RFC 8221 / 8247</span>
                <span>·</span>
                <span>Zero Cloud Decryption</span>
              </div>
            </div>

            {/* Right Column: Apple 28px Card Sign-In */}
            <div id="signin-card" className="lg:col-span-5">
              <div className="apple-card p-8 md:p-10 shadow-sm">
                <div className="border-b border-[#e6e6e8] pb-4 mb-6">
                  <h2 className="font-display text-xl font-semibold tracking-tight text-[#1d1d1f]">
                    Sign in to Workbench
                  </h2>
                  <p className="mt-1 text-xs text-[#707070]">
                    Enter your credentials or select a quick profile above.
                  </p>
                </div>

                <form
                  onSubmit={(e) => void onSubmit(e)}
                  noValidate
                  className="space-y-4"
                  aria-describedby={error !== null ? errorId : undefined}
                >
                  <div>
                    <label
                      htmlFor={emailId}
                      className="mb-1.5 block text-xs font-medium text-[#1d1d1f]"
                    >
                      Email
                    </label>
                    <input
                      id={emailId}
                      type="email"
                      autoComplete="username"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="e.g. admin@ipsec.lab"
                      className="w-full rounded-xl border border-[#d6d6d6] bg-white px-3.5 py-2.5 text-sm text-[#1d1d1f] placeholder:text-[#86868b] focus:border-[#0071e3] focus:outline-none focus:ring-1 focus:ring-[#0071e3] transition"
                    />
                  </div>

                  <div>
                    <label
                      htmlFor={passwordId}
                      className="mb-1.5 block text-xs font-medium text-[#1d1d1f]"
                    >
                      Password
                    </label>
                    <input
                      id={passwordId}
                      type="password"
                      autoComplete="current-password"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Any password accepted in demo"
                      className="w-full rounded-xl border border-[#d6d6d6] bg-white px-3.5 py-2.5 text-sm text-[#1d1d1f] placeholder:text-[#86868b] focus:border-[#0071e3] focus:outline-none focus:ring-1 focus:ring-[#0071e3] transition"
                    />
                  </div>

                  {error !== null && (
                    <div
                      id={errorId}
                      role="alert"
                      className="rounded-xl border border-red-200 bg-red-50 px-3.5 py-2.5 text-xs text-red-600"
                    >
                      {error}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full cursor-pointer rounded-full bg-[#0071e3] py-3 text-sm font-medium text-white transition hover:bg-[#0077ed] active:scale-[0.99] disabled:opacity-50 shadow-sm"
                  >
                    {submitting ? "Signing in…" : "Sign in"}
                  </button>
                </form>

                <p className="mt-6 text-center text-[11px] text-[#86868b]">
                  Authorized Security Analysts · SHA-256 Validated Session
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Highlights Stage — Studio Mist (#f5f5f7) Feature Band with 28px White Cards */}
      <section className="py-24 bg-[#f5f5f7]">
        <div className="mx-auto max-w-[1200px] px-6 md:px-12">
          <div className="flex flex-wrap items-end justify-between gap-4 mb-12">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-[#707070]">
                Core Architecture
              </p>
              <h2 className="font-display text-3xl md:text-5xl font-semibold tracking-tight text-[#1d1d1f] mt-1">
                Engineered for cryptographic truth.
              </h2>
            </div>
            <Link to="/captures" className="text-sm font-medium text-[#0066cc] hover:underline">
              Inspect testbed captures →
            </Link>
          </div>

          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
            <Link to="/captures" className="apple-card p-7 transition hover:border-[#86868b] block">
              <span className="font-display text-2xl font-semibold text-[#0071e3]">01</span>
              <h3 className="mt-4 font-display text-base font-semibold text-[#1d1d1f]">
                Cipher Extraction
              </h3>
              <p className="mt-2 text-xs text-[#707070] leading-relaxed">
                IKEv2 SA proposals and Child SA transforms are mapped to ENCR, PRF, INTEG, and D-H
                attributes directly from packet traces.
              </p>
              <span className="mt-4 inline-flex items-center gap-1 text-xs font-medium text-[#0066cc]">
                Explore Captures →
              </span>
            </Link>

            <Link to="/analyses" className="apple-card p-7 transition hover:border-[#86868b] block">
              <span className="font-display text-2xl font-semibold text-[#0071e3]">02</span>
              <h3 className="mt-4 font-display text-base font-semibold text-[#1d1d1f]">
                Zero Fabrication
              </h3>
              <p className="mt-2 text-xs text-[#707070] leading-relaxed">
                Unobserved parameters (e.g. ESP tunnels without matching key exchange) are scored as
                unknown — never falsely certified secure.
              </p>
              <span className="mt-4 inline-flex items-center gap-1 text-xs font-medium text-[#0066cc]">
                View Analyses →
              </span>
            </Link>

            <Link to="/dataset" className="apple-card p-7 transition hover:border-[#86868b] block">
              <span className="font-display text-2xl font-semibold text-[#0071e3]">03</span>
              <h3 className="mt-4 font-display text-base font-semibold text-[#1d1d1f]">
                Sandboxed Local
              </h3>
              <p className="mt-2 text-xs text-[#707070] leading-relaxed">
                Local headless TShark parsing with deterministic memory and packet limits. No PCAP
                bytes ever leave your perimeter.
              </p>
              <span className="mt-4 inline-flex items-center gap-1 text-xs font-medium text-[#0066cc]">
                Benchmark Lab →
              </span>
            </Link>

            <Link to="/analyses" className="apple-card p-7 transition hover:border-[#86868b] block">
              <span className="font-display text-2xl font-semibold text-[#0071e3]">04</span>
              <h3 className="mt-4 font-display text-base font-semibold text-[#1d1d1f]">
                Audit Reports
              </h3>
              <p className="mt-2 text-xs text-[#707070] leading-relaxed">
                Generate formal compliance assessments with threat matrix mappings, risk scoring,
                and reproducible evidence chains.
              </p>
              <span className="mt-4 inline-flex items-center gap-1 text-xs font-medium text-[#0066cc]">
                Audit Reports →
              </span>
            </Link>
          </div>
        </div>
      </section>

      {/* Editorial Feature Block — Gallery White (#ffffff) */}
      <section className="py-24 bg-[#ffffff]">
        <div className="mx-auto max-w-[1200px] px-6 md:px-12">
          <div className="apple-card bg-[#f5f5f7] border-0 p-10 md:p-16">
            <div className="max-w-2xl">
              <span className="text-xs font-semibold uppercase tracking-wider text-[#707070]">
                Hardware-Grade Assessment
              </span>
              <h2 className="mt-2 font-display text-3xl md:text-5xl font-semibold tracking-tight text-[#1d1d1f]">
                Cryptographic posture in seconds.
              </h2>
              <p className="mt-4 text-base text-[#707070] leading-relaxed">
                Drop your authorized testbed PCAPs directly into the vault. Immediate dissection of
                SA lifetimes, PFS compliance, and cipher suites without installing intrusive
                endpoint agents.
              </p>
              <div className="mt-8">
                <button
                  type="button"
                  onClick={() => handleQuickRole("admin@ipsec.lab")}
                  className="apple-btn-primary text-sm px-6 py-3"
                >
                  Launch Workbench as Admin →
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Clean Apple Studio Footer */}
      <footer className="border-t border-[#e6e6e8] bg-[#f5f5f7] py-10 text-xs text-[#707070]">
        <div className="mx-auto flex max-w-[1200px] flex-wrap items-center justify-between gap-4 px-6 md:px-12">
          <div className="flex items-center gap-3">
            <span className="font-semibold text-[#1d1d1f]">IPsec Cryptographic Analyzer</span>
            <span>·</span>
            <span>Automated Protocol Assessment Engine</span>
            <span>·</span>
            <span>RFC 7296 / RFC 4303</span>
          </div>

          <div className="flex items-center gap-4">
            <span>Zero Cloud LLM Transmission</span>
            <span>·</span>
            <span className="font-medium text-[#0066cc]">Passive Defense Architecture</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
