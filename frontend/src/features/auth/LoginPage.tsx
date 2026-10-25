import type { FormEvent, ReactNode } from "react";
import { useId, useState } from "react";

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
    <div className="min-h-screen bg-[#090909] text-[#f7f9fa] selection:bg-[#af50ff] selection:text-[#090909]">
      {/* Frosted Nav Bar — dope.security style */}
      <nav
        aria-label="Landing Navigation"
        className="fixed top-0 left-0 right-0 z-50 flex h-16 items-center justify-between border-b border-[#f7f9fa]/10 bg-[rgba(18,16,28,0.75)] px-6 backdrop-blur-md md:px-12"
      >
        <div className="flex items-center gap-3">
          <span className="flex h-2.5 w-2.5 rounded-full bg-[#af50ff] shadow-[0_0_12px_#af50ff]" />
          <span className="font-mono text-sm tracking-[0.2em] font-semibold text-[#f7f9fa]">
            IPSEC // ANALYZER
          </span>
          <span className="hidden rounded-full border border-[#f7f9fa]/15 bg-[rgba(247,249,250,0.04)] px-2.5 py-0.5 text-[10px] uppercase tracking-wider text-[#828384] md:inline-block">
            dope.terminal
          </span>
        </div>

        <div className="hidden items-center gap-8 text-xs uppercase tracking-[0.14em] text-[#828384] lg:flex">
          <span className="hover:text-[#f7f9fa] transition-colors cursor-default">
            SSL / IKE INSPECTION
          </span>
          <span className="hover:text-[#f7f9fa] transition-colors cursor-default">
            PACKET EVIDENCE
          </span>
          <span className="hover:text-[#f7f9fa] transition-colors cursor-default">
            POLICY ENGINE
          </span>
          <span className="hover:text-[#f7f9fa] transition-colors cursor-default">
            BENCHMARK LAB
          </span>
        </div>

        <div className="flex items-center gap-3">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-[#af50ff]/30 bg-[#af50ff]/10 px-3 py-1 text-xs font-mono text-[#e1bdff]">
            <span className="h-1.5 w-1.5 rounded-full bg-[#af50ff] animate-pulse" />
            Demo Mode
          </span>
          <a
            href="#signin-card"
            className="rounded-[8px] border border-[#f7f9fa] bg-[#090909] px-4 py-1.5 text-xs font-medium text-[#f7f9fa] transition hover:bg-[#f7f9fa] hover:text-[#090909]"
          >
            Terminal Access
          </a>
        </div>
      </nav>

      {/* Hero Section with Twilight Violet Bloom */}
      <section className="relative pt-28 pb-20 md:pt-36 md:pb-32 overflow-hidden violet-bloom-hero">
        <div className="mx-auto max-w-[1200px] px-6 md:px-12">
          <div className="grid grid-cols-1 items-start gap-12 lg:grid-cols-12 lg:gap-16">
            {/* Left Column: Editorial Luxury Headline & Product Ethos */}
            <div className="lg:col-span-7 pt-4">
              <div className="mb-4 inline-flex items-center gap-2 font-mono text-xs uppercase tracking-[0.2em] text-[#af50ff]">
                <span>●</span>
                <span>MIDNIGHT TERMINAL // DEFENSIVE INSPECTION</span>
              </div>

              <div className="space-y-1">
                <span className="font-display-italic block text-5xl md:text-7xl font-light text-[#e1bdff] leading-[1.05]">
                  Your new
                </span>
                <h1 className="text-4xl md:text-6xl font-normal tracking-[-0.03em] text-[#f7f9fa] leading-[1.1]">
                  IPsec Cryptographic Analyzer
                </h1>
                <span className="font-display-italic block text-3xl md:text-5xl font-light text-[#828384] pt-1">
                  with automated packet evidence.
                </span>
              </div>

              <p className="mt-8 max-w-xl text-base md:text-lg text-[#828384] font-light leading-relaxed">
                Automated cryptographic audit of IKEv2 and ESP network captures. Every transform,
                SPI exchange, lifetime, and threat vector verified directly against packet-observed
                truth. Unknown evidence is reported as unknown — never as secure.
              </p>

              {/* Stamped letterhead indicator */}
              <div className="mt-10 border-t border-[#f7f9fa]/10 pt-6">
                <p className="font-mono text-xs uppercase tracking-[0.2em] text-[#f0f0f0]">
                  S A N D B O X E D T S H A R K · Z E R O C L O U D L L M
                </p>
                <p className="mt-2 text-xs text-[#828384]">
                  RFC 7296 (IKEv2) · RFC 4303 (ESP) · Strict tenant isolation · Argon2id + HS256
                </p>
              </div>

              {/* Key Capabilities Stamped List */}
              <div className="mt-8 grid grid-cols-2 gap-4 text-xs font-mono text-[#f7f9fa]">
                <div className="rounded-[10.8px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-3">
                  <span className="text-[#af50ff]">01 /</span> IKE SA &amp; CHILD SA CIPHERS
                </div>
                <div className="rounded-[10.8px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-3">
                  <span className="text-[#af50ff]">02 /</span> PERFECT FORWARD SECRECY AUDIT
                </div>
                <div className="rounded-[10.8px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-3">
                  <span className="text-[#af50ff]">03 /</span> INTEGRITY &amp; PRF ALGORITHMS
                </div>
                <div className="rounded-[10.8px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-3">
                  <span className="text-[#af50ff]">04 /</span> RFC 9457 STRUCTURED FINDINGS
                </div>
              </div>
            </div>

            {/* Right Column: Hero Boarding Pass Card */}
            <div id="signin-card" className="lg:col-span-5">
              <div className="relative rounded-[19.2px] border border-[#f7f9fa]/15 bg-[rgba(237,195,196,0.03)] p-8 md:p-10 shadow-[0_0_60px_-15px_rgba(175,80,255,0.2)] backdrop-blur-xl">
                {/* Boarding Pass Header Stamp */}
                <div className="flex items-center justify-between border-b border-[#f7f9fa]/10 pb-4">
                  <div className="flex items-center gap-2">
                    <span className="text-sm">✈</span>
                    <span className="font-mono text-xs uppercase tracking-[0.2em] text-[#f7f9fa]">
                      BOARDING PASS
                    </span>
                  </div>
                  <span className="font-mono text-[11px] text-[#af50ff]">LEGACY → DS</span>
                </div>

                {/* Route Line */}
                <div className="mt-4 flex items-center justify-between font-mono text-[11px] text-[#828384]">
                  <div>
                    <span className="block text-[9px] uppercase tracking-wider text-[#6b6b6b]">
                      ORIGIN
                    </span>
                    <span className="text-[#f7f9fa]">TESTBED PCAP</span>
                  </div>
                  <div className="flex-1 px-4 text-center text-[#af50ff]">-----------------→</div>
                  <div className="text-right">
                    <span className="block text-[9px] uppercase tracking-wider text-[#6b6b6b]">
                      DESTINATION
                    </span>
                    <span className="text-[#f7f9fa]">DEFENSIVE AUDIT</span>
                  </div>
                </div>

                {/* Terminal Title */}
                <div className="mt-6">
                  <h2 className="text-xl font-medium text-[#f7f9fa]">Analyst Terminal Access</h2>
                  <p className="mt-1 text-xs text-[#828384]">
                    Select an instant profile or enter any credentials to enter:
                  </p>
                </div>

                {/* 1-Click Role Ghost Pill Buttons */}
                <div className="mt-5 space-y-2">
                  <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-[#828384]">
                    1-Click Instant Profiles
                  </p>
                  <div className="grid grid-cols-3 gap-2">
                    <button
                      type="button"
                      onClick={() => handleQuickRole("admin@ipsec.lab")}
                      className="group flex flex-col items-center justify-center rounded-[1584px] border border-[#f7f9fa]/10 bg-[rgba(237,195,196,0.05)] py-2.5 px-3 transition hover:border-[#af50ff] hover:bg-[#af50ff]/10"
                    >
                      <span className="text-xs">🛡️</span>
                      <span className="text-[11px] font-medium text-[#f7f9fa] group-hover:text-[#af50ff]">
                        Admin
                      </span>
                    </button>

                    <button
                      type="button"
                      onClick={() => handleQuickRole("analyst@ipsec.lab")}
                      className="group flex flex-col items-center justify-center rounded-[1584px] border border-[#f7f9fa]/10 bg-[rgba(237,195,196,0.05)] py-2.5 px-3 transition hover:border-[#af50ff] hover:bg-[#af50ff]/10"
                    >
                      <span className="text-xs">🔬</span>
                      <span className="text-[11px] font-medium text-[#f7f9fa] group-hover:text-[#af50ff]">
                        Analyst
                      </span>
                    </button>

                    <button
                      type="button"
                      onClick={() => handleQuickRole("viewer@ipsec.lab")}
                      className="group flex flex-col items-center justify-center rounded-[1584px] border border-[#f7f9fa]/10 bg-[rgba(237,195,196,0.05)] py-2.5 px-3 transition hover:border-[#af50ff] hover:bg-[#af50ff]/10"
                    >
                      <span className="text-xs">👁️</span>
                      <span className="text-[11px] font-medium text-[#f7f9fa] group-hover:text-[#af50ff]">
                        Viewer
                      </span>
                    </button>
                  </div>
                </div>

                {/* Credentials Form */}
                <form
                  onSubmit={(e) => void onSubmit(e)}
                  noValidate
                  className="mt-6 space-y-4"
                  aria-describedby={error !== null ? errorId : undefined}
                >
                  <div>
                    <label
                      htmlFor={emailId}
                      className="mb-1 block font-mono text-xs uppercase tracking-wider text-[#828384]"
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
                      className="w-full rounded-[8px] border border-[#f7f9fa]/20 bg-[#090909] px-3.5 py-2.5 text-sm text-[#f7f9fa] placeholder:text-[#474747] focus:border-[#af50ff] focus:outline-none focus:ring-1 focus:ring-[#af50ff] transition"
                    />
                  </div>

                  <div>
                    <label
                      htmlFor={passwordId}
                      className="mb-1 block font-mono text-xs uppercase tracking-wider text-[#828384]"
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
                      placeholder="Any password accepted"
                      className="w-full rounded-[8px] border border-[#f7f9fa]/20 bg-[#090909] px-3.5 py-2.5 text-sm text-[#f7f9fa] placeholder:text-[#474747] focus:border-[#af50ff] focus:outline-none focus:ring-1 focus:ring-[#af50ff] transition"
                    />
                  </div>

                  {error !== null && (
                    <p
                      id={errorId}
                      role="alert"
                      className="rounded-[8px] border border-red-500/40 bg-red-500/10 px-3.5 py-2 text-xs text-red-400 font-mono"
                    >
                      {error}
                    </p>
                  )}

                  {/* Filled Action Button */}
                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full cursor-pointer rounded-[8px] border border-[#f7f9fa] bg-[#090909] py-3 text-sm font-medium text-[#f7f9fa] transition duration-200 hover:bg-[#af50ff] hover:border-[#af50ff] hover:text-[#090909] active:scale-[0.99] disabled:opacity-50"
                  >
                    {submitting ? "Signing in…" : "Sign in"}
                  </button>
                </form>

                {/* Vertical Barcode Graphic at bottom */}
                <div className="mt-6 flex items-center justify-between border-t border-[#f7f9fa]/10 pt-4 font-mono text-[9px] text-[#474747]">
                  <span>HASH-VERIFIED // SHA-256</span>
                  <span className="tracking-[0.18em]">|| | ||| | |||| | || |</span>
                  <span>SESSION: PERSISTENT</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Stamped Section 1: SSL / IPSEC INSPECTION */}
      <section className="border-t border-[#f7f9fa]/10 py-20 bg-[#090909]">
        <div className="mx-auto max-w-[1200px] px-6 md:px-12">
          <p className="font-mono text-3xl md:text-5xl uppercase tracking-[0.2em] text-[#f0f0f0] font-normal leading-tight text-center md:text-left">
            I P S E C I N S P E C T I O N
          </p>
          <p className="mt-3 text-sm text-[#828384] max-w-2xl font-light">
            Every cryptographic assertion is linked to raw network frames. Flight-tested inspection
            rules ensure zero fabricated security conclusions.
          </p>

          {/* 4-Card Comparison Route Block */}
          <div className="mt-14 grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-[19.2px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-6">
              <span className="font-mono text-3xl font-light text-[#af50ff]">01</span>
              <h3 className="mt-4 font-mono text-xs uppercase tracking-[0.14em] text-[#f7f9fa]">
                CIPHER EXTRACTION
              </h3>
              <p className="mt-2 text-xs text-[#828384] leading-relaxed">
                IKEv2 SA proposals and Child SA transforms are mapped to ENCR, PRF, INTEG, and D-H
                attributes directly from packet traces.
              </p>
            </div>

            <div className="rounded-[19.2px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-6">
              <span className="font-mono text-3xl font-light text-[#828384]">02</span>
              <h3 className="mt-4 font-mono text-xs uppercase tracking-[0.14em] text-[#f7f9fa]">
                ZERO FABRICATION
              </h3>
              <p className="mt-2 text-xs text-[#828384] leading-relaxed">
                Unobserved parameters (e.g. ESP tunnels without matching key exchange) are scored as
                unknown — never falsely certified secure.
              </p>
            </div>

            <div className="rounded-[19.2px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-6">
              <span className="font-mono text-3xl font-light text-[#828384]">03</span>
              <h3 className="mt-4 font-mono text-xs uppercase tracking-[0.14em] text-[#f7f9fa]">
                SANDBOXED LOCAL
              </h3>
              <p className="mt-2 text-xs text-[#828384] leading-relaxed">
                Local headless TShark parsing with deterministic memory and packet limits. No PCAP
                bytes ever leave your perimeter.
              </p>
            </div>

            <div className="rounded-[19.2px] border border-[#f7f9fa]/10 bg-[rgba(247,249,250,0.02)] p-6">
              <span className="font-mono text-3xl font-light text-[#828384]">04</span>
              <h3 className="mt-4 font-mono text-xs uppercase tracking-[0.14em] text-[#f7f9fa]">
                AUDIT REPORTS
              </h3>
              <p className="mt-2 text-xs text-[#828384] leading-relaxed">
                Generate formal compliance assessments with threat matrix mappings, risk scoring,
                and reproducible evidence chains.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Violet Bloom Feature Card Block */}
      <section className="py-16 bg-[#090909]">
        <div className="mx-auto max-w-[1200px] px-6 md:px-12">
          <div className="relative rounded-[19.2px] bg-gradient-to-r from-[#af50ff] to-[#7928ca] p-10 md:p-14 text-[#090909] shadow-[0_0_80px_-20px_#af50ff]">
            <div className="max-w-2xl">
              <span className="font-mono text-xs uppercase tracking-[0.2em] font-semibold text-[#090909]/80">
                dope.ipsec // ACCELERATED PASSIVE INSPECTION
              </span>
              <h2 className="mt-2 text-2xl md:text-4xl font-semibold tracking-tight text-[#090909]">
                Hardware-grade cryptographic verification in seconds.
              </h2>
              <p className="mt-3 text-sm md:text-base text-[#090909]/85 leading-relaxed font-normal">
                Drop your authorized testbed PCAPs directly into the vault. Immediate dissection of
                SA lifetimes, PFS compliance, and cipher suites without installing intrusive
                endpoint agents.
              </p>
              <div className="mt-8">
                <button
                  type="button"
                  onClick={() => handleQuickRole("admin@ipsec.lab")}
                  className="rounded-[8px] bg-[#090909] px-6 py-3 font-mono text-xs uppercase tracking-[0.14em] text-[#f7f9fa] shadow-lg transition hover:bg-[#1f1f1f]"
                >
                  Launch Workbench as Admin →
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Coordinate Footer — dope.security signature closing */}
      <footer className="border-t border-[#f7f9fa]/10 py-8 bg-[#090909] text-xs font-mono text-[#828384]">
        <div className="mx-auto flex max-w-[1200px] flex-wrap items-center justify-between gap-4 px-6 md:px-12">
          <div className="flex items-center gap-3">
            <span className="text-[#f7f9fa]">+</span>
            <span className="text-[#f7f9fa]">Fly Direct</span>
            <span>·</span>
            <span>IPsec Cryptographic Analyzer</span>
            <span>·</span>
            <span>RFC 7296 / RFC 4303</span>
          </div>

          <div className="flex items-center gap-4">
            <span className="text-[#f7f9fa]">GPS 37.7749° N, 122.4194° W</span>
            <span>·</span>
            <span>PORT 8000</span>
            <span>·</span>
            <span className="text-[#af50ff]">♥ PASSIVE DEFENSE</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
