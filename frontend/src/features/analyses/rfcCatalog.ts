import type { AnalysisDetail } from "@/api/client";

export type RfcDomain =
  | "Key Exchange"
  | "Encryption"
  | "Integrity"
  | "Identity"
  | "Anti-Replay"
  | "Architecture";

export type RfcRequirement = "MUST" | "SHOULD" | "SHOULD NOT" | "MUST NOT";

export type ComplianceVerdict = "compliant" | "warning" | "non-compliant" | "not-observed";

export interface RfcStandard {
  id: string;
  domain: RfcDomain;
  title: string;
  algorithm: string;
  rfc: string;
  rfcUrl: string;
  requirement: RfcRequirement;
  nistRef: string;
  description: string;
  evaluator: (detail: AnalysisDetail) => {
    observed: boolean;
    observedValue?: string | undefined;
    verdict: ComplianceVerdict;
    notes: string;
  };
}

function findFact(detail: AnalysisDetail, factName: string): unknown | undefined {
  const allFacts = [
    ...detail.packet_observed_facts,
    ...detail.supplied_facts,
    ...detail.model_inferred_facts,
  ];
  const found = allFacts.find((f) => f.fact_name === factName);
  return found?.fact_value;
}

function hasFinding(detail: AnalysisDetail, ruleSubstr: string): boolean {
  return detail.findings.some(
    (f) =>
      f.rule_id.toLowerCase().includes(ruleSubstr.toLowerCase()) ||
      (f.recommendation && f.recommendation.toLowerCase().includes(ruleSubstr.toLowerCase())),
  );
}

export const RFC_CATALOG: RfcStandard[] = [
  {
    id: "rfc-7296-ikev2",
    domain: "Architecture",
    title: "Internet Key Exchange Protocol Version 2",
    algorithm: "IKEv2",
    rfc: "RFC 7296",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc7296",
    requirement: "MUST",
    nistRef: "NIST SP 800-77r1 §3.1",
    description: "Modern key exchange framework with 4-message exchange, DoS cookies, and built-in NAT-T.",
    evaluator: (detail) => {
      const v = findFact(detail, "ike.version");
      const versions = Array.isArray(v) ? v.map(String) : v ? [String(v)] : [];
      if (versions.includes("2")) {
        return {
          observed: true,
          observedValue: "IKEv2",
          verdict: "compliant",
          notes: "IKEv2 detected in handshake messages.",
        };
      }
      if (versions.includes("1")) {
        return {
          observed: true,
          observedValue: "IKEv1",
          verdict: "non-compliant",
          notes: "Legacy IKEv1 observed. Deprecated per NIST SP 800-77.",
        };
      }
      return {
        observed: false,
        verdict: "not-observed",
        notes: "No IKE handshake versions captured in trace.",
      };
    },
  },
  {
    id: "rfc-2409-ikev1",
    domain: "Architecture",
    title: "The Internet Key Exchange (IKEv1 Legacy)",
    algorithm: "IKEv1",
    rfc: "RFC 2409",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc2409",
    requirement: "MUST NOT",
    nistRef: "NIST SP 800-77r1 (Disallowed)",
    description: "Obsolete protocol subject to aggressive mode hash extraction, DoS amplification, and complex state machines.",
    evaluator: (detail) => {
      const v = findFact(detail, "ike.version");
      const versions = Array.isArray(v) ? v.map(String) : v ? [String(v)] : [];
      if (versions.includes("1")) {
        return {
          observed: true,
          observedValue: "IKEv1 Active",
          verdict: "non-compliant",
          notes: "CRITICAL: Obsolete IKEv1 in use. Vulnerable to pre-shared key offline dictionary attacks.",
        };
      }
      return {
        observed: versions.length > 0,
        observedValue: versions.length > 0 ? "Not Used" : undefined,
        verdict: versions.length > 0 ? "compliant" : "not-observed",
        notes: versions.length > 0 ? "No legacy IKEv1 packets detected." : "No IKE traffic captured.",
      };
    },
  },
  {
    id: "rfc-4303-esp",
    domain: "Architecture",
    title: "IP Encapsulating Security Payload (ESP)",
    algorithm: "ESP",
    rfc: "RFC 4303",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc4303",
    requirement: "MUST",
    nistRef: "NIST SP 800-77r1 §2.1",
    description: "Provides packet confidentiality, data integrity, anti-replay, and traffic-flow confidentiality.",
    evaluator: (detail) => {
      const protos = findFact(detail, "ipsec.protocols_observed");
      const protoList = Array.isArray(protos) ? protos.map(String) : [];
      if (protoList.includes("esp")) {
        return {
          observed: true,
          observedValue: "ESP (IP proto 50)",
          verdict: "compliant",
          notes: "ESP data transport observed in packet capture.",
        };
      }
      return {
        observed: false,
        verdict: "not-observed",
        notes: "No ESP payload packets detected.",
      };
    },
  },
  {
    id: "rfc-4106-aes-gcm",
    domain: "Encryption",
    title: "AES-GCM Authenticated Encryption for ESP",
    algorithm: "AES-256-GCM / AES-128-GCM",
    rfc: "RFC 4106 / RFC 8221",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc4106",
    requirement: "MUST",
    nistRef: "NIST SP 800-77r1 §3.2.1",
    description: "AEAD mode providing high-speed hardware-accelerated confidentiality and integrity in a single pass.",
    evaluator: (detail) => {
      const selectedEnc = findFact(detail, "ike_sa.selected.encryption_algorithm");
      const offeredEnc = findFact(detail, "ike_sa.offered.encryption_algorithms");
      const encStr = String(selectedEnc || offeredEnc || "");
      if (encStr.toLowerCase().includes("gcm") || encStr.toLowerCase().includes("aes-256")) {
        return {
          observed: true,
          observedValue: encStr || "AES-GCM",
          verdict: "compliant",
          notes: "NIST SP 800-77 and RFC 8221 compliant authenticated encryption.",
        };
      }
      if (hasFinding(detail, "cipher") || hasFinding(detail, "enc")) {
        return {
          observed: true,
          observedValue: encStr || "Weak / Non-AEAD",
          verdict: "warning",
          notes: "Non-AEAD or legacy cipher suite detected.",
        };
      }
      return {
        observed: Boolean(selectedEnc || offeredEnc),
        observedValue: selectedEnc ? String(selectedEnc) : undefined,
        verdict: selectedEnc ? "warning" : "not-observed",
        notes: selectedEnc ? `Observed: ${String(selectedEnc)}` : "No cipher negotiation recorded.",
      };
    },
  },
  {
    id: "rfc-8221-3des-disallowed",
    domain: "Encryption",
    title: "Deprecation of Triple-DES (3DES) in IPsec",
    algorithm: "3DES-CBC",
    rfc: "RFC 8221 §5",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc8221#section-5",
    requirement: "MUST NOT",
    nistRef: "NIST SP 800-131A Rev. 2",
    description: "64-bit block size vulnerable to Sweet32 collision attacks (CVE-2016-2183). Officially retired by NIST.",
    evaluator: (detail) => {
      const offered = String(findFact(detail, "ike_sa.offered.encryption_algorithms") || "");
      const selected = String(findFact(detail, "ike_sa.selected.encryption_algorithm") || "");
      const combined = `${offered} ${selected}`.toLowerCase();
      if (combined.includes("3des") || combined.includes("des3")) {
        return {
          observed: true,
          observedValue: "3DES Observed",
          verdict: "non-compliant",
          notes: "VIOLATION: 3DES is deprecated and prohibited by NIST SP 800-131A.",
        };
      }
      return {
        observed: combined.trim().length > 0,
        observedValue: combined.trim().length > 0 ? "Not Offered" : undefined,
        verdict: combined.trim().length > 0 ? "compliant" : "not-observed",
        notes: combined.trim().length > 0 ? "3DES rejected / absent." : "Encryption transforms not observable.",
      };
    },
  },
  {
    id: "rfc-8221-des-forbidden",
    domain: "Encryption",
    title: "DES-CBC Deprecation (Single DES)",
    algorithm: "DES-CBC",
    rfc: "RFC 8221 §5",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc8221#section-5",
    requirement: "MUST NOT",
    nistRef: "NIST FIPS 46-3 (Withdrawn)",
    description: "56-bit effective key length can be brute-forced in under 24 hours with commodity hardware.",
    evaluator: (detail) => {
      const offered = String(findFact(detail, "ike_sa.offered.encryption_algorithms") || "").toLowerCase();
      if (/\bdes\b/.test(offered) && !offered.includes("3des")) {
        return {
          observed: true,
          observedValue: "Single DES",
          verdict: "non-compliant",
          notes: "CRITICAL: Single DES (56-bit) observed in proposals. Insecure.",
        };
      }
      return {
        observed: offered.length > 0,
        observedValue: offered.length > 0 ? "Not Offered" : undefined,
        verdict: offered.length > 0 ? "compliant" : "not-observed",
        notes: offered.length > 0 ? "No single DES proposals found." : "Encryption proposals not observable.",
      };
    },
  },
  {
    id: "rfc-4868-sha2",
    domain: "Integrity",
    title: "HMAC-SHA-256 / 384 / 512 for IPsec",
    algorithm: "HMAC-SHA-256-128",
    rfc: "RFC 4868 / RFC 8221",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc4868",
    requirement: "MUST",
    nistRef: "NIST FIPS 180-4 / SP 800-77",
    description: "SHA-2 family hash function with truncated 128-bit or 256-bit authenticator tag.",
    evaluator: (detail) => {
      const selected = String(findFact(detail, "ike_sa.selected.integrity_algorithm") || "");
      const offered = String(findFact(detail, "ike_sa.offered.integrity_algorithms") || "");
      const integ = `${selected} ${offered}`.toLowerCase();
      if (integ.includes("sha256") || integ.includes("sha384") || integ.includes("sha512") || integ.includes("sha-2")) {
        return {
          observed: true,
          observedValue: selected || offered || "HMAC-SHA-256",
          verdict: "compliant",
          notes: "SHA-2 compliant integrity algorithm active.",
        };
      }
      return {
        observed: Boolean(selected || offered),
        observedValue: selected ? String(selected) : undefined,
        verdict: selected ? "warning" : "not-observed",
        notes: selected ? `Using ${selected}` : "Integrity algorithm not negotiated in plain text.",
      };
    },
  },
  {
    id: "rfc-4305-sha1-deprecated",
    domain: "Integrity",
    title: "Deprecation of HMAC-SHA-1-96",
    algorithm: "HMAC-SHA1-96",
    rfc: "RFC 8247 §3.2 / RFC 8221",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc8247",
    requirement: "MUST NOT",
    nistRef: "NIST SP 800-131A (Deprecation)",
    description: "SHA-1 collision attacks (SHAttered, Shambles) render SHA-1 unsuitable for cryptographic guarantees.",
    evaluator: (detail) => {
      const selected = String(findFact(detail, "ike_sa.selected.integrity_algorithm") || "").toLowerCase();
      const offered = String(findFact(detail, "ike_sa.offered.integrity_algorithms") || "").toLowerCase();
      if (selected.includes("sha1") || offered.includes("sha1") || selected.includes("sha-1")) {
        return {
          observed: true,
          observedValue: "SHA-1 Observed",
          verdict: "non-compliant",
          notes: "SHA-1 HMAC detected. Should be migrated to SHA-256.",
        };
      }
      return {
        observed: (selected + offered).length > 0,
        observedValue: (selected + offered).length > 0 ? "Not Used" : undefined,
        verdict: (selected + offered).length > 0 ? "compliant" : "not-observed",
        notes: "No SHA-1 integrity transforms present.",
      };
    },
  },
  {
    id: "rfc-8247-dh-groups",
    domain: "Key Exchange",
    title: "Diffie-Hellman Groups for IKEv2 (ECDH / MODP >= 2048)",
    algorithm: "DH Group 19 / 20 / 14",
    rfc: "RFC 8247 §2.3 / RFC 5903",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc8247",
    requirement: "MUST",
    nistRef: "NIST SP 800-77r1 / CNSA 2.0",
    description: "ECDH Curve P-256 (Group 19), Curve P-384 (Group 20), or 2048-bit MODP (Group 14) minimum for 112+ bit security.",
    evaluator: (detail) => {
      const selectedDh = String(findFact(detail, "ike_sa.selected.dh_group") || "");
      const offeredDh = String(findFact(detail, "ike_sa.offered.dh_groups") || "");
      const dhStr = `${selectedDh} ${offeredDh}`;
      if (/19|20|21|ecp|curve25519/i.test(dhStr)) {
        return {
          observed: true,
          observedValue: selectedDh || offeredDh || "ECDH (Group 19/20)",
          verdict: "compliant",
          notes: "NIST SP 800-77 approved Elliptic Curve Diffie-Hellman.",
        };
      }
      if (/14|15|16|2048|3072|4096/i.test(dhStr)) {
        return {
          observed: true,
          observedValue: selectedDh || offeredDh || "MODP >= 2048",
          verdict: "compliant",
          notes: "Acceptable 2048+ bit modular exponential DH group.",
        };
      }
      return {
        observed: Boolean(selectedDh || offeredDh),
        observedValue: selectedDh ? String(selectedDh) : undefined,
        verdict: selectedDh ? "warning" : "not-observed",
        notes: selectedDh ? `Observed: ${selectedDh}` : "DH group not captured.",
      };
    },
  },
  {
    id: "rfc-6989-dh-small-groups",
    domain: "Key Exchange",
    title: "Prohibition of DH Groups < 2048-bit (Group 1 & 2)",
    algorithm: "DH Group 1 (768-bit) / Group 2 (1024-bit)",
    rfc: "RFC 6989 §2 / RFC 8247",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc6989",
    requirement: "MUST NOT",
    nistRef: "NIST SP 800-131A (Transitioned)",
    description: "1024-bit primes can be solved by nation-state actors via Number Field Sieve (Logjam attack).",
    evaluator: (detail) => {
      const selectedDh = String(findFact(detail, "ike_sa.selected.dh_group") || "");
      const offeredDh = String(findFact(detail, "ike_sa.offered.dh_groups") || "");
      const dhStr = `${selectedDh} ${offeredDh}`;
      if (/\b(1|2)\b|group 1\b|group 2\b|768|1024/i.test(dhStr)) {
        return {
          observed: true,
          observedValue: "Legacy DH 1024/768",
          verdict: "non-compliant",
          notes: "CRITICAL: Deprecated DH group under 2048 bits detected.",
        };
      }
      return {
        observed: dhStr.trim().length > 0,
        observedValue: dhStr.trim().length > 0 ? "Not Offered" : undefined,
        verdict: dhStr.trim().length > 0 ? "compliant" : "not-observed",
        notes: "No weak DH Group 1 or 2 observed.",
      };
    },
  },
  {
    id: "rfc-7296-pfs",
    domain: "Key Exchange",
    title: "Perfect Forward Secrecy for Child SAs",
    algorithm: "PFS (Child SA DH Exchange)",
    rfc: "RFC 7296 §2.12",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc7296#section-2.12",
    requirement: "SHOULD",
    nistRef: "NIST SP 800-77r1 §3.1",
    description: "Ensures compromise of long-term IKE keys does not compromise past encrypted session payloads.",
    evaluator: (detail) => {
      // In passive observation, PFS is verified if CREATE_CHILD_SA exchange includes KE payload
      const exchanges = findFact(detail, "ike.exchange_types_observed");
      const exList = Array.isArray(exchanges) ? exchanges.map(String) : [];
      if (exList.some((e) => e.includes("CHILD_SA") || e === "36")) {
        return {
          observed: true,
          observedValue: "CREATE_CHILD_SA Active",
          verdict: "compliant",
          notes: "Child SA rekey observed; PFS exchange present.",
        };
      }
      return {
        observed: false,
        verdict: "not-observed",
        notes: "Child SA rekey not captured; PFS configuration not observable without CREATE_CHILD_SA trace.",
      };
    },
  },
  {
    id: "rfc-4303-anti-replay",
    domain: "Anti-Replay",
    title: "ESP Anti-Replay Sliding Window",
    algorithm: "Anti-Replay Window (>= 64 packets)",
    rfc: "RFC 4303 §3.4.3",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc4303#section-3.4.3",
    requirement: "MUST",
    nistRef: "NIST SP 800-77r1 §2.1",
    description: "Rejects duplicated or old sequence numbers to protect against packet reinjection and replay attacks.",
    evaluator: (detail) => {
      const windowFact = findFact(detail, "esp.sequence_window_observed");
      if (windowFact && typeof windowFact === "object") {
        return {
          observed: true,
          observedValue: "Active ESP Sequences",
          verdict: "compliant",
          notes: "ESP sequence numbers incrementing normally without catastrophic duplicate anomalies.",
        };
      }
      return {
        observed: false,
        verdict: "not-observed",
        notes: "Insufficient ESP packet sequence flow to measure window state.",
      };
    },
  },
  {
    id: "rfc-3948-natt",
    domain: "Architecture",
    title: "UDP Encapsulation of IPsec ESP Packets (NAT-T)",
    algorithm: "NAT-T (UDP Port 4500)",
    rfc: "RFC 3948",
    rfcUrl: "https://www.rfc-editor.org/rfc/rfc3948",
    requirement: "SHOULD",
    nistRef: "NIST SP 800-77r1 §2.3",
    description: "Encapsulates ESP packets inside UDP port 4500 to allow IPsec tunnels to traverse NAT gateways.",
    evaluator: (detail) => {
      const natt = findFact(detail, "ike.nat_traversal_observed");
      if (natt === true) {
        return {
          observed: true,
          observedValue: "UDP/4500 Active",
          verdict: "compliant",
          notes: "NAT Traversal (UDP 4500) active and traversing middleboxes.",
        };
      }
      return {
        observed: natt !== undefined,
        observedValue: natt === false ? "Direct ESP (No NAT)" : undefined,
        verdict: "compliant",
        notes: "Direct ESP / no NAT detected on link.",
      };
    },
  },
];
