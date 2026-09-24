export type CertificateStatus =
  | "OK"
  | "INFORMATION"
  | "WARNING"
  | "CRITICAL"
  | "EXPIRED";
export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Criticality = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type FindingSeverity = "INFO" | "WARNING" | "CRITICAL";

export interface Target {
  id: string;
  address: string;
  port: number;
  server_name: string;
  enabled: boolean;
  owner: string;
  criticality: Criticality;
}

export interface Certificate {
  fingerprint_sha256: string;
  serial_number: string;
  subject: string;
  common_name: string;
  dns_names: string[] | null;
  ip_addresses: string[] | null;
  issuer: string;
  valid_from: string;
  valid_to: string;
  signature_algorithm: string;
  public_key_algorithm: string;
  public_key_size: number;
}

export interface Finding {
  type: string;
  severity: FindingSeverity;
  message: string;
}

export interface Risk {
  score: number;
  level: RiskLevel;
}

export interface Scan {
  target_id: string;
  scanned_at: string;
  days_left: number;
  status: CertificateStatus;
  hostname: { status: "MATCH" | "MISMATCH" | "UNKNOWN"; error: string };
  chain: { status: "VALID" | "INVALID" | "UNKNOWN"; error: string };
  self_signed: boolean;
  tls_version: number;
  cipher_suite: number;
  owner: string;
  criticality: Criticality;
  certificate: Certificate;
  findings: Finding[];
  risk: Risk;
}

export interface RecentScansResponse {
  items: Scan[];
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface TargetInput {
  target: string;
  owner?: string;
  criticality?: Criticality;
}

export interface TargetUpdateInput {
  owner?: string;
  criticality?: Criticality;
  enabled?: boolean;
  /** Backend extension: the documented MVP API currently does not accept address changes. */
  address?: string;
  port?: number;
  server_name?: string;
}
