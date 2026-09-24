import type { CertificateStatus, RiskLevel } from "../api/types";

export const statusColor = (status: CertificateStatus) =>
  ({
    OK: "teal",
    INFORMATION: "blue",
    WARNING: "yellow",
    CRITICAL: "red",
    EXPIRED: "gray",
  })[status];

export const riskColor = (level: RiskLevel) =>
  ({ LOW: "teal", MEDIUM: "blue", HIGH: "orange", CRITICAL: "red" })[level];

export function formatDate(value?: string | null) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    year: "numeric",
  }).format(new Date(value));
}

export function formatDateTime(value?: string | null) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

export function daysLabel(days: number) {
  if (days < 0) return `${Math.abs(days)}d overdue`;
  if (days === 0) return "Today";
  if (days === 1) return "1 day";
  return `${days} days`;
}

export function truncateError(value: string | undefined, max = 180) {
  if (!value) return "No additional details were provided.";
  return value.length > max ? `${value.slice(0, max).trimEnd()}...` : value;
}

export function statusFromDays(days: number): CertificateStatus {
  if (days < 0) return "EXPIRED";
  if (days <= 14) return "CRITICAL";
  if (days <= 30) return "WARNING";
  if (days <= 60) return "INFORMATION";
  return "OK";
}

export function tlsVersionName(version: number) {
  return (
    (
      {
        769: "TLS 1.0",
        770: "TLS 1.1",
        771: "TLS 1.2",
        772: "TLS 1.3",
      } as Record<number, string>
    )[version] ?? `TLS (${version})`
  );
}

export function cipherSuiteName(value: number) {
  return (
    (
      {
        4865: "TLS_AES_128_GCM_SHA256",
        4866: "TLS_AES_256_GCM_SHA384",
        4867: "TLS_CHACHA20_POLY1305_SHA256",
      } as Record<number, string>
    )[value] ?? `IANA ${value}`
  );
}
