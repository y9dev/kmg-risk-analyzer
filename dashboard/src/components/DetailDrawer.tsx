import {
  Badge,
  Button,
  Divider,
  Drawer,
  Group,
  SimpleGrid,
  Stack,
  Text,
} from "@mantine/core";
import {
  IconAlertTriangle,
  IconEdit,
  IconRefresh,
  IconShieldCheck,
  IconWorld,
} from "@tabler/icons-react";
import type { Scan, Target } from "../api/types";
import {
  cipherSuiteName,
  daysLabel,
  formatDate,
  formatDateTime,
  tlsVersionName,
  truncateError,
} from "../utils/format";
import { RiskIndicator } from "./RiskIndicator";
import { StatusOrb } from "./StatusOrb";

export function DetailDrawer({
  opened,
  onClose,
  scan,
  target,
  onEdit,
  onScan,
  scanning,
}: {
  opened: boolean;
  onClose: () => void;
  scan: Scan | null;
  target?: Target;
  onEdit: () => void;
  onScan: () => void;
  scanning: boolean;
}) {
  if (!scan) return null;

  const dnsNames = scan.certificate.dns_names ?? [];
  const ipAddresses = scan.certificate.ip_addresses ?? [];
  const findings = scan.findings ?? [];

  return (
    <Drawer
      opened={opened}
      onClose={onClose}
      title="Certificate details"
      position="right"
      size="min(720px, 100vw)"
      className="detail-drawer"
    >
      <Stack gap="xl">
        <Group justify="space-between" align="flex-start">
          <div>
            <Text size="xs" c="cyan.4" tt="uppercase" fw={800}>
              {scan.owner || "Unassigned"}
            </Text>

            <Text size="xl" fw={850}>
              {scan.certificate.common_name ||
                target?.server_name ||
                target?.address ||
                "Unknown target"}
            </Text>

            <Text size="sm" c="dimmed">
              {target?.address || "—"}
              {target?.port ? `:${target.port}` : ""}
            </Text>
          </div>

          <StatusOrb status={scan.status} compact />
        </Group>

        <div className="detail-hero">
          <RiskIndicator risk={scan.risk} detail />

          <div>
            <Text fw={800} size="lg">
              {daysLabel(scan.days_left)}
            </Text>

            <Text size="sm" c="dimmed">
              Expires {formatDate(scan.certificate.valid_to)}
            </Text>

            <Group mt="md">
              <Button
                size="sm"
                color="cyan"
                leftSection={<IconRefresh size={15} />}
                loading={scanning}
                onClick={onScan}
              >
                Run scan
              </Button>

              {target && (
                <Button
                  size="sm"
                  variant="light"
                  color="gray"
                  leftSection={<IconEdit size={15} />}
                  onClick={onEdit}
                >
                  Edit target
                </Button>
              )}
            </Group>
          </div>
        </div>

        <section>
          <Text className="section-label">Certificate</Text>

          <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md" mt="sm">
            <Info label="Issuer" value={scan.certificate.issuer} />

            <Info label="Subject" value={scan.certificate.subject} />

            <Info
              label="Valid from"
              value={formatDate(scan.certificate.valid_from)}
            />

            <Info
              label="Valid to"
              value={formatDate(scan.certificate.valid_to)}
            />

            <Info
              label="Serial number"
              value={scan.certificate.serial_number}
              mono
            />

            <Info
              label="SHA-256 fingerprint"
              value={scan.certificate.fingerprint_sha256}
              mono
            />

            <Info
              label="Signature"
              value={scan.certificate.signature_algorithm}
            />

            <Info
              label="Public key"
              value={`${scan.certificate.public_key_algorithm} ${scan.certificate.public_key_size} bit`}
            />
          </SimpleGrid>
        </section>

        <Divider />

        <section>
          <Text className="section-label">Validation</Text>

          <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md" mt="sm">
            <Info label="Hostname" value={scan.hostname.status} />

            <Info label="Chain" value={scan.chain.status} />

            <Info label="Self-signed" value={scan.self_signed ? "Yes" : "No"} />
          </SimpleGrid>

          {(scan.hostname.error || scan.chain.error) && (
            <Stack mt="md" gap="xs">
              {scan.hostname.error && (
                <Text size="sm" c="red.3">
                  Hostname: {truncateError(scan.hostname.error)}
                </Text>
              )}

              {scan.chain.error && (
                <Text size="sm" c="red.3">
                  Chain: {truncateError(scan.chain.error)}
                </Text>
              )}
            </Stack>
          )}
        </section>

        <Divider />

        <section>
          <Text className="section-label">TLS</Text>

          <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md" mt="sm">
            <Info
              label="TLS version"
              value={tlsVersionName(scan.tls_version)}
            />

            <Info
              label="Cipher suite"
              value={cipherSuiteName(scan.cipher_suite)}
            />
          </SimpleGrid>
        </section>

        <Divider />

        <section>
          <Text className="section-label">Names</Text>

          <Text size="sm" mt="sm" c="dimmed">
            DNS names
          </Text>

          <Group gap="xs" mt={5}>
            {dnsNames.length > 0 ? (
              dnsNames.map((name) => (
                <Badge key={name} variant="light" color="cyan">
                  {name}
                </Badge>
              ))
            ) : (
              <Text size="sm">—</Text>
            )}
          </Group>

          <Text size="sm" mt="md" c="dimmed">
            IP addresses
          </Text>

          <Group gap="xs" mt={5}>
            {ipAddresses.length > 0 ? (
              ipAddresses.map((ip) => (
                <Badge key={ip} variant="outline">
                  {ip}
                </Badge>
              ))
            ) : (
              <Text size="sm">—</Text>
            )}
          </Group>
        </section>

        <Divider />

        <Group justify="space-between">
          <Group gap="xs">
            <IconShieldCheck size={17} />

            <Text size="xs" c="dimmed">
              Last scanned {formatDateTime(scan.scanned_at)}
            </Text>
          </Group>

          {target && (
            <Group gap="xs">
              <IconWorld size={15} />

              <Text size="xs" c="dimmed">
                {target.enabled ? "Scanning enabled" : "Scanning disabled"}
              </Text>
            </Group>
          )}
        </Group>

        {scan.risk.level !== "LOW" &&
          scan.risk.level !== "MEDIUM" &&
          findings.length > 0 && (
            <div className="risk-reasons">
              <Group gap="xs">
                <IconAlertTriangle size={17} />

                <Text fw={750}>Risk findings</Text>
              </Group>

              <Stack gap="xs" mt="sm">
                {findings.map((finding, index) => (
                  <div key={`${finding.type}-${index}`} className="finding-row">
                    <Badge
                      color={finding.severity === "CRITICAL" ? "red" : "yellow"}
                      variant="light"
                    >
                      {finding.severity}
                    </Badge>

                    <div>
                      <Text size="sm" fw={700}>
                        {finding.type}
                      </Text>

                      <Text size="sm" c="dimmed">
                        {finding.message}
                      </Text>
                    </div>
                  </div>
                ))}
              </Stack>
            </div>
          )}
      </Stack>
    </Drawer>
  );
}

function Info({
  label,
  value,
  mono,
}: {
  label: string;
  value?: string | null;
  mono?: boolean;
}) {
  return (
    <div>
      <Text size="xs" c="dimmed" fw={700}>
        {label}
      </Text>

      <Text
        size="sm"
        mt={3}
        className={mono ? "mono" : ""}
        style={{ wordBreak: "break-word" }}
      >
        {value || "—"}
      </Text>
    </div>
  );
}
