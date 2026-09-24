import { Badge, Group, Text, Tooltip } from "@mantine/core";
import type { CertificateStatus } from "../api/types";
import { statusColor } from "../utils/format";

export function StatusOrb({
  status,
  compact = false,
}: {
  status: CertificateStatus;
  compact?: boolean;
}) {
  const color = statusColor(status);
  return (
    <Tooltip label={status} withArrow>
      <Group gap={compact ? 7 : 9} wrap="nowrap">
        <span className={`status-orb status-${status.toLowerCase()}`} />
        {!compact && (
          <Text size="sm" c="gray.2" fw={600}>
            {status}
          </Text>
        )}
        {compact && (
          <Badge variant="light" color={color} size="sm">
            {status}
          </Badge>
        )}
      </Group>
    </Tooltip>
  );
}
