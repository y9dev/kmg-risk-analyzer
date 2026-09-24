import {
  ActionIcon,
  Badge,
  Button,
  Group,
  Pagination,
  Table,
  Text,
  Tooltip,
} from "@mantine/core";
import {
  IconExternalLink,
  IconRefresh,
  IconSettings,
} from "@tabler/icons-react";
import type { Scan } from "../api/types";
import {
  daysLabel,
  formatDate,
  formatDateTime,
  riskColor,
} from "../utils/format";
import { RiskIndicator } from "./RiskIndicator";
import { StatusOrb } from "./StatusOrb";

export type SortKey =
  | "owner"
  | "server_name"
  | "issuer"
  | "valid_to"
  | "days_left"
  | "status"
  | "risk_score";
export function CertificateTable({
  scans,
  sort,
  onSort,
  onOpen,
  onScan,
  scanningId,
  page,
  totalPages,
  onPage,
}: {
  scans: Scan[];
  sort: { key: SortKey; direction: "asc" | "desc" };
  onSort: (key: SortKey) => void;
  onOpen: (scan: Scan) => void;
  onScan: (id: string) => void;
  scanningId?: string;
  page: number;
  totalPages: number;
  onPage: (p: number) => void;
}) {
  const sorted = [...scans].sort((a, b) => {
    let av: string | number = a.owner,
      bv: string | number = b.owner;
    if (sort.key === "server_name") {
      av = a.certificate.common_name;
      bv = b.certificate.common_name;
    }
    if (sort.key === "issuer") {
      av = a.certificate.issuer;
      bv = b.certificate.issuer;
    }
    if (sort.key === "valid_to") {
      av = a.certificate.valid_to;
      bv = b.certificate.valid_to;
    }
    if (sort.key === "days_left") {
      av = a.days_left;
      bv = b.days_left;
    }
    if (sort.key === "risk_score") {
      av = a.risk.score;
      bv = b.risk.score;
    }
    if (sort.key === "status") {
      av = a.status;
      bv = b.status;
    }
    const result = av < bv ? -1 : av > bv ? 1 : 0;
    return sort.direction === "asc" ? result : -result;
  });
  const arrow = (key: SortKey) =>
    sort.key === key ? (sort.direction === "asc" ? " ↑" : " ↓") : "";
  const header = (label: string, key: SortKey) => (
    <Button
      variant="subtle"
      color="gray"
      className="sort-button"
      onClick={() => onSort(key)}
    >
      {label}
      {arrow(key)}
    </Button>
  );
  return (
    <div className="table-shell">
      <div className="table-scroll">
        <Table
          highlightOnHover
          verticalSpacing="md"
          className="certificate-table"
        >
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{header("Owner", "owner")}</Table.Th>
              <Table.Th>{header("Server name", "server_name")}</Table.Th>
              <Table.Th>{header("Issuer", "issuer")}</Table.Th>
              <Table.Th>{header("Expiration", "valid_to")}</Table.Th>
              <Table.Th>{header("Days left", "days_left")}</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>{header("Risk", "risk_score")}</Table.Th>
              <Table.Th className="actions-col"> </Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {sorted.map((scan) => (
              <Table.Tr
                key={`${scan.target_id}-${scan.scanned_at}`}
                onClick={() => onOpen(scan)}
                className="clickable-row"
              >
                <Table.Td>
                  <Text fw={650} size="sm">
                    {scan.owner || "Unassigned"}
                  </Text>
                  <Text size="xs" c="dimmed">
                    {scan.criticality}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text fw={650} size="sm">
                    {scan.certificate.common_name || "Unknown"}
                  </Text>
                  <Text size="xs" c="dimmed">
                    Last scan {formatDateTime(scan.scanned_at)}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="sm" maw={230} truncate>
                    {scan.certificate.issuer || "Unknown issuer"}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="sm" fw={650}>
                    {formatDate(scan.certificate.valid_to)}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text
                    size="sm"
                    fw={800}
                    c={
                      scan.days_left < 0
                        ? "red.4"
                        : scan.days_left <= 30
                          ? "yellow.4"
                          : "gray.2"
                    }
                  >
                    {daysLabel(scan.days_left)}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <StatusOrb status={scan.status} compact />
                </Table.Td>
                <Table.Td>
                  <RiskIndicator risk={scan.risk} />
                </Table.Td>
                <Table.Td>
                  <Group
                    gap={4}
                    justify="flex-end"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <Tooltip label="Run scan">
                      <ActionIcon
                        variant="subtle"
                        color="cyan"
                        loading={scanningId === scan.target_id}
                        onClick={() => onScan(scan.target_id)}
                      >
                        <IconRefresh size={17} />
                      </ActionIcon>
                    </Tooltip>
                    <Tooltip label="Open details">
                      <ActionIcon
                        variant="subtle"
                        color="gray"
                        onClick={() => onOpen(scan)}
                      >
                        <IconExternalLink size={17} />
                      </ActionIcon>
                    </Tooltip>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {!sorted.length && (
          <div className="empty-table">
            <IconSettings size={28} />
            <Text fw={700}>No certificates match these filters</Text>
            <Text size="sm" c="dimmed">
              Try clearing a filter or waiting for the next scan.
            </Text>
          </div>
        )}
      </div>
      <div className="table-footer">
        <Text size="xs" c="dimmed">
          Showing {sorted.length} certificates on this page
        </Text>
        <Pagination
          value={page}
          onChange={onPage}
          total={totalPages}
          size="sm"
          color="cyan"
        />
      </div>
    </div>
  );
}
