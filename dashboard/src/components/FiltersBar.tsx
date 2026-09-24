import {
  Button,
  Group,
  MultiSelect,
  NumberInput,
  Paper,
  Select,
  TextInput,
} from "@mantine/core";
import {
  IconAdjustmentsHorizontal,
  IconCalendarTime,
  IconFilterOff,
  IconSearch,
} from "@tabler/icons-react";
import type { CertificateStatus, RiskLevel } from "../api/types";

export interface Filters {
  owner: string;
  issuer: string;
  status: CertificateStatus | null;
  risk: RiskLevel | null;
  minDays: number | "";
  maxDays: number | "";
}

export function FiltersBar({
  filters,
  owners,
  issuers,
  onChange,
  onReset,
}: {
  filters: Filters;
  owners: string[];
  issuers: string[];
  onChange: (next: Partial<Filters>) => void;
  onReset: () => void;
}) {
  return (
    <Paper className="filter-panel" p="md">
      <Group gap="sm" align="end" wrap="wrap">
        <TextInput
          label="Owner"
          placeholder="Search owner"
          leftSection={<IconSearch size={16} />}
          value={filters.owner}
          onChange={(e) => onChange({ owner: e.currentTarget.value })}
          className="filter-owner"
        />
        <Select
          label="Issuer"
          placeholder="All issuers"
          clearable
          searchable
          data={issuers}
          value={filters.issuer || null}
          onChange={(issuer) => onChange({ issuer: issuer ?? "" })}
          className="filter-issuer"
        />
        <Select
          label="Status"
          placeholder="All statuses"
          clearable
          data={["OK", "INFORMATION", "WARNING", "CRITICAL", "EXPIRED"]}
          value={filters.status}
          onChange={(status) =>
            onChange({ status: status as CertificateStatus | null })
          }
        />
        <Select
          label="Risk"
          placeholder="All risk"
          clearable
          data={["LOW", "MEDIUM", "HIGH", "CRITICAL"]}
          value={filters.risk}
          onChange={(risk) => onChange({ risk: risk as RiskLevel | null })}
        />
        <NumberInput
          label="Min days"
          placeholder="Any"
          min={-9999}
          value={filters.minDays}
          onChange={(minDays) =>
            onChange({ minDays: typeof minDays === "number" ? minDays : "" })
          }
          leftSection={<IconCalendarTime size={15} />}
          w={125}
        />
        <NumberInput
          label="Max days"
          placeholder="Any"
          min={-9999}
          value={filters.maxDays}
          onChange={(maxDays) =>
            onChange({ maxDays: typeof maxDays === "number" ? maxDays : "" })
          }
          leftSection={<IconCalendarTime size={15} />}
          w={125}
        />
        <Button
          variant="subtle"
          color="gray"
          leftSection={<IconFilterOff size={16} />}
          onClick={onReset}
        >
          Reset
        </Button>
        <div className="filter-spacer" />
        <Button
          variant="light"
          color="cyan"
          leftSection={<IconAdjustmentsHorizontal size={16} />}
          onClick={() =>
            document.dispatchEvent(new CustomEvent("open-dashboard-settings"))
          }
        >
          Thresholds
        </Button>
      </Group>
    </Paper>
  );
}
