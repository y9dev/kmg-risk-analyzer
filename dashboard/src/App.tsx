import { useEffect, useMemo, useRef, useState } from "react";
import {
  ActionIcon,
  AppShell,
  Badge,
  Button,
  Group,
  Loader,
  Paper,
  Stack,
  Text,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconActivity,
  IconAlertTriangle,
  IconCertificate,
  IconChevronRight,
  IconClock,
  IconCloudLock,
  IconPlus,
  IconRefresh,
  IconSettings,
  IconShieldCheck,
  IconTarget,
} from "@tabler/icons-react";
import { api, ApiError } from "./api/client";
import type {
  CertificateStatus,
  RiskLevel,
  Scan,
  Target,
  TargetInput,
} from "./api/types";
import { CertificateTable, type SortKey } from "./components/CertificateTable";
import { DetailDrawer } from "./components/DetailDrawer";
import { FiltersBar, type Filters } from "./components/FiltersBar";
import {
  SettingsModal,
  loadSettings,
  type DashboardSettings,
} from "./components/SettingsModal";
import { StatCard } from "./components/StatCard";
import { TargetDeleteModal } from "./components/TargetDeleteModal";
import { TargetModal } from "./components/TargetModal";
import { formatDate, statusFromDays, truncateError } from "./utils/format";

const initialFilters: Filters = {
  owner: "",
  issuer: "",
  status: null,
  risk: null,
  minDays: "",
  maxDays: "",
};

export function App() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [page, setPage] = useState(1);
  const [settings, setSettings] = useState<DashboardSettings>(loadSettings());
  const [filters, setFilters] = useState<Filters>(initialFilters);
  const [sort, setSort] = useState<{ key: SortKey; direction: "asc" | "desc" }>(
    { key: "days_left", direction: "asc" },
  );
  const [selected, setSelected] = useState<Scan | null>(null);
  const [targetModal, setTargetModal] = useState(false);
  const [deleteModal, setDeleteModal] = useState(false);
  const [settingsModal, setSettingsModal] = useState(false);
  const [editingTarget, setEditingTarget] = useState<Target | null>(null);
  const [scanningId, setScanningId] = useState<string>();
  const loadVersion = useRef(0);

  const notifyError = (title: string, err: unknown) =>
    notifications.show({
      color: "red",
      title,
      message: truncateError(
        err instanceof ApiError
          ? err.details
          : err instanceof Error
            ? err.message
            : "Unknown error",
      ),
      autoClose: 8000,
    });

  const load = async (initial = false) => {
    const version = ++loadVersion.current;

    if (initial) setLoading(true);
    else setRefreshing(true);

    try {
      const targetList = await api.getTargets();

      const all: Scan[] = [];
      let offset = 0;

      while (true) {
        const response = await api.getRecentScans(
          new URLSearchParams({
            limit: "100",
            offset: String(offset),
            sort: "scanned_at",
            order: "desc",
          }),
        );

        all.push(...response.items);

        if (!response.has_more || response.items.length === 0) {
          break;
        }

        offset += response.items.length;
      }

      // If a scan started while this request was running,
      // do not overwrite its newer state with stale data.
      if (version !== loadVersion.current) {
        return;
      }

      setTargets(targetList);
      setScans(all);
    } catch (err) {
      if (version === loadVersion.current) {
        notifyError("Unable to load dashboard", err);
      }
    } finally {
      if (version === loadVersion.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  };

  const latestScans = useMemo(() => {
    const latestByTarget = new Map<string, Scan>();

    for (const scan of scans) {
      const previous = latestByTarget.get(scan.target_id);

      if (
        !previous ||
        new Date(scan.scanned_at).getTime() >
          new Date(previous.scanned_at).getTime()
      ) {
        latestByTarget.set(scan.target_id, scan);
      }
    }

    return [...latestByTarget.values()];
  }, [scans]);

  useEffect(() => {
    void load(true);
  }, []);
  useEffect(() => {
    const id = window.setInterval(() => void load(), 20_000);
    return () => window.clearInterval(id);
  }, []);
  useEffect(() => {
    const handler = () => setSettingsModal(true);
    document.addEventListener("open-dashboard-settings", handler);
    return () =>
      document.removeEventListener("open-dashboard-settings", handler);
  }, []);
  useEffect(() => {
    setPage(1);
  }, [filters, settings.pageSize]);

  const owners = useMemo(
    () => [...new Set(latestScans.map((s) => s.owner).filter(Boolean))].sort(),
    [latestScans],
  );

  const issuers = useMemo(
    () =>
      [
        ...new Set(
          latestScans.map((s) => s.certificate.issuer).filter(Boolean),
        ),
      ].sort(),
    [latestScans],
  );

  const targetById = useMemo(
    () => new Map(targets.map((t) => [t.id, t])),
    [targets],
  );

  const filtered = useMemo(
    () =>
      latestScans.filter((scan) => {
        if (
          filters.owner &&
          !scan.owner.toLowerCase().includes(filters.owner.toLowerCase())
        ) {
          return false;
        }

        if (filters.issuer && scan.certificate.issuer !== filters.issuer) {
          return false;
        }

        if (filters.status && scan.status !== filters.status) {
          return false;
        }

        if (filters.risk && scan.risk.level !== filters.risk) {
          return false;
        }

        if (filters.minDays !== "" && scan.days_left < filters.minDays) {
          return false;
        }

        if (filters.maxDays !== "" && scan.days_left > filters.maxDays) {
          return false;
        }

        return true;
      }),
    [latestScans, filters],
  );

  const sorted = useMemo(
    () =>
      [...filtered].sort((a, b) => {
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
        return (
          (av < bv ? -1 : av > bv ? 1 : 0) * (sort.direction === "asc" ? 1 : -1)
        );
      }),
    [filtered, sort],
  );
  const totalPages = Math.max(1, Math.ceil(sorted.length / settings.pageSize));
  const safePage = Math.min(page, totalPages);
  const visible = sorted.slice(
    (safePage - 1) * settings.pageSize,
    safePage * settings.pageSize,
  );

  const stats = useMemo(
    () => ({
      total: targets.length,
      ok: latestScans.filter((s) => s.status === "OK").length,
      attention: latestScans.filter(
        (s) => s.status === "INFORMATION" || s.status === "WARNING",
      ).length,
      critical: latestScans.filter((s) => s.status === "CRITICAL").length,
      expired: latestScans.filter((s) => s.status === "EXPIRED").length,
    }),
    [targets.length, latestScans],
  );

  const expiring = useMemo(
    () =>
      latestScans
        .filter(
          (s) => s.days_left <= settings.expiringSoonDays && s.days_left >= 0,
        )
        .sort((a, b) => a.days_left - b.days_left)
        .slice(0, 5),
    [latestScans, settings.expiringSoonDays],
  );

  const runScan = async (id: string) => {
    setScanningId(id);

    try {
      const scan = await api.scanTarget(id);

      // Invalidate any refresh that was started before this scan completed.
      loadVersion.current += 1;

      setScans((prev) => [scan, ...prev]);

      setSelected(scan);

      notifications.show({
        title: "Scan completed",
        message: "The target has been rescanned successfully.",
        color: "teal",
      });
    } catch (err) {
      notifyError("Unable to scan target", err);
    } finally {
      setScanningId(undefined);
    }
  };

  const saveTarget = async (
    input: TargetInput & { enabled?: boolean; id?: string },
  ) => {
    try {
      if (input.id) {
        // The documented MVP PUT endpoint accepts owner, criticality and enabled only.
        // Address changes are intentionally sent here for the planned backend extension.
        const current = targetById.get(input.id);
        const normalized = parseTargetAddress(input.target);
        const updated = await api.updateTarget(input.id, {
          owner: input.owner,
          criticality: input.criticality,
          enabled: input.enabled,
          address: normalized.address,
          port: normalized.port,
          server_name: normalized.serverName,
        });
        setTargets((prev) =>
          prev.map((t) => (t.id === updated.id ? updated : t)),
        );

        setTargetModal(false);
        setEditingTarget(null);

        if (
          current &&
          (current.address !== updated.address ||
            current.port !== updated.port ||
            current.server_name !== updated.server_name)
        ) {
          await runScan(updated.id);
        } else {
          await load();
        }
      } else {
        const created = await api.createTarget({
          target: input.target,
          owner: input.owner,
          criticality: input.criticality,
        });
        setTargets((prev) => [...prev, created]);
        setTargetModal(false);
        setEditingTarget(null);
        await runScan(created.id);
        notifications.show({
          color: "teal",
          title: "Target added",
          message: "Target was created and scanned.",
        });
      }
    } catch (err) {
      notifyError(
        input.id ? "Unable to update target" : "Unable to add target",
        err,
      );
    }
  };

  const openScan = (scan: Scan) => setSelected(scan);

  const openEdit = () => {
    const target = selected ? targetById.get(selected.target_id) : null;

    if (target) {
      setSelected(null);
      setEditingTarget(target);
      setTargetModal(true);
    }
  };

  const onSort = (key: SortKey) =>
    setSort((prev) => ({
      key,
      direction: prev.key === key && prev.direction === "asc" ? "desc" : "asc",
    }));

  return (
    <AppShell padding={0} className="radar-app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <IconCloudLock size={21} />
          </div>
          <div>
            <Text fw={850} size="md">
              Certificate Radar
            </Text>
            <Text size="xs" c="dimmed">
              TLS visibility console
            </Text>
          </div>
        </div>
        <Group gap="xs">
          <Badge
            variant="light"
            color="teal"
            leftSection={<span className="live-dot" />}
          >
            LIVE
          </Badge>
          <Tooltip label="Refresh now">
            <ActionIcon
              variant="subtle"
              color="gray"
              onClick={() => void load()}
              loading={refreshing}
            >
              <IconRefresh size={18} />
            </ActionIcon>
          </Tooltip>
          <Tooltip label="Dashboard settings">
            <ActionIcon
              variant="subtle"
              color="gray"
              onClick={() => setSettingsModal(true)}
            >
              <IconSettings size={18} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </header>
      <main className="content">
        <section className="hero">
          <div>
            <Text className="eyebrow">
              <IconActivity size={14} /> SECURITY OBSERVABILITY
            </Text>
            <Title order={1}>Certificate overview</Title>
            <Text c="dimmed" mt={6}>
              Monitor certificate health, expiration and TLS risk across your
              services.
            </Text>
          </div>
          <Button
            color="cyan"
            leftSection={<IconPlus size={17} />}
            onClick={() => {
              setEditingTarget(null);
              setTargetModal(true);
            }}
          >
            Add target
          </Button>
        </section>
        <section className="stats-grid">
          <StatCard
            label="Total targets"
            value={stats.total}
            accent="#25d0ef"
            icon={<IconTarget size={21} />}
          />
          <StatCard
            label="Healthy"
            value={stats.ok}
            accent="#35d399"
            icon={<IconShieldCheck size={21} />}
          />
          <StatCard
            label="Attention"
            value={stats.attention}
            accent="#f4c95d"
            icon={<IconClock size={21} />}
          />
          <StatCard
            label="Critical"
            value={stats.critical}
            accent="#ff5c78"
            icon={<IconAlertTriangle size={21} />}
          />
          <StatCard
            label="Expired"
            value={stats.expired}
            accent="#8a96a8"
            icon={<IconCertificate size={21} />}
          />
        </section>
        <section className="section-grid">
          <Paper className="expiring-card" p="lg">
            <Group justify="space-between">
              <div>
                <Text className="section-label">Expiring soon</Text>
                <Text size="sm" c="dimmed">
                  Next {settings.expiringSoonDays} days
                </Text>
              </div>
              <Badge color="cyan" variant="light">
                {expiring.length}
              </Badge>
            </Group>
            <Stack mt="md" gap="xs">
              {expiring.length ? (
                expiring.map((s) => (
                  <button
                    className="expiring-item"
                    key={s.target_id}
                    onClick={() => openScan(s)}
                  >
                    <div>
                      <Text size="sm" fw={700}>
                        {s.certificate.common_name || "Unknown certificate"}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {s.owner || "Unassigned"} ·{" "}
                        {formatDate(s.certificate.valid_to)}
                      </Text>
                    </div>
                    <Group gap="xs">
                      <Text
                        size="sm"
                        fw={800}
                        c={s.days_left <= 14 ? "red.4" : "yellow.4"}
                      >
                        {s.days_left}d
                      </Text>
                      <IconChevronRight size={15} />
                    </Group>
                  </button>
                ))
              ) : (
                <Text size="sm" c="dimmed" py="md">
                  No certificates are expiring in this window.
                </Text>
              )}
            </Stack>
          </Paper>
          <Paper className="pulse-card" p="lg">
            <Group justify="space-between">
              <div>
                <Text className="section-label">Scanner status</Text>
                <Text size="sm" c="dimmed">
                  Automatic refresh every 20 seconds
                </Text>
              </div>
              <span className="pulse-ring">
                <span />
              </span>
            </Group>
            <div className="scanner-line">
              <span />
              <span />
              <span />
              <span />
              <span />
              <span />
            </div>
            <Text size="xs" c="dimmed" mt="md">
              Latest dashboard refresh{" "}
              {refreshing ? "in progress…" : "complete"}
            </Text>
          </Paper>
        </section>
        <section className="table-section">
          <Group justify="space-between" mb="md">
            <div>
              <Title order={2}>Certificates</Title>
              <Text size="sm" c="dimmed">
                Latest scan per monitored target
              </Text>
            </div>
            <Badge variant="outline" color="gray">
              {filtered.length} matching
            </Badge>
          </Group>
          <FiltersBar
            filters={filters}
            owners={owners}
            issuers={issuers}
            onChange={(next) => setFilters((f) => ({ ...f, ...next }))}
            onReset={() => setFilters(initialFilters)}
          />
          {loading ? (
            <div className="loading">
              <Loader color="cyan" />
              <Text size="sm" c="dimmed">
                Loading Certificate Radar…
              </Text>
            </div>
          ) : (
            <CertificateTable
              scans={visible}
              sort={sort}
              onSort={onSort}
              onOpen={openScan}
              onScan={runScan}
              scanningId={scanningId}
              page={safePage}
              totalPages={totalPages}
              onPage={setPage}
            />
          )}
        </section>
      </main>
      <DetailDrawer
        opened={!!selected}
        onClose={() => setSelected(null)}
        scan={selected}
        target={selected ? targetById.get(selected.target_id) : undefined}
        onEdit={openEdit}
        onScan={() => selected && void runScan(selected.target_id)}
        scanning={!!selected && scanningId === selected.target_id}
      />
      <TargetModal
        opened={targetModal}
        onClose={() => {
          setTargetModal(false);
          setEditingTarget(null);
          setEditingTarget(null);
        }}
        target={editingTarget}
        onSave={saveTarget}
        loading={!!scanningId}
        onDelete={() => setDeleteModal(true)}
      />
      <TargetDeleteModal
        opened={deleteModal}
        target={editingTarget}
        onClose={() => setDeleteModal(false)}
      />
      <SettingsModal
        opened={settingsModal}
        onClose={() => setSettingsModal(false)}
        settings={settings}
        onSave={(s) => setSettings(s)}
      />
    </AppShell>
  );
}

function parseTargetAddress(input: string): {
  address: string;
  port: number;
  serverName: string;
} {
  try {
    const url = input.includes("://")
      ? new URL(input)
      : new URL(`https://${input}`);
    return {
      address: url.hostname,
      port: Number(url.port) || 443,
      serverName: url.hostname,
    };
  } catch {
    const [host, port] = input.split(":");
    return { address: host, port: Number(port) || 443, serverName: host };
  }
}
