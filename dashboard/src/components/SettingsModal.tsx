import { useEffect, useState } from "react";
import { Button, Group, Modal, NumberInput, Stack, Text } from "@mantine/core";

export interface DashboardSettings {
  expiringSoonDays: number;
  pageSize: number;
}
const KEY = "certificate-radar-dashboard-settings";
const defaults: DashboardSettings = { expiringSoonDays: 30, pageSize: 20 };
export function loadSettings(): DashboardSettings {
  try {
    return { ...defaults, ...JSON.parse(localStorage.getItem(KEY) || "{}") };
  } catch {
    return defaults;
  }
}
function saveSettings(value: DashboardSettings) {
  localStorage.setItem(KEY, JSON.stringify(value));
}

export function SettingsModal({
  opened,
  onClose,
  settings,
  onSave,
}: {
  opened: boolean;
  onClose: () => void;
  settings: DashboardSettings;
  onSave: (s: DashboardSettings) => void;
}) {
  const [draft, setDraft] = useState(settings);
  useEffect(() => setDraft(settings), [settings, opened]);
  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title="Dashboard settings"
      centered
    >
      <Stack>
        <Text size="sm" c="dimmed">
          These values are dashboard preferences and do not change Certificate
          Radar's risk engine.
        </Text>
        <NumberInput
          label="Expiring soon threshold (days)"
          min={1}
          max={3650}
          value={draft.expiringSoonDays}
          onChange={(v) =>
            setDraft({
              ...draft,
              expiringSoonDays:
                typeof v === "number" ? v : defaults.expiringSoonDays,
            })
          }
        />
        <NumberInput
          label="Rows per page"
          min={10}
          max={25}
          value={draft.pageSize}
          onChange={(v) =>
            setDraft({
              ...draft,
              pageSize: typeof v === "number" ? v : defaults.pageSize,
            })
          }
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button
            color="cyan"
            onClick={() => {
              saveSettings(draft);
              onSave(draft);
              onClose();
            }}
          >
            Save settings
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
