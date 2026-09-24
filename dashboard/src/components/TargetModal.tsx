import { useEffect, useState } from "react";
import {
  Button,
  Group,
  Modal,
  Select,
  Stack,
  Switch,
  TextInput,
} from "@mantine/core";
import type { Criticality, Target, TargetInput } from "../api/types";

export function TargetModal({
  opened,
  onClose,
  target,
  onSave,
  onDelete,
  loading,
}: {
  opened: boolean;
  onClose: () => void;
  target?: Target | null;
  onSave: (
    input: TargetInput & { enabled?: boolean; id?: string },
  ) => Promise<void>;
  onDelete: () => void;
  loading: boolean;
}) {
  const [address, setAddress] = useState("");
  const [owner, setOwner] = useState("");
  const [criticality, setCriticality] = useState<Criticality>("LOW");
  const [enabled, setEnabled] = useState(true);
  useEffect(() => {
    if (opened) {
      setAddress(
        target
          ? `${target.address}${target.port ? `:${target.port}` : ""}`
          : "",
      );
      setOwner(target?.owner ?? "");
      setCriticality(target?.criticality ?? "LOW");
      setEnabled(target?.enabled ?? true);
    }
  }, [opened, target]);
  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={target ? "Edit target" : "Add target"}
      centered
      size="md"
    >
      <Stack>
        <TextInput
          label="Target"
          placeholder="https://example.com or example.com:8443"
          value={address}
          onChange={(e) => setAddress(e.currentTarget.value)}
          required
        />
        <TextInput
          label="Owner"
          placeholder="platform"
          value={owner}
          onChange={(e) => setOwner(e.currentTarget.value)}
        />
        <Select
          label="Criticality"
          data={["LOW", "MEDIUM", "HIGH", "CRITICAL"]}
          value={criticality}
          onChange={(v) => setCriticality((v ?? "LOW") as Criticality)}
        />
        {target && (
          <Switch
            label="Enabled"
            checked={enabled}
            onChange={(e) => setEnabled(e.currentTarget.checked)}
          />
        )}
        <Group justify="space-between" mt="md">
          {target ? (
            <Button variant="subtle" color="red" onClick={onDelete}>
              Delete target
            </Button>
          ) : (
            <span />
          )}
          <Group>
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button
              color="cyan"
              loading={loading}
              onClick={() =>
                void onSave({
                  target: address,
                  owner,
                  criticality,
                  enabled,
                  id: target?.id,
                })
              }
            >
              {target ? "Save changes" : "Add & scan"}
            </Button>
          </Group>
        </Group>
      </Stack>
    </Modal>
  );
}
