import { Button, Group, Modal, Text } from "@mantine/core";
import type { Target } from "../api/types";

export function TargetDeleteModal({
  opened,
  target,
  onClose,
}: {
  opened: boolean;
  target?: Target | null;
  onClose: () => void;
}) {
  const handleDelete = () => {
    // TODO: Replace this placeholder with DELETE /api/targets/:id when the backend endpoint is available.
    onClose();
  };
  return (
    <Modal opened={opened} onClose={onClose} title="Delete target" centered>
      <Text size="sm" c="dimmed">
        Delete <strong>{target?.server_name || target?.address}</strong>? This
        action is currently a UI placeholder.
      </Text>
      <Group justify="flex-end" mt="xl">
        <Button variant="default" onClick={onClose}>
          Cancel
        </Button>
        <Button color="red" onClick={handleDelete}>
          Delete
        </Button>
      </Group>
    </Modal>
  );
}
