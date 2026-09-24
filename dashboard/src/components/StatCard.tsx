import { Group, Paper, Text } from "@mantine/core";
import type { CSSProperties, ReactNode } from "react";

export function StatCard({
  label,
  value,
  accent,
  icon,
}: {
  label: string;
  value: number;
  accent: string;
  icon: ReactNode;
}) {
  return (
    <Paper className="stat-card" p="lg">
      <Group justify="space-between" align="flex-start" wrap="nowrap">
        <div>
          <Text
            size="xs"
            c="dimmed"
            fw={800}
            tt="uppercase"
            letterSpacing="0.08em"
          >
            {label}
          </Text>
          <Text className="stat-value" mt={7}>
            {value}
          </Text>
        </div>
        <div
          className="stat-icon"
          style={{ "--stat-accent": accent } as CSSProperties}
        >
          {icon}
        </div>
      </Group>
      <div
        className="stat-line"
        style={{ background: `linear-gradient(90deg, ${accent}, transparent)` }}
      />
    </Paper>
  );
}
