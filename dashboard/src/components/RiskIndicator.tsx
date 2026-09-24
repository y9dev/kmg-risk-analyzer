import { RingProgress, Text, Tooltip } from "@mantine/core";
import type { Risk } from "../api/types";
import { riskColor } from "../utils/format";

export function RiskIndicator({
  risk,
  detail = false,
}: {
  risk: Risk;
  detail?: boolean;
}) {
  const value = Math.max(0, Math.min(100, risk.score));
  const color = riskColor(risk.level);

  console.log("RiskIndicator:", {
    score: risk.score,
    level: risk.level,
    color,
  });

  if (detail) {
    return (
      <div className="risk-detail">
        <RingProgress
          size={116}
          thickness={10}
          sections={[{ value, color }]}
          label={
            <Text ta="center" fw={800} size="lg">
              {value}
            </Text>
          }
        />

        <div>
          <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
            Risk level
          </Text>
          <Text size="xl" fw={800} c={`${color}.4`}>
            {risk.level}
          </Text>
        </div>
      </div>
    );
  }

  return (
    <Tooltip label={`${risk.level} risk`} withArrow>
      <div>
        <RingProgress
          size={42}
          thickness={5}
          sections={[{ value, color }]}
          label={
            <Text ta="center" size="xs" fw={800}>
              {value}
            </Text>
          }
        />
      </div>
    </Tooltip>
  );
}
