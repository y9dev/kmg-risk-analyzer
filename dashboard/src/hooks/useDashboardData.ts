import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type { Scan, Target } from "../api/types";

export function useDashboardData(pageSize: number, refreshMs = 20_000) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [totalPages, setTotalPages] = useState(1);
  const pageRef = useRef(1);

  const load = useCallback(
    async (page = pageRef.current, initial = false) => {
      pageRef.current = page;
      if (initial) setLoading(true);
      else setRefreshing(true);
      try {
        const [targetList, recent] = await Promise.all([
          api.getTargets(),
          api.getRecentScans(
            new URLSearchParams({
              limit: String(pageSize),
              offset: String((page - 1) * pageSize),
              sort: "days_left",
              order: "asc",
            }),
          ),
        ]);
        setTargets(targetList);
        setScans(recent.items);
        setTotalPages(recent.has_more ? page + 1 : Math.max(1, page));
        setError(null);
      } catch (err) {
        setError(
          err instanceof Error ? err : new Error("Unknown dashboard error"),
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [pageSize],
  );

  useEffect(() => {
    void load(1, true);
  }, [load]);
  useEffect(() => {
    const timer = window.setInterval(
      () => void load(pageRef.current),
      refreshMs,
    );
    return () => window.clearInterval(timer);
  }, [load, refreshMs]);

  return {
    targets,
    scans,
    loading,
    refreshing,
    error,
    totalPages,
    page: pageRef.current,
    load,
  };
}
