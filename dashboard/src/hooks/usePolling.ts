import { useCallback, useEffect, useRef, useState } from "react";

export type Polled<T> = {
  data: T | null;
  error: string | null;
  reload: () => void;
};

/**
 * Load `load()` now and every `intervalMs`, again whenever `key` changes.
 * A `null` key pauses loading (e.g. nothing selected). Responses that
 * arrive after the key changed are discarded.
 */
export function usePolling<T>(key: string | null, load: () => Promise<T>, intervalMs = 5000): Polled<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const loadRef = useRef(load);
  loadRef.current = load;
  const generation = useRef(0);

  const run = useCallback(async () => {
    const mine = generation.current;
    try {
      const next = await loadRef.current();
      if (mine === generation.current) {
        setData(next);
        setError(null);
      }
    } catch (cause) {
      if (mine === generation.current) setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, []);

  useEffect(() => {
    generation.current += 1;
    setData(null);
    setError(null);
    if (key === null) return;
    void run();
    const timer = window.setInterval(() => void run(), intervalMs);
    return () => window.clearInterval(timer);
  }, [key, intervalMs, run]);

  return { data, error, reload: () => void run() };
}
