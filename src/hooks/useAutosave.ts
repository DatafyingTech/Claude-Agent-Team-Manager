import { useEffect, useRef } from "react";

/**
 * Auto-saves editor changes after a debounce period.
 * Skips the initial mount and node-switch re-initialization to avoid false saves.
 * Flushes pending saves on unmount AND on node switch (covers AI-generated changes
 * that haven't triggered a timeout yet).
 */
export function useAutosave(
  saveFn: () => void,
  triggers: unknown[],
  nodeId: string,
  delay = 800,
) {
  const saveFnRef = useRef(saveFn);
  // Keep a snapshot of the save function from the previous render so that when
  // nodeId changes we can flush the *old* node's data (with its correct id and
  // local state) before the current render's saveFn — which already references
  // the new node's id but still has stale local state — overwrites it.
  const prevSaveFnRef = useRef(saveFn);
  saveFnRef.current = saveFn;
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Skip 2: first for the initial effect run, second for the re-init setState re-render
  const skipRef = useRef(2);
  // Track whether any real changes happened since the last save
  const dirtyRef = useRef(false);

  // Reset skip counter when node changes — flush any unsaved work first
  useEffect(() => {
    if (dirtyRef.current) {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
      // Use prevSaveFnRef: it still holds the save function from the render
      // BEFORE nodeId changed, so it targets the correct (old) node id with
      // the correct (old) local-state values.
      prevSaveFnRef.current();
      dirtyRef.current = false;
    }
    // Now promote the current saveFn so subsequent flushes use the right one
    prevSaveFnRef.current = saveFnRef.current;
    skipRef.current = 2;
  }, [nodeId]);

  // Debounced save on trigger change
  useEffect(() => {
    if (skipRef.current > 0) {
      skipRef.current--;
      return;
    }

    dirtyRef.current = true;

    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = setTimeout(() => {
      saveFnRef.current();
      dirtyRef.current = false;
      timeoutRef.current = null;
    }, delay);

    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, triggers);

  // Keep prevSaveFnRef in sync after every render so it's always one-render-behind
  // when a nodeId change occurs. This runs after the nodeId effect, so on a
  // nodeId-change render the promotion inside the nodeId effect takes priority.
  useEffect(() => {
    prevSaveFnRef.current = saveFnRef.current;
  });

  // Flush pending save on unmount (user clicked away)
  useEffect(() => {
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      if (dirtyRef.current) {
        saveFnRef.current();
        dirtyRef.current = false;
      }
    };
  }, []);
}
