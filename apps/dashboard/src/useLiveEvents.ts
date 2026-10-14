/**
 * SSE subscription with a polling fallback.
 *
 * `EventSource` cannot send an `Authorization` header, which is fine because the stream
 * is a read-only GET and reads are unauthenticated in this single-user development
 * control plane. If the stream fails -- a proxy that buffers, a browser that blocks it --
 * the hook degrades to polling rather than silently showing stale data, and reports
 * which mode it is in so the UI can say so honestly.
 */

import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import type { AuditEvent } from "./types";

export type LiveMode = "connecting" | "stream" | "polling" | "error";

export interface LiveState {
  mode: LiveMode;
  lastSeq: number;
  lastEventAt: number | null;
  events: AuditEvent[];
}

export function useLiveEvents(onEvent?: (event: AuditEvent) => void): LiveState {
  const [state, setState] = useState<LiveState>({
    mode: "connecting",
    lastSeq: 0,
    lastEventAt: null,
    events: [],
  });
  const handler = useRef(onEvent);
  handler.current = onEvent;
  const seqRef = useRef(0);

  useEffect(() => {
    let cancelled = false;
    let source: EventSource | null = null;
    let pollTimer: number | null = null;

    function absorb(incoming: AuditEvent[], mode: LiveMode) {
      if (cancelled || incoming.length === 0) {
        if (!cancelled) setState((prev) => (prev.mode === mode ? prev : { ...prev, mode }));
        return;
      }
      for (const event of incoming) {
        seqRef.current = Math.max(seqRef.current, event.seq);
        handler.current?.(event);
      }
      setState((prev) => ({
        mode,
        lastSeq: seqRef.current,
        lastEventAt: Date.now(),
        events: [...incoming, ...prev.events].slice(0, 300),
      }));
    }

    function startPolling() {
      if (pollTimer !== null) return;
      const tick = async () => {
        try {
          const page = await api.events(seqRef.current);
          absorb(page.events, "polling");
        } catch {
          if (!cancelled) setState((prev) => ({ ...prev, mode: "error" }));
        }
      };
      void tick();
      pollTimer = window.setInterval(tick, 1500);
    }

    // Prime from the REST endpoint so the panel is populated on first paint, then stream.
    void (async () => {
      try {
        const page = await api.events(0);
        if (cancelled) return;
        seqRef.current = page.latest_seq;
        setState({
          mode: "connecting",
          lastSeq: page.latest_seq,
          lastEventAt: page.events.length > 0 ? Date.now() : null,
          events: page.events.slice(-300).reverse(),
        });
      } catch {
        if (!cancelled) setState((prev) => ({ ...prev, mode: "error" }));
        return;
      }

      if (typeof EventSource === "undefined") {
        startPolling();
        return;
      }

      try {
        source = new EventSource(api.streamUrl(seqRef.current));
        source.addEventListener("open", () => {
          if (!cancelled) setState((prev) => ({ ...prev, mode: "stream" }));
        });
        source.addEventListener("decision", (raw) => {
          try {
            absorb([JSON.parse((raw as MessageEvent).data) as AuditEvent], "stream");
          } catch {
            /* ignore a malformed frame rather than tearing down the stream */
          }
        });
        source.addEventListener("error", () => {
          source?.close();
          source = null;
          startPolling();
        });
      } catch {
        startPolling();
      }
    })();

    return () => {
      cancelled = true;
      source?.close();
      if (pollTimer !== null) window.clearInterval(pollTimer);
    };
  }, []);

  return state;
}
