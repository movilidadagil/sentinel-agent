// Thin client for the Sentinel backend.

export async function getHealth() {
  const r = await fetch("/api/health");
  return r.json();
}

export async function validateTarget(target) {
  const r = await fetch("/api/validate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target }),
  });
  return r.json();
}

// Streams the scan, invoking onEvent for every StreamEvent as it arrives.
// Returns a function that aborts the in-flight scan.
export function streamScan(target, onEvent, onError) {
  const controller = new AbortController();

  (async () => {
    try {
      const resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
        signal: controller.signal,
      });
      if (!resp.ok || !resp.body) {
        throw new Error(`Scan request failed (HTTP ${resp.status}).`);
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      // Parse the text/event-stream frames (separated by a blank line).
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        let sep;
        while ((sep = buffer.indexOf("\n\n")) !== -1) {
          const frame = buffer.slice(0, sep);
          buffer = buffer.slice(sep + 2);
          const dataLine = frame
            .split("\n")
            .find((l) => l.startsWith("data:"));
          if (dataLine) {
            const json = dataLine.slice(5).trim();
            try {
              onEvent(JSON.parse(json));
            } catch {
              /* ignore malformed frame */
            }
          }
        }
      }
    } catch (err) {
      if (err.name !== "AbortError") onError?.(err);
    }
  })();

  return () => controller.abort();
}
