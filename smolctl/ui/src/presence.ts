import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";

export type PresenceEvent = {
  device: string;
  name: string | null;
  hostname: string | null;
  ip: string;
  online: boolean;
};

export function usePresence(onEvent?: (event: PresenceEvent) => void) {
  const queries = useQueryClient();

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${protocol}://${window.location.host}/api/events`);

    socket.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as PresenceEvent;

        onEvent?.(event);
        queries.invalidateQueries({ queryKey: ["devices"] });
      } catch {
        // a frame we do not understand is not worth tearing the socket down for
      }
    };

    return () => socket.close();
  }, [queries, onEvent]);
}
