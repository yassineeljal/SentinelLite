import type { IncidentStatus } from "./api/types";

export const statusLabels: Record<IncidentStatus, string> = {
  new: "New",
  investigating: "Investigating",
  closed: "Closed",
};

// Badge colour per status: new needs attention, investigating is in progress, closed is done.
export const statusBadge: Record<IncidentStatus, string> = {
  new: "badge-info",
  investigating: "badge-warn",
  closed: "badge-ok",
};
