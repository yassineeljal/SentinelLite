import type { IncidentStatus } from "./api/types";

export const statusLabels: Record<IncidentStatus, string> = {
  new: "New",
  investigating: "Investigating",
  closed: "Closed",
};
