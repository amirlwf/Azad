/** Live per-isolate counters shared by the tunnel and the admin API. */
export interface TunnelStats {
  inflightByUser: Map<string, number>;
  total: number;
}

export const tunnelStats: TunnelStats = { inflightByUser: new Map(), total: 0 };
