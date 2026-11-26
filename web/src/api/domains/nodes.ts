import type {
  NodeConnection,
  NodeCreateInput,
  PairingInput,
  Pairing,
  PairingOffer,
  PairingJobInput,
  PairingJob,
} from "../types";
import type { APIRequest } from "../transport";

export function createNodesAPI(request: APIRequest) {
  return {
    nodes: (signal?: AbortSignal) =>
      request<NodeConnection[]>({ url: "/nodes", signal }),
    pairings: () => request<Pairing[]>({ url: "/remote/pairings" }),
    createPairing: (data: PairingInput, key: string) =>
      request<PairingOffer>({
        url: "/remote/pairings",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    revokePairing: (id: string) =>
      request<Pairing>({ url: `/remote/pairings/${id}`, method: "DELETE" }),
    pairingJobs: () => request<PairingJob[]>({ url: "/nodes/pairings" }),
    startPairing: (data: PairingJobInput, key: string) =>
      request<PairingJob>({
        url: "/nodes/pairings",
        method: "POST",
        data,
        timeout: 30_000,
        headers: { "Idempotency-Key": key },
      }),
    resumePairing: (id: string) =>
      request<PairingJob>({
        url: `/nodes/pairings/${id}/resume`,
        method: "POST",
        timeout: 30_000,
      }),
    abandonPairing: (id: string) =>
      request<PairingJob>({
        url: `/nodes/pairings/${id}/abandon`,
        method: "POST",
        timeout: 25_000,
      }),
    createNode: (data: NodeCreateInput, key: string) =>
      request<NodeConnection>({
        url: "/nodes",
        method: "POST",
        data,
        timeout: 30_000,
        headers: { "Idempotency-Key": key },
      }),
    refreshNode: (id: string, key: string) =>
      request<NodeConnection>({
        url: `/nodes/${id}/refresh`,
        method: "POST",
        timeout: 30_000,
        headers: { "Idempotency-Key": key },
      }),
    deleteNode: (id: string, key: string) =>
      request<NodeConnection>({
        url: `/nodes/${id}`,
        method: "DELETE",
        timeout: 30_000,
        headers: { "Idempotency-Key": key },
      }),
  };
}
