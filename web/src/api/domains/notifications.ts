import type {
  NotificationPolicyInput,
  NotificationChannelInput,
  NotificationEvent,
  NotificationDelivery,
  NotificationChange,
  NotificationOverview,
} from "../types";
import type { APIRequest } from "../transport";

export function createNotificationsAPI(request: APIRequest) {
  return {
    notifications: (signal?: AbortSignal) =>
      request<NotificationOverview>({ url: "/notifications", signal }),
    notificationEvents: (limit = 30, offset = 0, signal?: AbortSignal) =>
      request<NotificationEvent[]>({
        url: "/notifications/events",
        params: { limit, offset },
        signal,
      }),
    notificationDeliveries: (
      channel_id = "",
      limit = 30,
      offset = 0,
      signal?: AbortSignal,
    ) =>
      request<NotificationDelivery[]>({
        url: "/notifications/deliveries",
        params: { channel_id, limit, offset },
        signal,
      }),
    setNotificationPolicy: (data: NotificationPolicyInput, key: string) =>
      request<NotificationChange>({
        method: "PUT",
        url: "/notifications/policy",
        data,
        headers: { "Idempotency-Key": key },
      }),
    saveNotificationChannel: (
      id: string,
      data: NotificationChannelInput,
      key: string,
    ) =>
      request<NotificationChange>({
        method: id ? "PUT" : "POST",
        url: id ? `/notifications/channels/${id}` : "/notifications/channels",
        data,
        headers: { "Idempotency-Key": key },
      }),
    notificationChannelAction: (
      id: string,
      base_version: number,
      action: "delete" | "test",
      key: string,
    ) =>
      request<NotificationChange>({
        method: action === "delete" ? "DELETE" : "POST",
        url: `/notifications/channels/${id}${action === "test" ? "/test" : ""}`,
        data: { base_version },
        headers: { "Idempotency-Key": key },
      }),
    retryNotification: (id: string, key: string) =>
      request<NotificationChange>({
        method: "POST",
        url: `/notifications/deliveries/${id}/retry`,
        headers: { "Idempotency-Key": key },
      }),
  };
}
