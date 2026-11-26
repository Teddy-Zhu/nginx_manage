import type {
  BackupInput,
  BackupPolicyInput,
  BackupPolicy,
  BackupRecord,
  BackupOverview,
  BackupDownloadTicket,
} from "../types";
import type { APIRequest } from "../transport";

export function createBackupsAPI(request: APIRequest) {
  return {
    backups: () => request<BackupOverview>({ url: "/backups" }),
    backup: (id: string) => request<BackupRecord>({ url: `/backups/${id}` }),
    createBackup: (data: BackupInput, key: string) =>
      request<BackupRecord>({
        url: "/backups",
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    deleteBackup: (id: string) =>
      request<BackupRecord>({ url: `/backups/${id}`, method: "DELETE" }),
    backupPolicy: () => request<BackupPolicy>({ url: "/backups/policy" }),
    saveBackupPolicy: (data: BackupPolicyInput) =>
      request<BackupPolicy>({ url: "/backups/policy", method: "PUT", data }),
    backupDownload: (id: string) =>
      request<BackupDownloadTicket>({
        url: `/backups/${id}/download`,
        method: "POST",
      }),
  };
}
