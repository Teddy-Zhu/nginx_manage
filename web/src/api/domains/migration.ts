import type {
  MigrationDependencyInput,
  MigrationPushInput,
  MigrationPushTask,
  MigrationPushResumeInput,
  MigrationExportInput,
  MigrationImportInput,
  MigrationPullInput,
  MigrationExecuteInput,
  MigrationPlan,
  MigrationPackage,
} from "../types";
import type { APIRequest } from "../transport";

export function createMigrationAPI(request: APIRequest) {
  return {
    exportMigration: (data: MigrationExportInput) =>
      request<MigrationPackage>({
        method: "POST",
        url: "/migrations/export",
        data,
        timeout: 45_000,
      }),
    prepareMigration: (data: MigrationImportInput) =>
      request<MigrationPlan>({
        method: "POST",
        url: "/migrations/plan",
        data,
        timeout: 45_000,
      }),
    preflightMigration: (id: string) =>
      request<MigrationPlan>({
        url: `/migrations/${id}/preflight`,
        method: "POST",
      }),
    prepareMigrationDependencies: (
      id: string,
      data: MigrationDependencyInput,
      key: string,
    ) =>
      request<MigrationPlan>({
        url: `/migrations/${id}/dependencies`,
        method: "POST",
        data,
        headers: { "Idempotency-Key": key },
      }),
    executeMigration: (id: string, data: MigrationExecuteInput, key: string) =>
      request<MigrationPlan>({
        method: "POST",
        url: `/migrations/${encodeURIComponent(id)}/execute`,
        data,
        headers: { "Idempotency-Key": key },
        timeout: 45_000,
      }),
    startMigrationPush: (data: MigrationPushInput, key: string) =>
      request<MigrationPushTask>({
        activity: "迁移到目标服务器",
        method: "POST",
        url: "/migrations/push",
        data,
        headers: { "Idempotency-Key": key },
        timeout: 45_000,
      }),
    migrationPushes: (signal?: AbortSignal) =>
      request<MigrationPushTask[]>({ url: "/migrations/push", signal }),
    migrationPush: (id: string, signal?: AbortSignal) =>
      request<MigrationPushTask>({
        url: `/migrations/push/${encodeURIComponent(id)}`,
        signal,
      }),
    resumeMigrationPush: (
      id: string,
      data: MigrationPushResumeInput,
      key: string,
    ) =>
      request<MigrationPushTask>({
        activity: "迁移到目标服务器",
        method: "POST",
        url: `/migrations/push/${encodeURIComponent(id)}/resume`,
        data,
        headers: { "Idempotency-Key": key },
      }),
    pullMigration: (data: MigrationPullInput, key: string) =>
      request<MigrationPlan>({
        method: "POST",
        url: "/migrations/pull",
        data,
        headers: { "Idempotency-Key": key },
        timeout: 45_000,
      }),
    migrations: (signal?: AbortSignal) =>
      request<MigrationPlan[]>({ url: "/migrations", signal }),
    migration: (id: string, signal?: AbortSignal) =>
      request<MigrationPlan>({
        url: `/migrations/${encodeURIComponent(id)}`,
        signal,
      }),
  };
}
