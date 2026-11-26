import type {
  Certificate,
  CertificateInput,
  CertificateResult,
  ACMEAccount,
  ACMEAccountInput,
  ACMEChangeResult,
  ACMEProfile,
  ACMEProfileInput,
  ACMEIssueInput,
  ACMEArchiveInput,
  ACMEPolicyInput,
  CertificateDeployPreview,
  CertificateDeployInput,
  CertificateDeployment,
  CertificateDeploymentStatus,
  ACMEOrder,
  DNSProvider,
  DNSCredential,
  DNSCredentialInput,
} from "../types";
import type { APIRequest } from "../transport";

export function createCertificatesAPI(request: APIRequest) {
  return {
    acmeProfiles: (offset = 0) =>
      request<ACMEProfile[]>({
        url: "/acme-profiles",
        params: { limit: 100, offset },
      }),
    acmeOrders: (id: string) =>
      request<ACMEOrder[]>({ url: `/acme-profiles/${id}/orders` }),
    createACMEProfile: (data: ACMEProfileInput, key: string) =>
      request<ACMEChangeResult>({
        method: "POST",
        url: "/acme-profiles",
        data,
        headers: { "Idempotency-Key": key },
      }),
    issueACMEProfile: (id: string, data: ACMEIssueInput, key: string) =>
      request<ACMEChangeResult>({
        activity: "申请网站证书",
        method: "POST",
        url: `/acme-profiles/${id}/issue`,
        data,
        headers: { "Idempotency-Key": key },
      }),
    updateACMEPolicy: (id: string, data: ACMEPolicyInput, key: string) =>
      request<ACMEChangeResult>({
        method: "PUT",
        url: `/acme-profiles/${id}/policy`,
        data,
        headers: { "Idempotency-Key": key },
      }),
    archiveACMEProfile: (id: string, data: ACMEArchiveInput, key: string) =>
      request<ACMEChangeResult>({
        method: "POST",
        url: `/acme-profiles/${id}/archive`,
        data,
        headers: { "Idempotency-Key": key },
      }),
    acmeAccounts: () => request<ACMEAccount[]>({ url: "/acme-accounts" }),
    createACMEAccount: (data: ACMEAccountInput, key: string) =>
      request<ACMEChangeResult>({
        method: "POST",
        url: "/acme-accounts",
        data,
        headers: { "Idempotency-Key": key },
      }),
    registerACMEAccount: (id: string, version: number, key: string) =>
      request<ACMEChangeResult>({
        activity: "注册证书账户",
        method: "POST",
        url: `/acme-accounts/${id}/register`,
        data: { base_version: version, terms_agreed: true },
        headers: { "Idempotency-Key": key },
      }),
    deleteACMEAccount: (id: string, version: number, key: string) =>
      request<ACMEChangeResult>({
        method: "DELETE",
        url: `/acme-accounts/${id}`,
        data: { base_version: version },
        headers: { "Idempotency-Key": key },
      }),
    dnsProviders: () => request<DNSProvider[]>({ url: "/dns-providers" }),
    dnsCredentials: () => request<DNSCredential[]>({ url: "/dns-credentials" }),
    saveDNSCredential: (
      id: string | null,
      data: DNSCredentialInput,
      key: string,
    ) =>
      request<ACMEChangeResult>({
        method: id ? "PUT" : "POST",
        url: id ? `/dns-credentials/${id}` : "/dns-credentials",
        data,
        headers: { "Idempotency-Key": key },
      }),
    deleteDNSCredential: (id: string, version: number, key: string) =>
      request<ACMEChangeResult>({
        method: "DELETE",
        url: `/dns-credentials/${id}`,
        data: { base_version: version },
        headers: { "Idempotency-Key": key },
      }),
    certificates: () => request<Certificate[]>({ url: "/certificates" }),
    certificate: (id: string) =>
      request<Certificate>({ url: `/certificates/${encodeURIComponent(id)}` }),
    certificateDeployments: (id: string) =>
      request<CertificateDeploymentStatus>({
        url: `/certificates/${encodeURIComponent(id)}/deployments`,
      }),
    previewCertificateDeploy: (id: string) =>
      request<CertificateDeployPreview>({
        url: `/certificates/${encodeURIComponent(id)}/deploy-preview`,
      }),
    deployCertificate: (
      id: string,
      data: CertificateDeployInput,
      key: string,
    ) =>
      request<CertificateDeployment>({
        activity: "部署网站证书",
        method: "POST",
        url: `/certificates/${encodeURIComponent(id)}/deploy`,
        data,
        headers: { "Idempotency-Key": key },
      }),
    importCertificate: (
      id: string | null,
      data: CertificateInput,
      key: string,
    ) =>
      request<CertificateResult>({
        method: id ? "PUT" : "POST",
        url: `/certificates${id ? "/" + encodeURIComponent(id) + "/versions" : ""}`,
        data,
        headers: { "Idempotency-Key": key },
      }),
    deleteCertificate: (id: string, base_version: number, key: string) =>
      request<CertificateResult>({
        method: "DELETE",
        url: `/certificates/${encodeURIComponent(id)}`,
        data: { base_version },
        headers: { "Idempotency-Key": key },
      }),
  };
}
