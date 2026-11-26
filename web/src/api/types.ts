import type { components, operations } from "./schema";
export type GeoIPSource = components["schemas"]["GeoIPSource"];
export type GeoIPState = components["schemas"]["GeoIPState"];
export type GeoIPSourceInput = components["schemas"]["GeoIPSourceInput"];
export type GeoIPUpdateInput = components["schemas"]["GeoIPUpdateInput"];
export type GeoIPResolveInput = components["schemas"]["GeoIPResolveInput"];
export type GeoIPResolved = components["schemas"]["GeoIPResolved"];
export type RuntimeHistoryFilter =
  components["schemas"]["RuntimeHistoryFilter"];
export type RuntimeHistoryExecuteInput =
  components["schemas"]["RuntimeHistoryExecuteInput"];
export type RuntimeHistoryPreview =
  components["schemas"]["RuntimeHistoryPreview"];
export type RuntimeHistoryStatus =
  components["schemas"]["RuntimeHistoryStatus"];
export type HistoryFilter = components["schemas"]["HistoryFilter"];
export type HistoryItem = components["schemas"]["HistoryItem"];
export type HistoryScope = components["schemas"]["HistoryScope"];
export type HistoryPreview = components["schemas"]["HistoryPreview"];
export type HistoryExecuteInput = components["schemas"]["HistoryExecuteInput"];
export type HistoryResult = components["schemas"]["HistoryResult"];
export type AuditFilter = components["schemas"]["AuditFilter"];
export type AuditRow = components["schemas"]["AuditRow"];
export type AuditPage = components["schemas"]["AuditPage"];
export type AuditQuery = operations["listAudit"]["parameters"]["query"];
export type BackupInput = components["schemas"]["BackupInput"];
export type BackupPolicyInput = components["schemas"]["BackupPolicyInput"];
export type BackupPolicy = components["schemas"]["BackupPolicy"];
export type BackupRecord = components["schemas"]["BackupRecord"];
export type BackupOverview = components["schemas"]["BackupOverview"];
export type BackupDownloadTicket =
  components["schemas"]["BackupDownloadTicket"];
export type ComponentOfflineInput =
  components["schemas"]["ComponentOfflineInput"];
export type ComponentOfflineChunk =
  components["schemas"]["ComponentOfflineChunk"];
export type ComponentOfflineAsset =
  components["schemas"]["ComponentOfflineAsset"];
export type ComponentOfflineUpload =
  components["schemas"]["ComponentOfflineUpload"];
export type FrpsConfig = components["schemas"]["FrpsConfig"];
export type FrpsStatus = components["schemas"]["FrpsStatus"];
export type FrpsRequest = components["schemas"]["FrpsRequest"];
export type DockerContainer = components["schemas"]["DockerContainer"];
export type DockerOverview = components["schemas"]["DockerOverview"];
export type DockerDetail = components["schemas"]["DockerDetail"];
export type DockerLogs = components["schemas"]["DockerLogs"];
export type DockerControl = components["schemas"]["DockerControl"];
export type SoftwareResult = components["schemas"]["SoftwareResult"];
export type SoftwareRequest = components["schemas"]["SoftwareRequest"];
export type ComponentVersion = components["schemas"]["ComponentVersion"];
export type ComponentVersionCatalog =
  components["schemas"]["ComponentVersionCatalog"];
export type UpdateChannel = components["schemas"]["UpdateChannel"];
export type ComponentInput = components["schemas"]["ComponentInput"];
export type ComponentCreateInput =
  components["schemas"]["ComponentCreateInput"];
export type ComponentOverview = components["schemas"]["ComponentOverview"];
export type ComponentAsset = components["schemas"]["ComponentAsset"];
export type ComponentRelease = components["schemas"]["ComponentRelease"];
export type ComponentOperation = components["schemas"]["ComponentOperation"];
export type ComponentTask = components["schemas"]["ComponentTask"];
export type CoreUpdateCheck = components["schemas"]["CoreUpdateCheck"];
export type ImageUpgradeTask = components["schemas"]["ImageUpgradeTask"];
export type NginxImageUpgradeCreateInput =
  components["schemas"]["NginxImageUpgradeCreateInput"];
export type PanelUpdateTask = components["schemas"]["PanelUpdateTask"];
export type PanelUpdateCreateInput =
  components["schemas"]["PanelUpdateCreateInput"];
export type NginxSwitchTask = components["schemas"]["NginxSwitchTask"];
export type NginxSwitchCreateInput =
  components["schemas"]["NginxSwitchCreateInput"];
export type NginxInstallTask = components["schemas"]["NginxInstallTask"];
export type NginxInstallCreateInput =
  components["schemas"]["NginxInstallCreateInput"];
export type Tree = components["schemas"]["Tree"];
export type ConfigFile = components["schemas"]["File"];
export type Resource = components["schemas"]["Resource"];
export type SaveResult = components["schemas"]["SaveResult"];
export type SaveRequest = components["schemas"]["SaveRequest"];
export type Me = components["schemas"]["Me"];
export type NodeConnection = components["schemas"]["NodeConnection"];
export type NodeCreateInput = components["schemas"]["NodeCreateInput"];
export type PairingInput = components["schemas"]["PairingInput"];
export type Pairing = components["schemas"]["Pairing"];
export type PairingOffer = components["schemas"]["PairingOffer"];
export type PairingJobInput = components["schemas"]["PairingJobInput"];
export type PairingJob = components["schemas"]["PairingJob"];
export type ManagementListenerInput =
  components["schemas"]["ManagementListenerInput"];
export type ManagementListenerOperation =
  components["schemas"]["ManagementListenerOperation"];
export type ManagementListenerView =
  components["schemas"]["ManagementListenerView"];
export type Task = components["schemas"]["Task"];
export type Module = components["schemas"]["Module"];
export type SystemVersion = components["schemas"]["SystemVersion"];
export type HostLinkDNS = components["schemas"]["HostLinkDNS"];
export type HostNetplanSource = components["schemas"]["HostNetplanSource"];
export type HostDNSOverview = components["schemas"]["HostDNSOverview"];
export type Fail2banTemplateCheck =
  components["schemas"]["Fail2banTemplateCheck"];
export type Fail2banPanelLoginEvent =
  components["schemas"]["Fail2banPanelLoginEvent"];
export type Fail2banPanelLoginStatus =
  components["schemas"]["Fail2banPanelLoginStatus"];
export type Fail2banHostInputPreview =
  components["schemas"]["Fail2banHostInputPreview"];
export type Fail2banTemplateCheckInput =
  components["schemas"]["Fail2banTemplateCheckInput"];
export type Fail2banDesiredJail = components["schemas"]["Fail2banDesiredJail"];
export type Fail2banPolicyView = components["schemas"]["Fail2banPolicyView"];
export type Fail2banPolicyInput = components["schemas"]["Fail2banPolicyInput"];
export type Fail2banTemplate = components["schemas"]["Fail2banTemplate"];
export type Fail2banPolicyPreview =
  components["schemas"]["Fail2banPolicyPreview"];
export type Fail2banPython = components["schemas"]["Fail2banPython"];
export type Fail2banPythonPackage =
  components["schemas"]["Fail2banPythonPackage"];
export type Fail2banPythonPlan = components["schemas"]["Fail2banPythonPlan"];
export type Fail2banPythonTaskInput =
  components["schemas"]["Fail2banPythonTaskInput"];
export type Fail2banPythonTaskOperation =
  components["schemas"]["Fail2banPythonTaskOperation"];
export type Fail2banPythonTask = components["schemas"]["Fail2banPythonTask"];
export type Fail2banPythonTaskStatus =
  components["schemas"]["Fail2banPythonTaskStatus"];
export type Fail2banManaged = components["schemas"]["Fail2banManaged"];
export type Fail2banService = components["schemas"]["Fail2banService"];
export type Fail2banUpgradeInput =
  components["schemas"]["Fail2banUpgradeInput"];
export type Fail2banUpgradeBans = components["schemas"]["Fail2banUpgradeBans"];
export type Fail2banUpgradePlan = components["schemas"]["Fail2banUpgradePlan"];
export type Fail2banUpgradePreparation =
  components["schemas"]["Fail2banUpgradePreparation"];
export type Fail2banUpgradeRunResult =
  components["schemas"]["Fail2banUpgradeRunResult"];
export type Fail2banUpgradeOperation =
  components["schemas"]["Fail2banUpgradeOperation"];
export type Fail2banUpgradeTask = components["schemas"]["Fail2banUpgradeTask"];
export type Fail2banUpgradeTaskStatus =
  components["schemas"]["Fail2banUpgradeTaskStatus"];
export type Fail2banLifecyclePreviewInput =
  components["schemas"]["Fail2banLifecyclePreviewInput"];
export type Fail2banLifecycleInput =
  components["schemas"]["Fail2banLifecycleInput"];
export type Fail2banLifecyclePlan =
  components["schemas"]["Fail2banLifecyclePlan"];
export type Fail2banLifecycleOperation =
  components["schemas"]["Fail2banLifecycleOperation"];
export type Fail2banLifecycleTask =
  components["schemas"]["Fail2banLifecycleTask"];
export type Fail2banLifecycleTaskStatus =
  components["schemas"]["Fail2banLifecycleTaskStatus"];
export type Fail2banAddressInput =
  components["schemas"]["Fail2banAddressInput"];
export type Fail2banExistingResource =
  components["schemas"]["Fail2banExistingResource"];
export type Fail2banExistingResourcePolicy =
  components["schemas"]["Fail2banExistingResourcePolicy"];
export type Fail2banExistingPolicy =
  components["schemas"]["Fail2banExistingPolicy"];
export type Fail2banExistingPolicyInput =
  components["schemas"]["Fail2banExistingPolicyInput"];
export type Fail2banExistingPlan =
  components["schemas"]["Fail2banExistingPlan"];
export type Fail2banExistingTaskStatus =
  components["schemas"]["Fail2banExistingTaskStatus"];
export type Fail2banExistingPolicyTask =
  components["schemas"]["Fail2banExistingPolicyTask"];
export type Fail2banAddressStatus =
  components["schemas"]["Fail2banAddressStatus"];
export type Fail2banAddressOperation =
  components["schemas"]["Fail2banAddressOperation"];
export type Fail2banAddressTask = components["schemas"]["Fail2banAddressTask"];
export type Fail2banAddressTaskStatus =
  components["schemas"]["Fail2banAddressTaskStatus"];
export type Fail2banApplyInput = components["schemas"]["Fail2banApplyInput"];
export type Fail2banApplyTask = components["schemas"]["Fail2banApplyTask"];
export type Fail2banApplyTaskStatus =
  components["schemas"]["Fail2banApplyTaskStatus"];
export type Fail2banJailsRuntime =
  components["schemas"]["Fail2banJailsRuntime"];
export type MigrationHostDNSInput =
  components["schemas"]["MigrationHostDNSInput"];
export type MigrationHostDNSPlan =
  components["schemas"]["MigrationHostDNSPlan"];
export type MigrationHostDNSItem =
  components["schemas"]["MigrationHostDNSItem"];
export type MigrationMonitoringInput =
  components["schemas"]["MigrationMonitoringInput"];
export type MigrationMonitoringPlan =
  components["schemas"]["MigrationMonitoringPlan"];
export type MigrationFail2banInput =
  components["schemas"]["MigrationFail2banInput"];
export type MigrationFail2banPlan =
  components["schemas"]["MigrationFail2banPlan"];
export type Fail2banInstance = components["schemas"]["Fail2banInstance"];
export type Fail2banJail = components["schemas"]["Fail2banJail"];
export type Fail2banContainerStatus =
  components["schemas"]["Fail2banContainerStatus"];
export type Fail2banContainerRule =
  components["schemas"]["Fail2banContainerRule"];
export type Fail2banContainerConfig =
  components["schemas"]["Fail2banContainerConfig"];
export type Fail2banContainerRequest =
  components["schemas"]["Fail2banContainerRequest"];
export type Fail2banObservation = components["schemas"]["Fail2banObservation"];
export type FirewallObservation = components["schemas"]["FirewallObservation"];
export type FirewallRule = components["schemas"]["FirewallRule"];
export type FirewallPolicy = components["schemas"]["FirewallPolicy"];
export type FirewallPolicyView = components["schemas"]["FirewallPolicyView"];
export type FirewallPolicyInput = components["schemas"]["FirewallPolicyInput"];
export type FirewallPlanInput = components["schemas"]["FirewallPlanInput"];
export type FirewallPlan = components["schemas"]["FirewallPlan"];
export type FirewallOperation = components["schemas"]["FirewallOperation"];
export type FirewallRuntime = components["schemas"]["FirewallRuntime"];
export type FirewallApplyInput = components["schemas"]["FirewallApplyInput"];
export type FirewallPreview = components["schemas"]["FirewallPreview"];
export type HostDNSPlan = components["schemas"]["HostDNSPlan"];
export type HostDNSPlanInput = components["schemas"]["HostDNSPlanInput"];
export type HostDNSChange = components["schemas"]["HostDNSChange"];
export type ResourceMetadata = components["schemas"]["ResourceMetadata"];
export type AccessList = components["schemas"]["AccessList"];
export type WAFConfig = components["schemas"]["WAFConfig"];
export type WAFInput = components["schemas"]["WAFInput"];
export type WAFPolicy = components["schemas"]["WAFPolicy"];
export type NginxFeatures = components["schemas"]["NginxFeatures"];
export type Certificate = components["schemas"]["Certificate"];
export type CertificateVersion = components["schemas"]["CertificateVersion"];
export type CertificateInput = components["schemas"]["CertificateInput"];
export type CertificateResult = components["schemas"]["CertificateResult"];
export type ACMEAccount = components["schemas"]["ACMEAccount"];
export type ACMEAccountInput = components["schemas"]["ACMEAccountInput"];
export type ACMEChangeResult = components["schemas"]["ACMEChangeResult"];
export type ACMEProfile = components["schemas"]["ACMEProfile"];
export type ACMEProfileInput = components["schemas"]["ACMEProfileInput"];
export type ACMEIssueInput = components["schemas"]["ACMEIssueInput"];
export type ACMEArchiveInput = components["schemas"]["ACMEArchiveInput"];
export type ACMEPolicyInput = components["schemas"]["ACMEPolicyInput"];
export type CertificateDeployPreview =
  components["schemas"]["CertificateDeployPreview"];
export type CertificateDeployInput =
  components["schemas"]["CertificateDeployInput"];
export type CertificateDeployment =
  components["schemas"]["CertificateDeployment"];
export type CertificateDeploymentStatus =
  components["schemas"]["CertificateDeploymentStatus"];
export type ACMEOrder = components["schemas"]["ACMEOrder"];
export type DNSProvider = components["schemas"]["DNSProvider"];
export type DNSCredential = components["schemas"]["DNSCredential"];
export type DNSCredentialInput = components["schemas"]["DNSCredentialInput"];
export type AccessListInput = components["schemas"]["AccessListInput"];
export type NginxRuntime = components["schemas"]["NginxRuntime"];
export type Difference = components["schemas"]["Difference"];
export type ExternalSnapshot = components["schemas"]["ExternalSnapshot"];
export type CaptureExternalRequest =
  components["schemas"]["CaptureExternalRequest"];
export type RestoreExternalRequest =
  components["schemas"]["RestoreExternalRequest"];
export type NativeModulesRequest =
  components["schemas"]["NativeModulesRequest"];
export type LogSource = components["schemas"]["LogSource"];
export type LogQuery = components["schemas"]["LogQuery"];
export type LogPage = components["schemas"]["LogPage"];
export type LogRow = components["schemas"]["LogRow"];
export type LogPolicyView = components["schemas"]["LogPolicyView"];
export type LogPolicyInput = components["schemas"]["LogPolicyInput"];
export type MonitoringCapability =
  components["schemas"]["MonitoringCapability"];
export type MonitoringThreshold = components["schemas"]["MonitoringThreshold"];
export type MonitoringSettings = components["schemas"]["MonitoringSettings"];
export type MonitoringSettingsView =
  components["schemas"]["MonitoringSettingsView"];
export type MonitoringSettingsInput =
  components["schemas"]["MonitoringSettingsInput"];
export type HostMetric = components["schemas"]["HostMetric"];
export type MonitoredService = components["schemas"]["MonitoredService"];
export type MonitoringSample = components["schemas"]["MonitoringSample"];
export type MonitoringCondition = components["schemas"]["MonitoringCondition"];
export type MonitoringLatest = components["schemas"]["MonitoringLatest"];
export type MonitoringPoint = components["schemas"]["MonitoringPoint"];
export type MonitoringHistory = components["schemas"]["MonitoringHistory"];
export type NotificationKind = components["schemas"]["NotificationKind"];
export type NotificationPolicy = components["schemas"]["NotificationPolicy"];
export type NotificationPolicyView =
  components["schemas"]["NotificationPolicyView"];
export type NotificationPolicyInput =
  components["schemas"]["NotificationPolicyInput"];
export type NotificationVersionInput =
  components["schemas"]["NotificationVersionInput"];
export type NotificationChannelInput =
  components["schemas"]["NotificationChannelInput"];
export type NotificationChannel = components["schemas"]["NotificationChannel"];
export type NotificationEvent = components["schemas"]["NotificationEvent"];
export type NotificationPayload = components["schemas"]["NotificationPayload"];
export type NotificationDelivery =
  components["schemas"]["NotificationDelivery"];
export type NotificationChange = components["schemas"]["NotificationChange"];
export type NotificationHealth = components["schemas"]["NotificationHealth"];
export type NotificationOverview =
  components["schemas"]["NotificationOverview"];
export type MigrationDependencyStatus =
  components["schemas"]["MigrationDependencyStatus"];
export type MigrationDependencyInput =
  components["schemas"]["MigrationDependencyInput"];
export type MigrationPushInput = components["schemas"]["MigrationPushInput"];
export type MigrationPushTask = components["schemas"]["MigrationPushTask"];
export type MigrationPushResumeInput =
  components["schemas"]["MigrationPushResumeInput"];
export type MigrationSelection = components["schemas"]["MigrationSelection"];
export type MigrationExportInput =
  components["schemas"]["MigrationExportInput"];
export type MigrationImportInput =
  components["schemas"]["MigrationImportInput"];
export type MigrationPullInput = components["schemas"]["MigrationPullInput"];
export type MigrationExecuteInput =
  components["schemas"]["MigrationExecuteInput"];
export type MigrationFirewallInput =
  components["schemas"]["MigrationFirewallInput"];
export type MigrationFirewallPlan =
  components["schemas"]["MigrationFirewallPlan"];
export type MigrationPlan = components["schemas"]["MigrationPlan"];
export type MigrationPackage = components["schemas"]["MigrationPackage"];
