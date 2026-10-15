// Package limits defines the resource budgets shared by HTTP, parsing and IPC.
package limits

const (
	RequestBytes             = 4 << 20
	TreeBytes                = 2 << 20
	FileBytes                = 256 << 10
	Files                    = 128
	PublishedRevisions       = 128
	NginxListeners           = 256
	NginxModules             = 16
	StoredNginxModules       = 128
	StoredNginxModuleBytes   = 256 << 20
	NginxModuleBytes         = 8 << 20
	NginxModuleBundleBytes   = 32 << 20
	NginxBinaryBytes         = 64 << 20
	CertificateReferences    = 128
	Certificates             = 128
	ACMEAccounts             = 16
	ACMEProfiles             = 2048
	DNSCredentials           = 32
	ACMEOrders               = 2048
	ACMEDNSRecords           = 8192
	CertificateVersions      = 32
	CertificateChain         = 16
	CertificateMaterialBytes = 128 << 10
	CertificateBundleBytes   = 1 << 20
	WAFPolicies              = 32
	WAFPaths                 = 128
	Directives               = 20000
	Depth                    = 32
	PageSize                 = 100
	QueuedTasks              = 100
	TaskWorkers              = 4
	SSEConnections           = 16
	LogScanBytes             = 16 << 20
	LogSources               = 2048
	PublishedLogSources      = 512
	LogArchives              = 16384
	LogSourceArchives        = 128
	LogLineBytes             = 64 << 10
	LogCursorSessions        = 32
	LogQueryConcurrency      = 4
	StagingBytes             = 256 << 20
	BackupBytes              = 2 << 30
	MetricCPUs               = 128
	MetricInterfaces         = 32
	MetricMounts             = 32
	MetricIntervalSeconds    = 15
	MetricRetentionHours     = 24
)
