package nodes

import "nginxpanel/internal/auth"

type PairingInput struct {
	Name                string   `json:"name"`
	ControllerNodeID    string   `json:"controller_node_id"`
	Scopes              []string `json:"scopes"`
	AllowedSources      []string `json:"allowed_sources"`
	CredentialExpiresAt int64    `json:"credential_expires_at"`
}

type Pairing struct {
	ID                  string   `json:"id"`
	NodeID              string   `json:"node_id"`
	Name                string   `json:"name"`
	ControllerNodeID    string   `json:"controller_node_id"`
	Scopes              []string `json:"scopes"`
	AllowedSources      []string `json:"allowed_sources"`
	CredentialExpiresAt int64    `json:"credential_expires_at"`
	CredentialID        string   `json:"credential_id"`
	State               string   `json:"state"`
	CreatedAt           int64    `json:"created_at"`
	ExpiresAt           int64    `json:"expires_at"`
	ClaimedAt           int64    `json:"claimed_at"`
	ConfirmedAt         int64    `json:"confirmed_at"`
	RevokedAt           int64    `json:"revoked_at"`
	principal           string
	machine             bool
	epoch               int64
	secretHash          string
	claimHash           string
	token               []byte
}

type PairingOffer struct {
	Pairing Pairing `json:"pairing"`
	Secret  string  `json:"secret"`
}

type PairingClaim struct {
	Secret           string `json:"secret"`
	ControllerNodeID string `json:"controller_node_id"`
	Claim            string `json:"claim"`
}

type PairingConfirmation struct {
	ControllerNodeID string `json:"controller_node_id"`
	Claim            string `json:"claim"`
}

type PairingExchange struct {
	Pairing Pairing `json:"pairing"`
	Token   string  `json:"token"`
}

type PairingJobInput struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	Fingerprint  string `json:"fingerprint"`
	TargetNodeID string `json:"target_node_id"`
	PairingID    string `json:"pairing_id"`
	Secret       string `json:"secret"`
}

type PairingJob struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	URL              string `json:"url"`
	Fingerprint      string `json:"fingerprint"`
	ControllerNodeID string `json:"controller_node_id"`
	TargetNodeID     string `json:"target_node_id"`
	PairingID        string `json:"pairing_id"`
	CredentialID     string `json:"credential_id"`
	ConnectionID     string `json:"connection_id"`
	State            string `json:"state"`
	Stage            string `json:"stage"`
	Error            string `json:"error"`
	Revocation       string `json:"revocation"`
	CreatedAt        int64  `json:"created_at"`
	UpdatedAt        int64  `json:"updated_at"`
	principal        string
	material         []byte
}

func (in PairingInput) credential() auth.CredentialInput {
	return auth.CredentialInput{Name: in.Name, Scopes: in.Scopes, AllowedSources: in.AllowedSources, ExpiresAt: in.CredentialExpiresAt}
}
