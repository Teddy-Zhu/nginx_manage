package fail2ban

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

func Address(value string) (string, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" {
		return "", fault.Invalid("请输入单个数值 IP 地址，不接受域名、网段或接口区域")
	}
	return ip.Unmap().String(), nil
}
func ManagedJailName(name string) bool {
	id, ok := strings.CutPrefix(name, "nginxpanel-")
	return ok && policyID.MatchString(id)
}

type AddressInput struct {
	EngineOwner string `json:"engine_owner"`
	AdoptionID  string `json:"adoption_id"`
	Jail        string `json:"jail"`
	IP          string `json:"ip"`
	Action      string `json:"action"`
	Target      string `json:"target"`
}

type AddressQuery struct {
	EngineOwner string `json:"engine_owner"`
	AdoptionID  string `json:"adoption_id"`
	Jail        string `json:"jail"`
	IP          string `json:"ip"`
}

func (in AddressQuery) Validate() error {
	ip, err := Address(in.IP)
	managed := in.EngineOwner == "managed" && in.AdoptionID == "" && ManagedJailName(in.Jail)
	existing := in.EngineOwner == "existing" && policyID.MatchString(in.AdoptionID) && existingJailName.MatchString(in.Jail) && !strings.HasPrefix(in.Jail, "nginxpanel-")
	if err != nil || ip != in.IP || !managed && !existing {
		return fault.Invalid("手动操作须明确实例所有者、有效接管标识、jail 和单个数值地址")
	}
	return nil
}

func (in AddressInput) Query() AddressQuery {
	return AddressQuery{EngineOwner: in.EngineOwner, AdoptionID: in.AdoptionID, Jail: in.Jail, IP: in.IP}
}

func (in AddressInput) Validate() error {
	if in.Query().Validate() != nil || in.Action != "ban" && in.Action != "unban" || len(in.Target) != 64 || strings.Trim(in.Target, "0123456789abcdef") != "" {
		return fault.Invalid("手动封禁操作的 jail、地址、动作或目标基准无效")
	}
	return nil
}

type AddressRequest struct {
	Protocol    int          `json:"protocol"`
	OperationID string       `json:"operation_id"`
	Input       AddressInput `json:"input"`
}

func (in AddressRequest) Valid() bool {
	return in.Protocol == protocol.Agent && policyID.MatchString(in.OperationID) && in.Input.Validate() == nil
}
func (in AddressRequest) Hash() string { raw, _ := json.Marshal(in); return secure.Hash(raw) }

type AddressStatus struct {
	EngineOwner string `json:"engine_owner"`
	AdoptionID  string `json:"adoption_id"`
	At          int64  `json:"at"`
	Jail        string `json:"jail"`
	IP          string `json:"ip"`
	Available   bool   `json:"available"`
	Backend     string `json:"backend"`
	Target      string `json:"target"`
	EngineState string `json:"engine_state"`
	ExpiresAt   int64  `json:"expires_at"`
	Permanent   bool   `json:"permanent"`
	BanTime     int64  `json:"ban_time"`
	CanBan      bool   `json:"can_ban"`
	ActionState string `json:"action_state"`
	Generation  string `json:"generation"`
	Reason      string `json:"reason"`
}

type AddressOperation struct {
	ID          string       `json:"id"`
	RequestHash string       `json:"request_hash"`
	Input       AddressInput `json:"input"`
	State       string       `json:"state"`
	Stage       string       `json:"stage"`
	Submission  string       `json:"submission"`
	EngineState string       `json:"engine_state"`
	ObservedAt  int64        `json:"observed_at"`
	ExpiresAt   int64        `json:"expires_at"`
	Permanent   bool         `json:"permanent"`
	Error       string       `json:"error"`
}

type AddressTask struct {
	TaskID      string `json:"task_id"`
	OperationID string `json:"operation_id"`
}
type AddressTaskStatus struct {
	ID          string            `json:"id"`
	OperationID string            `json:"operation_id"`
	State       string            `json:"state"`
	Stage       string            `json:"stage"`
	Error       string            `json:"error"`
	CreatedAt   int64             `json:"created_at"`
	Input       AddressInput      `json:"input"`
	Result      *AddressOperation `json:"result"`
}

type AddressExecutor interface {
	ReadFail2banAddress(context.Context, AddressQuery) (AddressStatus, error)
	ChangeFail2banAddress(context.Context, AddressRequest) (AddressOperation, error)
	Fail2banAddressOperation(context.Context, string) (AddressOperation, error)
}
