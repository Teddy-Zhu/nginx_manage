package nodes

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/remoteapi"
)

// Pairing has two fixed RPC methods. The short code authenticates only the
// exchange body; cookies and client-supplied forwarding headers never cross.
func pairingRPC(ctx context.Context, ep remoteapi.Endpoint, node, id string, confirm bool, input, output any) error {
	client, base, err := remoteapi.Client(ep)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	suffix := "exchange"
	if confirm {
		suffix = "confirm"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/remote/pairings/"+id+"/"+suffix, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(remoteapi.TargetHeader, node)
	req.Header.Set(remoteapi.ProtocolHeader, "1")
	if confirm {
		req.Header.Set("Authorization", "Bearer "+ep.APIKey)
	}
	response, err := client.Do(req)
	if err != nil {
		return fault.New(http.StatusBadGateway, "PAIRING_RESULT_UNKNOWN", "配对请求结果未确认，请续办原记录，勿重新交换授权")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
	media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	var envelope envelope
	if err != nil || mediaErr != nil || media != "application/json" || len(body) > 256<<10 || json.Unmarshal(body, &envelope) != nil || envelope.NodeID != node || response.Header.Get("X-Node-ID") != node || response.Header.Get(remoteapi.ProtocolHeader) != "1" || !uuid.MatchString(envelope.RequestID) || envelope.Code == "" || envelope.Data == nil {
		return fault.New(http.StatusBadGateway, "PAIRING_RESPONSE_UNCONFIRMED", "目标身份或配对回执无法核验，请核对原配对记录")
	}
	if response.StatusCode != http.StatusOK || envelope.Code != "OK" {
		if envelope.Code == "PAIRING_UNAVAILABLE" || envelope.Code == "UNAUTHENTICATED" {
			return fault.New(http.StatusConflict, "PAIRING_UNAVAILABLE", "目标配对信息或授权已失效，请先在目标核对并撤销原配对")
		}
		return fault.New(http.StatusBadGateway, "PAIRING_TARGET_REJECTED", "目标未接受配对操作，请检查配对期限、允许来源、授权及维护状态")
	}
	if json.Unmarshal(envelope.Data, output) != nil {
		return fault.New(http.StatusBadGateway, "PAIRING_RESPONSE_UNCONFIRMED", "目标配对数据无效，请核对原配对记录")
	}
	return nil
}
