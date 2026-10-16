package nodes

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/remoteapi"
	"nginxpanel/internal/secure"
)

const pairingJobColumns = "id,principal,name,endpoint,fingerprint,controller_node_id,target_node_id,pairing_id,material,credential_id,COALESCE(connection_id,''),state,stage,last_error,revocation,created_at,updated_at"

type pairingMaterial struct{ Secret, Claim, Token string }

func readPairingJob(row scanner) (PairingJob, error) {
	var j PairingJob
	err := row.Scan(&j.ID, &j.principal, &j.Name, &j.URL, &j.Fingerprint, &j.ControllerNodeID, &j.TargetNodeID, &j.PairingID, &j.material, &j.CredentialID, &j.ConnectionID, &j.State, &j.Stage, &j.Error, &j.Revocation, &j.CreatedAt, &j.UpdatedAt)
	return j, err
}
func (s *Service) pairingJob(ctx context.Context, p auth.Principal, id string) (PairingJob, error) {
	if err := p.Require("nodes.manage", "read"); err != nil {
		return PairingJob{}, err
	}
	if !uuid.MatchString(id) {
		return PairingJob{}, fault.Invalid("配对记录标识无效")
	}
	return readPairingJob(s.DB.QueryRowContext(ctx, "SELECT "+pairingJobColumns+" FROM node_pairing_jobs WHERE id=? AND principal=?", id, p.ID))
}
func (s *Service) ListPairingJobs(ctx context.Context, p auth.Principal) ([]PairingJob, error) {
	if err := p.Require("nodes.manage", "read"); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+pairingJobColumns+" FROM node_pairing_jobs WHERE principal=? ORDER BY created_at DESC,id", p.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PairingJob{}
	for rows.Next() {
		j, err := readPairingJob(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, j)
	}
	return result, rows.Err()
}
func (s *Service) GetPairingJob(ctx context.Context, p auth.Principal, id string) (PairingJob, error) {
	return s.pairingJob(ctx, p, id)
}

func (s *Service) StartPairing(ctx context.Context, p auth.Principal, trace, key string, in PairingJobInput) (PairingJob, error) {
	if err := p.Require("nodes.manage", "read"); err != nil {
		return PairingJob{}, err
	}
	if err := validKey(key); err != nil {
		return PairingJob{}, err
	}
	if in.Name == "" || len(in.Name) > 100 || strings.TrimSpace(in.Name) != in.Name || strings.ContainsAny(in.Name, "\x00\r\n") || !uuid.MatchString(in.PairingID) || !uuid.MatchString(in.TargetNodeID) || in.TargetNodeID == s.NodeID || !pairingSecret.MatchString(in.Secret) || !pin.MatchString(strings.ToLower(in.Fingerprint)) {
		return PairingJob{}, fault.Invalid("配对名称、目标编号、配对信息或证书指纹无效")
	}
	client, base, err := remoteapi.Client(remoteapi.Endpoint{URL: in.URL, APIKey: in.Secret, Fingerprint: in.Fingerprint})
	if err != nil {
		return PairingJob{}, err
	}
	client.CloseIdleConnections()
	hash := requestHash("pairing.connect", in)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return PairingJob{}, err
	}
	defer tx.Rollback()
	var previous, oldHash string
	err = tx.QueryRowContext(ctx, "SELECT id,request_hash FROM node_pairing_jobs WHERE principal=? AND request_key=?", p.ID, key).Scan(&previous, &oldHash)
	if err == nil {
		tx.Rollback()
		if oldHash != hash {
			return PairingJob{}, fault.Conflict("同一幂等键不能用于不同配对输入")
		}
		return s.ResumePairing(ctx, p, trace, previous)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PairingJob{}, err
	}
	var count, duplicate int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(target_node_id=? AND pairing_id=?),0) FROM node_pairing_jobs", in.TargetNodeID, in.PairingID).Scan(&count, &duplicate); err != nil {
		return PairingJob{}, err
	}
	if count >= 256 {
		return PairingJob{}, fault.Conflict("配对任务已达上限，须本机归档后继续")
	}
	if duplicate != 0 {
		return PairingJob{}, fault.Conflict("此配对已有任务，请续办原记录")
	}
	var active, total int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(node_id=? AND removed_at IS NULL),0) FROM nodes", in.TargetNodeID).Scan(&total, &duplicate); err != nil {
		return PairingJob{}, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes WHERE removed_at IS NULL").Scan(&active); err != nil {
		return PairingJob{}, err
	}
	if duplicate != 0 {
		return PairingJob{}, fault.Conflict("目标永久节点已登记，请使用已有连接")
	}
	if active >= 32 || total >= 128 {
		return PairingJob{}, fault.Conflict("节点连接已达上限")
	}
	id := secure.ID()
	now := time.Now().Unix()
	m := pairingMaterial{Secret: in.Secret, Claim: secure.Token()}
	raw, _ := json.Marshal(m)
	if _, err = tx.ExecContext(ctx, "INSERT INTO node_pairing_jobs(id,principal,request_key,request_hash,name,endpoint,fingerprint,controller_node_id,target_node_id,pairing_id,material,state,stage,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending','exchange',?,?)", id, p.ID, key, hash, in.Name, base, strings.ToLower(in.Fingerprint), s.NodeID, in.TargetNodeID, in.PairingID, s.Vault.Seal(raw, "pairing-job:"+id), now, now); err != nil {
		return PairingJob{}, err
	}
	if err = audit(ctx, tx, trace, p.ID, "nodes.pairing.start", id, "accepted"); err != nil {
		return PairingJob{}, err
	}
	if err = tx.Commit(); err != nil {
		return PairingJob{}, err
	}
	return s.ResumePairing(ctx, p, trace, id)
}

func (s *Service) savePairingJob(ctx context.Context, j *PairingJob, m *pairingMaterial, trace, outcome string) error {
	finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	var material []byte
	if m != nil {
		raw, err := json.Marshal(m)
		if err != nil {
			return err
		}
		material = s.Vault.Seal(raw, "pairing-job:"+j.ID)
	}
	tx, err := s.DB.BeginTx(finish, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	j.UpdatedAt = time.Now().Unix()
	var connection any
	if j.ConnectionID != "" {
		connection = j.ConnectionID
	}
	if _, err = tx.ExecContext(finish, "UPDATE node_pairing_jobs SET material=?,credential_id=?,connection_id=?,state=?,stage=?,last_error=?,revocation=?,updated_at=? WHERE id=? AND principal=?", material, j.CredentialID, connection, j.State, j.Stage, j.Error, j.Revocation, j.UpdatedAt, j.ID, j.principal); err != nil {
		return err
	}
	if err = audit(finish, tx, trace, j.principal, "nodes.pairing."+j.Stage, j.ID, outcome); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) pairJobSlot() (func(), error) {
	if s.pairJobActive.Add(1) > 2 {
		s.pairJobActive.Add(-1)
		return nil, fault.New(http.StatusTooManyRequests, "PAIRING_BUSY", "配对并发已达上限，请稍后续办原记录")
	}
	return func() { s.pairJobActive.Add(-1) }, nil
}

func (s *Service) ResumePairing(ctx context.Context, p auth.Principal, trace, id string) (PairingJob, error) {
	j, err := s.pairingJob(ctx, p, id)
	if err != nil {
		return j, err
	}
	unlock, err := s.lock("pair-job:" + id)
	if err != nil {
		return j, err
	}
	defer unlock()
	j, err = s.pairingJob(ctx, p, id)
	if err != nil {
		return j, err
	}
	if j.State == "succeeded" || j.State == "abandoned" {
		return j, nil
	}
	if j.State == "abandoning" {
		return j, fault.Conflict("原任务正在放弃，请继续放弃并核对目标撤销结果")
	}
	if j.ControllerNodeID != s.NodeID {
		return j, fault.Conflict("控制节点永久身份已变化，禁止继续原配对")
	}
	release, err := s.pairJobSlot()
	if err != nil {
		return j, err
	}
	defer release()
	raw, err := s.Vault.Open(j.material, "pairing-job:"+id)
	if err != nil {
		return j, err
	}
	var m pairingMaterial
	if json.Unmarshal(raw, &m) != nil || !pairingSecret.MatchString(m.Claim) || !pairingSecret.MatchString(m.Secret) {
		return j, fault.Conflict("原配对恢复材料无效，禁止重建交换")
	}
	j.State, j.Error = "pending", ""
	if err = s.savePairingJob(ctx, &j, &m, trace, "attempting"); err != nil {
		return j, err
	}
	work, stop := context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	ep := remoteapi.Endpoint{URL: j.URL, Fingerprint: j.Fingerprint, APIKey: m.Secret}
	failed := func(cause error) (PairingJob, error) {
		j.State = "recovery_required"
		j.Error = "原配对结果未完成核对，请续办原记录；放弃时须检查目标授权"
		var f *fault.Error
		if errors.As(cause, &f) {
			j.Error = f.Message
		}
		if err := s.savePairingJob(ctx, &j, &m, trace, "unconfirmed"); err != nil {
			return j, err
		}
		return j, nil
	}
	if j.Stage == "exchange" {
		var exchange PairingExchange
		if err = pairingRPC(work, ep, j.TargetNodeID, j.PairingID, false, PairingClaim{Secret: m.Secret, ControllerNodeID: s.NodeID, Claim: m.Claim}, &exchange); err != nil {
			return failed(err)
		}
		pair := exchange.Pairing
		if pair.ID != j.PairingID || pair.NodeID != j.TargetNodeID || pair.ControllerNodeID != s.NodeID || pair.State != "claimed" || !uuid.MatchString(pair.CredentialID) || !pairingSecret.MatchString(exchange.Token) {
			return failed(fault.Conflict("目标配对领取回执不匹配"))
		}
		m.Token, j.CredentialID, j.Stage = exchange.Token, pair.CredentialID, "confirm"
		if err = s.savePairingJob(ctx, &j, &m, trace, "exchanged"); err != nil {
			return j, err
		}
	}
	if !pairingSecret.MatchString(m.Token) || !uuid.MatchString(j.CredentialID) {
		return failed(fault.Conflict("原配对授权材料缺失，禁止重新创建授权"))
	}
	ep.APIKey = m.Token
	if j.Stage == "confirm" {
		if _, _, err = probe(work, ep, j.TargetNodeID, j.CredentialID); err != nil {
			return failed(err)
		}
		var pair Pairing
		if err = pairingRPC(work, ep, j.TargetNodeID, j.PairingID, true, PairingConfirmation{ControllerNodeID: s.NodeID, Claim: m.Claim}, &pair); err != nil {
			return failed(err)
		}
		if pair.ID != j.PairingID || pair.NodeID != j.TargetNodeID || pair.ControllerNodeID != s.NodeID || pair.CredentialID != j.CredentialID || pair.State != "confirmed" {
			return failed(fault.Conflict("目标配对确认回执不匹配"))
		}
		j.Stage = "register"
		if err = s.savePairingJob(ctx, &j, &m, trace, "confirmed"); err != nil {
			return j, err
		}
	}
	connection, err := s.create(work, p, trace, "pair-"+secure.Hash([]byte(j.ID)), CreateInput{Name: j.Name, URL: j.URL, Fingerprint: j.Fingerprint, APIKey: m.Token}, j.TargetNodeID, j.CredentialID)
	if err != nil {
		return failed(err)
	}
	if connection.NodeID != j.TargetNodeID || connection.CredentialID != j.CredentialID {
		return failed(fault.Conflict("本机连接登记与原配对身份不一致"))
	}
	j.ConnectionID, j.State, j.Stage, j.Error = connection.ID, "succeeded", "finished", ""
	if err = s.savePairingJob(ctx, &j, nil, trace, "succeeded"); err != nil {
		return j, err
	}
	return j, nil
}

func (s *Service) AbandonPairing(ctx context.Context, p auth.Principal, trace, id string) (PairingJob, error) {
	j, err := s.pairingJob(ctx, p, id)
	if err != nil {
		return j, err
	}
	unlock, err := s.lock("pair-job:" + id)
	if err != nil {
		return j, err
	}
	defer unlock()
	j, err = s.pairingJob(ctx, p, id)
	if err != nil {
		return j, err
	}
	if j.State == "abandoned" {
		return j, nil
	}
	if j.State == "succeeded" {
		return j, fault.Conflict("配对已完成，请从连接列表删除并撤销授权")
	}
	// A crash may leave the registration committed before the job is finalized.
	var registered string
	err = s.DB.QueryRowContext(ctx, "SELECT connection_id FROM node_requests WHERE principal=? AND key=?", p.ID, "pair-"+secure.Hash([]byte(id))).Scan(&registered)
	if err == nil {
		return j, fault.Conflict("原连接已登记，请先续办核对，再从连接列表删除")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return j, err
	}
	release, err := s.pairJobSlot()
	if err != nil {
		return j, err
	}
	defer release()
	raw, err := s.Vault.Open(j.material, "pairing-job:"+id)
	if err != nil {
		return j, err
	}
	var m pairingMaterial
	if err = json.Unmarshal(raw, &m); err != nil {
		return j, err
	}
	j.State = "abandoning"
	if err = s.savePairingJob(ctx, &j, &m, trace, "abandoning"); err != nil {
		return j, err
	}
	j.Revocation = "pending"
	if m.Token != "" && j.ControllerNodeID == s.NodeID {
		work, stop := context.WithTimeout(ctx, 15*time.Second)
		response, e := call(work, remoteapi.Endpoint{URL: j.URL, APIKey: m.Token, Fingerprint: j.Fingerprint}, j.TargetNodeID, http.MethodDelete, "/remote/authorization")
		stop()
		if e == nil {
			var receipt struct {
				CredentialID string `json:"credential_id"`
				Revoked      bool   `json:"revoked"`
			}
			if json.Unmarshal(response.Data, &receipt) == nil && receipt.CredentialID == j.CredentialID && receipt.Revoked {
				j.Revocation = "revoked"
			}
		}
	}
	j.State, j.Stage, j.Error = "abandoned", "finished", ""
	if j.Revocation == "pending" {
		j.Error = "目标撤销结果未确认，请在目标节点按配对编号检查并撤销授权"
	}
	if err = s.savePairingJob(ctx, &j, nil, trace, "abandoned:"+j.Revocation); err != nil {
		return j, err
	}
	return j, nil
}
