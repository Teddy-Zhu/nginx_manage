package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func dockerReportFixture(t *testing.T, bridgeID string) *dockerFirewallSnapshot {
	t.Helper()
	raw := fmt.Sprintf(`{
"Info":{"ID":"test-engine","ServerVersion":"29.9.1","OSType":"linux","SecurityOptions":[],"Swarm":{"LocalNodeState":"inactive"}},
"Networks":[
{"Id":"%[1]s","Name":"bridge","Driver":"bridge","Scope":"local","Options":{"com.docker.network.bridge.default_bridge":"true","com.docker.network.bridge.name":"docker0"}},
{"Id":"%[2]s","Name":"selected","Driver":"bridge","Scope":"local","Options":{"com.docker.network.bridge.name":"br-selected"}}],
"Containers":[
{"Id":"%[3]s","State":"running","Ports":[{"IP":"192.0.2.10","PrivatePort":8080,"PublicPort":18080,"Type":"tcp"}],"HostConfig":{"NetworkMode":"selected"},"NetworkSettings":{"Networks":{"selected":{"NetworkID":"%[2]s","IPAddress":"172.30.57.2"}}}},
{"Id":"%[4]s","State":"running","HostConfig":{"NetworkMode":"%[1]s"},"NetworkSettings":{"Networks":{"bridge":{"NetworkID":"%[1]s","IPAddress":"172.17.0.2"}}}}]}`,
		bridgeID, strings.Repeat("8", 64), strings.Repeat("a", 64), strings.Repeat("b", 64))
	var snapshot dockerFirewallSnapshot
	if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.normalize(); err != nil {
		t.Fatal(err)
	}
	return &snapshot
}

func TestDockerReportDefaultBridgeLifecycle(t *testing.T) {
	before := dockerReportFixture(t, strings.Repeat("1", 64))
	after := dockerReportFixture(t, strings.Repeat("f", 64))
	firstRaw, _ := json.Marshal(before)
	lastRaw, _ := json.Marshal(after)
	if bytes.Equal(firstRaw, lastRaw) {
		t.Fatal("raw daemon observations must still detect a network identity change")
	}
	first, err := before.reportHash()
	if err != nil {
		t.Fatal(err)
	}
	last, err := after.reportHash()
	if err != nil || first != last {
		t.Fatalf("default bridge recreation changed the semantic report: %s != %s, %v", first, last, err)
	}
	firstAgain, _ := json.Marshal(before)
	lastAgain, _ := json.Marshal(after)
	if !bytes.Equal(firstRaw, firstAgain) || !bytes.Equal(lastRaw, lastAgain) {
		t.Fatal("report projection changed real network IDs or endpoint bindings")
	}
}

func TestDockerReportRetainsScopeChanges(t *testing.T) {
	t.Run("unrecognized-bridge-identity", func(t *testing.T) {
		before := dockerReportFixture(t, strings.Repeat("1", 64))
		after := dockerReportFixture(t, strings.Repeat("f", 64))
		delete(before.Networks[0].Options, "com.docker.network.bridge.default_bridge")
		delete(after.Networks[1].Options, "com.docker.network.bridge.default_bridge")
		first, firstErr := before.reportHash()
		last, lastErr := after.reportHash()
		if firstErr != nil || lastErr != nil || first == last {
			t.Fatal("unrecognized bridge identity was normalized", firstErr, lastErr)
		}
	})
	baseline, err := dockerReportFixture(t, strings.Repeat("1", 64)).reportHash()
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*dockerFirewallSnapshot){
		"engine": func(v *dockerFirewallSnapshot) { v.Info.ID = "other-engine" },
		"bridge-options": func(v *dockerFirewallSnapshot) {
			v.Networks[0].Options["com.docker.network.bridge.name"] = "other0"
		},
		"unrecognized-bridge": func(v *dockerFirewallSnapshot) {
			delete(v.Networks[0].Options, "com.docker.network.bridge.default_bridge")
		},
		"custom-network": func(v *dockerFirewallSnapshot) {
			v.Networks[1].ID = strings.Repeat("9", 64)
			e := v.Containers[0].NetworkSettings.Networks["selected"]
			e.NetworkID = v.Networks[1].ID
			v.Containers[0].NetworkSettings.Networks["selected"] = e
		},
		"endpoint-address": func(v *dockerFirewallSnapshot) {
			e := v.Containers[0].NetworkSettings.Networks["selected"]
			e.IPAddress = "172.30.57.3"
			v.Containers[0].NetworkSettings.Networks["selected"] = e
		},
		"published-port":     func(v *dockerFirewallSnapshot) { v.Containers[0].Ports[0].PublicPort++ },
		"container-identity": func(v *dockerFirewallSnapshot) { v.Containers[0].ID = strings.Repeat("c", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			v := dockerReportFixture(t, strings.Repeat("1", 64))
			change(v)
			if err := v.normalize(); err != nil {
				t.Fatal(err)
			}
			hash, err := v.reportHash()
			if err != nil || hash == baseline {
				t.Fatalf("changed report was not distinguished: %v", err)
			}
		})
	}
	t.Run("ambiguous-default-bridge", func(t *testing.T) {
		v := dockerReportFixture(t, strings.Repeat("1", 64))
		network := v.Networks[0]
		network.ID = strings.Repeat("2", 64)
		v.Networks = append(v.Networks, network)
		if err := v.normalize(); err != nil {
			t.Fatal(err)
		}
		if _, err := v.reportHash(); err == nil {
			t.Fatal("duplicate default bridge identity was accepted")
		}
	})
}
