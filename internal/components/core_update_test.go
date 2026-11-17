package components

import "testing"

func TestCoreUpdateStatusUsesRunningVersion(t *testing.T) {
	task := Task{Result: &Operation{Release: &Release{
		Version: "1.2.4", Selected: []string{"panel-linux-amd64"},
		Assets: []Asset{{ID: "panel-linux-amd64", Component: "panel"}},
	}}}
	s := Service{}
	for _, test := range []struct {
		current, state string
	}{
		{"1.2.3", "available"},
		{"1.2.4", "current"},
		{"1.2.5", "older"},
		{"unknown", "unknown"},
	} {
		s.Version = test.current
		task = s.withCoreUpdate(task)
		if task.CoreUpdate == nil || task.CoreUpdate.CurrentVersion != test.current || task.CoreUpdate.State != test.state {
			t.Fatalf("current=%s: %+v", test.current, task.CoreUpdate)
		}
		if test.state == "unknown" && task.CoreUpdate.Message == "" {
			t.Fatal("invalid current version needs an explanation")
		}
	}
	for _, task := range []Task{
		{},
		{Result: &Operation{}},
		{Result: &Operation{Release: &Release{Version: "1.2.4", Selected: []string{"image-nginx"}}}},
		{Result: &Operation{Release: &Release{Version: "1.2.4", Selected: []string{"other"}, Assets: []Asset{{ID: "panel-linux-amd64", Component: "panel"}}}}},
	} {
		if got := s.withCoreUpdate(task); got.CoreUpdate != nil {
			t.Fatal("non-core results must not be labeled as core updates")
		}
	}
}
