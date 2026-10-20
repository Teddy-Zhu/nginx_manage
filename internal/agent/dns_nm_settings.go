package agent

import (
	"errors"
	"reflect"

	"github.com/godbus/dbus/v5"
)

type nmIPv6Address struct {
	Address []byte
	Prefix  uint32
	Gateway []byte
}

type nmIPv6Route struct {
	Destination []byte
	Prefix      uint32
	NextHop     []byte
	Metric      uint32
}

// Store recursively unwraps map variants and infers new signatures. Keep the
// decoded variants, and give legacy IPv6 tuples their concrete wire types so
// a DNS-only update can send every non-DNS property back unchanged.
func nmReadSettings(call *dbus.Call, target *nmSettings, version ...*uint64) error {
	if call.Err != nil {
		return call.Err
	}
	if len(version) > 1 || len(call.Body) != 1+len(version) {
		return errors.New("unexpected NetworkManager settings reply")
	}
	settings, ok := call.Body[0].(map[string]map[string]dbus.Variant)
	if !ok {
		return errors.New("unexpected NetworkManager settings type")
	}
	if len(version) == 1 {
		value, ok := call.Body[1].(uint64)
		if !ok {
			return errors.New("unexpected NetworkManager settings version")
		}
		*version[0] = value
	}
	for key, value := range settings["ipv6"] {
		var converted any
		switch key {
		case "addresses":
			converted = new([]nmIPv6Address)
		case "routes":
			converted = new([]nmIPv6Route)
		default:
			continue
		}
		if err := dbus.Store([]any{value.Value()}, converted); err != nil {
			return err
		}
		typed := dbus.MakeVariant(reflect.ValueOf(converted).Elem().Interface())
		if typed.Signature() != value.Signature() {
			return errors.New("unexpected NetworkManager IPv6 tuple signature")
		}
		settings["ipv6"][key] = typed
	}
	if !nmWireValue(reflect.ValueOf(settings)) {
		return errors.New("NetworkManager settings cannot retain their wire types")
	}
	*target = settings
	return nil
}

func nmWireValue(value reflect.Value) bool {
	if value.Type() == reflect.TypeFor[dbus.Variant]() {
		variant := value.Interface().(dbus.Variant)
		if dbus.SignatureOf(variant.Value()) != variant.Signature() {
			return false
		}
		return nmWireValue(reflect.ValueOf(variant.Value()))
	}
	switch value.Kind() {
	case reflect.Interface:
		return !value.IsNil() && nmWireValue(value.Elem())
	case reflect.Map:
		entries := value.MapRange()
		for entries.Next() {
			if !nmWireValue(entries.Value()) {
				return false
			}
		}
	case reflect.Array, reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			if !nmWireValue(value.Index(i)) {
				return false
			}
		}
	}
	return true
}
