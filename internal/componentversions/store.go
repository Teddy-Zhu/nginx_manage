package componentversions

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"nginxpanel/internal/secure"
)

func Directory(data, source, app string) (string, error) {
	if !Identifier(source) || !Identifier(app) {
		return "", errors.New("组件标识无效")
	}
	return filepath.Join(data, "agent", "component-versions", source, app), nil
}

func ReadState(data, source, app string) (State, error) {
	var state State
	dir, err := Directory(data, source, app)
	if err != nil {
		return state, err
	}
	raw, err := secure.ReadRootFile(filepath.Join(dir, "installed.json"), 32<<10)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err = json.Unmarshal(raw, &state); err != nil {
		return state, errors.New("组件版本记录损坏")
	}
	for _, version := range []*Version{state.Current, state.Previous} {
		if version != nil {
			if err = version.Validate(); err != nil {
				return state, err
			}
		}
	}
	return state, nil
}

func WriteFile(name string, value any) error {
	if err := secure.RootDirectory(filepath.Dir(name), 0700); err != nil {
		return err
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	raw := encoded.Bytes()
	f, err := os.CreateTemp(filepath.Dir(name), ".versions-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = os.Rename(f.Name(), name)
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func SaveState(data, source, app string, state State) error {
	dir, err := Directory(data, source, app)
	if err != nil {
		return err
	}
	return WriteFile(filepath.Join(dir, "installed.json"), state)
}

func ReadCatalog(data string, q Query) (Catalog, error) {
	var catalog Catalog
	dir, err := Directory(data, "builtin", q.AppID)
	if err != nil {
		return catalog, err
	}
	raw, err := secure.ReadRootFile(filepath.Join(dir, q.Channel+"-"+strconv.Itoa(q.Page)+".json"), 2<<20)
	if err != nil {
		return catalog, err
	}
	if err = json.Unmarshal(raw, &catalog); err != nil {
		return catalog, errors.New("版本目录缓存损坏")
	}
	if catalog.AppID != q.AppID || catalog.Channel != q.Channel || catalog.Page != q.Page || len(catalog.Versions) > 100 {
		return catalog, errors.New("版本目录缓存与查询不一致")
	}
	for _, version := range catalog.Versions {
		if err = version.Validate(); err != nil {
			return catalog, err
		}
	}
	return catalog, nil
}

func SaveCatalog(data string, q Query, catalog Catalog) error {
	dir, err := Directory(data, "builtin", q.AppID)
	if err != nil {
		return err
	}
	return WriteFile(filepath.Join(dir, q.Channel+"-"+strconv.Itoa(q.Page)+".json"), catalog)
}
