package software

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"nginxpanel/internal/secure"
	"os"
	"path/filepath"
	"time"
)

const maxCatalog = 48 << 10

func Read(data string) (Catalog, error) {
	c := Catalog{Sources: []Source{}, Installed: []Installation{}}
	raw, err := secure.ReadRootFile(filepath.Join(data, "agent", "software", "catalog.json"), maxCatalog)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(raw, &c); err != nil {
		return c, errors.New("软件源记录损坏")
	}
	for _, s := range c.Sources {
		if err = s.Validate(); err != nil {
			return c, err
		}
	}
	return c, nil
}
func save(data string, c Catalog) error {
	dir := filepath.Join(data, "agent", "software")
	if err := secure.RootDirectory(dir, 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if len(raw) > maxCatalog {
		return errors.New("软件源记录超过大小限制")
	}
	f, err := os.CreateTemp(dir, ".catalog-")
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
		err = os.Rename(f.Name(), filepath.Join(dir, "catalog.json"))
	}
	if err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func fetch(ctx context.Context, raw string) (Source, error) {
	var s Source
	u, err := sourceURL(raw)
	if err != nil {
		return s, err
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, ResponseHeaderTimeout: 20 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 40 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("软件源重定向过多")
		}
		_, err := sourceURL(req.URL.String())
		return err
	}}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return s, err
	}
	response, err := client.Do(req)
	if err != nil {
		return s, errors.New("无法读取远程软件源，请检查地址与网络")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return s, errors.New("远程软件源未返回配置文件：" + response.Status)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxCatalog+1))
	if err != nil {
		return s, err
	}
	if len(payload) > maxCatalog {
		return s, errors.New("软件源配置过大")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&s); err != nil {
		return s, errors.New("软件源配置不是受支持的 JSON 格式")
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return s, errors.New("软件源包含多余内容")
	}
	s.URL = u.String()
	return s, s.Validate()
}
