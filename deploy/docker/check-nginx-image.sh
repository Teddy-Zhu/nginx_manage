#!/bin/sh
set -eu
nginx -V > /usr/share/nginxpanel/nginx-build.txt 2>&1
build=$(cat /usr/share/nginxpanel/nginx-build.txt)
declared=$(sed -n 's/^[[:space:]]*"nginx_version"[[:space:]]*:[[:space:]]*"\([0-9][0-9.]*\)"[[:space:]]*,\{0,1\}[[:space:]]*$/\1/p' /usr/share/nginxpanel/capabilities.json)
actual=$(printf '%s\n' "$build" | sed -n '1s/^nginx version: nginx\///p')
if [ -z "$declared" ] || [ "$actual" != "$declared" ]; then
  echo 'Nginx engine version does not match image capabilities' >&2
  exit 1
fi
for flag in --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_gzip_static_module --with-http_stub_status_module --with-http_auth_request_module --with-http_sub_module --with-http_slice_module --with-http_addition_module --with-http_dav_module --with-stream --with-stream_ssl_module --with-stream_realip_module --with-stream_ssl_preread_module; do
  case " $build " in
    *" $flag "*) ;;
    *) echo "Required static module is missing: $flag" >&2; exit 1 ;;
  esac
done
for flag in --without-http --without-http-cache --without-http_access_module --without-http_proxy_module --without-http_map_module --without-http_rewrite_module --without-http_headers_module --without-http_log_module --without-http_limit_req_module --without-http_limit_conn_module --without-http_fastcgi_module --without-http_uwsgi_module --without-http_scgi_module --without-http_geo_module --without-http_split_clients_module --without-http_charset_module --without-http_gzip_module --without-http_upstream_hash_module --without-http_upstream_ip_hash_module --without-http_upstream_least_conn_module --without-http_upstream_keepalive_module --without-http_upstream_zone_module --without-stream_access_module --without-stream_map_module --without-stream_log_module --without-stream_limit_conn_module --without-stream_return_module --without-stream_geo_module --without-stream_split_clients_module --without-stream_set_module --without-stream_upstream_hash_module --without-stream_upstream_least_conn_module --without-stream_upstream_zone_module; do
  case " $build " in
    *" $flag "*) echo "Required default module is disabled: $flag" >&2; exit 1 ;;
  esac
done
sha256sum /usr/sbin/nginx > /usr/share/nginxpanel/nginx.sha256
sha256sum /usr/local/bin/nginxpanel-nginx-launcher > /usr/share/nginxpanel/launcher.sha256
