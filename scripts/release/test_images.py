"""Docker Hub identity, metadata authentication and redirect behavior."""
import base64
import hashlib
import unittest
from unittest.mock import patch
import urllib.parse
import urllib.request

from images import Registry, Redirects, image_repository


class ImageRegistryTests(unittest.TestCase):
    def test_explicit_docker_hub_repository_is_used_without_tags(self):
        with patch.dict("os.environ", {"NGINX_IMAGE_REPOSITORY": "docker.io/myteam/nginxpanel-nginx"}, clear=True):
            self.assertEqual(image_repository("source/project", "nginx"), "docker.io/myteam/nginxpanel-nginx")
        for value in ("https://docker.io/team/nginx", "docker.io/team/nginx:latest", "docker.io/team/nginx@sha256:123", "docker.io//nginx"):
            with self.subTest(value=value), patch.dict("os.environ", {"NGINX_IMAGE_REPOSITORY": value}, clear=True), self.assertRaises(ValueError):
                image_repository("source/project", "nginx")

    def test_docker_hub_metadata_uses_its_auth_service_and_registry(self):
        raw = b'{"schemaVersion":2}'
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        with patch.dict("os.environ", {"DOCKERHUB_USERNAME": "publisher", "DOCKERHUB_TOKEN": "test-token"}, clear=True), \
                patch.object(Registry, "request", side_effect=[b'{"access_token":"pull-token"}', raw]) as request:
            registry = Registry("docker.io/myteam/nginxpanel-nginx")
            self.assertEqual(registry.get("manifests", digest), raw)
        token_url, headers, _ = request.call_args_list[0].args
        self.assertEqual(urllib.parse.urlsplit(token_url).netloc, "auth.docker.io")
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(token_url).query), {
            "service": ["registry.docker.io"], "scope": ["repository:myteam/nginxpanel-nginx:pull"],
        })
        self.assertEqual(headers["Authorization"], "Basic " + base64.b64encode(b"publisher:test-token").decode())
        self.assertEqual(request.call_args_list[1].args[0], "https://registry-1.docker.io/v2/myteam/nginxpanel-nginx/manifests/" + digest)
        self.assertEqual(request.call_args_list[1].args[1]["Authorization"], "Bearer pull-token")

    def test_metadata_digest_and_incomplete_credentials_fail(self):
        with patch.dict("os.environ", {}, clear=True), patch.object(Registry, "request", side_effect=[b'{"token":"pull-token"}', b'{}']):
            registry = Registry("docker.io/myteam/nginxpanel-nginx")
            with self.assertRaisesRegex(ValueError, "digest or length"):
                registry.get("manifests", "sha256:" + "0" * 64)
        with patch.dict("os.environ", {"DOCKERHUB_USERNAME": "publisher"}, clear=True), self.assertRaisesRegex(ValueError, "provided together"):
            Registry("docker.io/myteam/nginxpanel-nginx")

    def test_cross_host_redirect_removes_authorization_and_rejects_other_hosts(self):
        redirects = Redirects({"production.cloudfront.docker.com"})
        request = urllib.request.Request("https://registry-1.docker.io/v2/team/nginx/blobs/sha256:123", headers={"Authorization": "Bearer private"})
        redirected = redirects.redirect_request(request, None, 307, "Redirect", {}, "https://production.cloudfront.docker.com/blob")
        self.assertIsNone(redirected.get_header("Authorization"))
        for target in ("http://production.cloudfront.docker.com/blob", "https://example.com/blob", "https://user@production.cloudfront.docker.com/blob"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                redirects.redirect_request(request, None, 307, "Redirect", {}, target)


if __name__ == "__main__":
    unittest.main()
