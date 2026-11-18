"""Docker Hub identity, metadata authentication and redirect behavior."""
import base64
import hashlib
import io
import json
from types import SimpleNamespace
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch
import urllib.parse
import urllib.request

from images import Registry, RegistryNotFound, RegistryRedirectRejected, Redirects, image_repository, tag


class ImageRegistryTests(unittest.TestCase):
    def test_published_tag_is_the_signed_component_version(self):
        repository = "docker.io/myteam/nginxpanel-nginx"
        raw = b'{"schemaVersion":2}'
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        for version in ("2.0.1", "2.0.1-dev"):
            args = SimpleNamespace(repository="source/project", version=version, commit="a" * 40, input=None)
            manifest = {
                "repository": args.repository, "version": version, "assets": [],
                "images": [{"id": "nginx", "repository": repository, "version": version,
                            "commit": args.commit, "digest": digest}],
            }
            env = {"NGINX_IMAGE_REPOSITORY": repository, "GITHUB_RUN_ID": "44", "GITHUB_RUN_ATTEMPT": "2"}
            with self.subTest(version=version), patch.dict("os.environ", env, clear=True), \
                    patch("images.read", return_value=json.dumps(manifest).encode()), \
                    patch("images.Registry") as registry, patch("images.subprocess.run") as run:
                registry.return_value.get.side_effect = [RegistryNotFound(), raw]
                tag(args)
                self.assertEqual([call.args for call in registry.return_value.get.call_args_list],
                                 [("manifests", version)] * 2)
                self.assertEqual(run.call_args.args[0][-2:], [repository + ":" + version, repository + "@" + digest])
                registry.return_value.get.side_effect = None
                registry.return_value.get.return_value = b"another manifest"
                run.reset_mock()
                with self.assertRaisesRegex(ValueError, "请使用新的组件版本"):
                    tag(args)
                run.assert_not_called()

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
        with patch.dict("os.environ", {}, clear=True), patch.object(Registry, "pull_token", return_value="pull-token"):
            registry = Registry("docker.io/myteam/nginxpanel-nginx")
        redirects = next(handler for handler in registry.opener.handlers if isinstance(handler, Redirects))
        request = urllib.request.Request("https://registry-1.docker.io/v2/team/nginx/blobs/sha256:123", headers={"Authorization": "Bearer private"})
        for host in (
            "production.cloudfront.docker.com",
            "docker-images-prod.s3.amazonaws.com",
            "docker-images-prod.s3.us-east-1.amazonaws.com",
            "docker-images-prod.s3.dualstack.us-east-1.amazonaws.com",
        ):
            with self.subTest(host=host):
                target = f"https://{host}/blob?X-Amz-Signature=storage-signature"
                redirected = redirects.redirect_request(request, None, 307, "Redirect", {}, target)
                self.assertEqual(redirected.full_url, target)
                self.assertIsNone(redirected.get_header("Authorization"))
        for target in (
            "http://production.cloudfront.docker.com/blob",
            "https://example.com/blob",
            "https://user@production.cloudfront.docker.com/blob",
            "https://another-bucket.s3.dualstack.us-east-1.amazonaws.com/blob",
            "https://docker-images-prod.s3.dualstack.us-east-1.amazonaws.com.example.com/blob",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                redirects.redirect_request(request, None, 307, "Redirect", {}, target)

    def test_authenticated_blob_redirect_retries_anonymously_and_checks_digest(self):
        raw = b'{"architecture":"amd64"}'
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        location = "https://unlisted.example/storage?signature=private"
        with patch.dict("os.environ", {"DOCKERHUB_USERNAME": "publisher", "DOCKERHUB_TOKEN": "test-token"}, clear=True), \
                patch.object(Registry, "request") as request, redirect_stderr(io.StringIO()) as logs:
            request.return_value = b'{"token":"authenticated"}'
            registry = Registry("docker.io/myteam/nginxpanel-nginx")
            with self.assertRaises(RegistryRedirectRejected) as rejected:
                Redirects({"registry-1.docker.io"}).redirect_request(
                    urllib.request.Request(registry.origin), None, 302, "Redirect", {}, location,
                )
            request.reset_mock()
            request.side_effect = [rejected.exception, b'{"token":"anonymous"}', raw, rejected.exception, b"x" * len(raw)]
            self.assertEqual(registry.get("blobs", digest, len(raw)), raw)
            with self.assertRaisesRegex(ValueError, "digest or length"):
                registry.get("blobs", digest, len(raw))
            self.assertEqual([call.args[1].get("Authorization") for call in request.call_args_list],
                             ["Bearer authenticated", None, "Bearer anonymous", "Bearer authenticated", "Bearer anonymous"])
            self.assertEqual(request.call_args_list[1].args[0], registry.token_url)
            self.assertIn("HTTP 302 to unlisted.example", logs.getvalue())
            self.assertNotIn("signature=private", logs.getvalue())


if __name__ == "__main__":
    unittest.main()
