"""Tests for §8 opt-ins (Docker + Kubernetes) via injected seams (v2)."""

from __future__ import annotations

from types import SimpleNamespace

from mcsand.config import parse_config
from mcsand.optins import maybe_docker, maybe_k8s


def _cfg(env=None):
    return parse_config({"HOME": "/h", **(env or {})}, cwd="/h/p")


def _cp(returncode=0, stdout=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")


# --------------------------------------------------------------------------- #
# Docker
# --------------------------------------------------------------------------- #
class TestMaybeDocker:
    def test_absent_socket_returns_none(self) -> None:
        assert maybe_docker(_cfg(), exists=lambda p: False, prompt=lambda q: True) is None

    def test_declined_returns_none(self) -> None:
        assert maybe_docker(_cfg(), exists=lambda p: True, prompt=lambda q: False) is None

    def test_accepted_returns_paths(self) -> None:
        result = maybe_docker(_cfg(), exists=lambda p: True, prompt=lambda q: True)
        assert result is not None
        assert result.socket == "/private/var/run/docker.sock"
        assert result.docker_dir == "/h/.docker"


# --------------------------------------------------------------------------- #
# Kubernetes
# --------------------------------------------------------------------------- #
def _run_k8s(
    cfg,
    *,
    run,
    prompt=lambda q: True,
    ask=lambda q, d: d,
    kubectl="/usr/bin/kubectl",
    env=None,
    write=lambda c: "/tmp/kc.yaml",
):
    emitted: list[str] = []
    result = maybe_k8s(
        cfg,
        {"KUBECONFIG": "/home/cfg", **(env or {})},
        kubectl_path=kubectl,
        prompt=prompt,
        ask=ask,
        run=run,
        write_kubeconfig=write,
        emit=emitted.append,
    )
    return result, emitted


def _happy_runner(commands_seen=None):
    def run(cmd):
        if commands_seen is not None:
            commands_seen.append(cmd)
        if cmd[:3] == ["kubectl", "create", "token"]:
            return _cp(0, "TOKEN123\n")
        if "server}" in cmd[-1]:
            return _cp(0, "https://k8s.example:6443")
        if "certificate-authority-data}" in cmd[-1]:
            return _cp(0, "CADATA==")
        if "auth" in cmd and "whoami" in cmd:
            return _cp(0, "Alice@Corp")
        return _cp(0, "")

    return run


def _namespace_scope_prompt(question: str) -> bool:
    # Opt-in: yes. Scope ("cluster-wide …"): no → namespace-scoped RoleBinding.
    return "cluster-wide" not in question.lower()


class TestMaybeK8sGating:
    def test_no_kubeconfig_returns_none(self) -> None:
        result, _ = _run_k8s(_cfg(), run=_happy_runner(), env={"KUBECONFIG": ""})
        # KUBECONFIG explicitly blanked → gate fails.
        assert result is None

    def test_no_kubectl_returns_none(self) -> None:
        result, _ = _run_k8s(_cfg(), run=_happy_runner(), kubectl=None)
        assert result is None

    def test_declined_returns_none(self) -> None:
        result, _ = _run_k8s(
            _cfg({"CLAUDE_SANDBOX_K8S_SA": "t/s"}), run=_happy_runner(), prompt=lambda q: False
        )
        assert result is None

    def test_lifetime_env_implies_optin(self) -> None:
        # A preset lifetime counts as opting in, even if the prompt would decline.
        result, _ = _run_k8s(
            _cfg({"CLAUDE_SANDBOX_K8S_SA": "t/s", "CLAUDE_SANDBOX_K8S_TOKEN_LIFETIME": "5m"}),
            run=_happy_runner(),
            prompt=lambda q: False,
        )
        assert result is not None


class TestMaybeK8sExplicitSA:
    def test_namespaced_sa_happy_path(self) -> None:
        result, _ = _run_k8s(_cfg({"CLAUDE_SANDBOX_K8S_SA": "team/svc"}), run=_happy_runner())
        assert result is not None
        assert result.kubeconfig_path == "/private/tmp/kc.yaml"

    def test_kubeconfig_content_is_self_contained(self) -> None:
        captured = {}

        def write(content: str) -> str:
            captured["content"] = content
            return "/tmp/kc.yaml"

        _run_k8s(_cfg({"CLAUDE_SANDBOX_K8S_SA": "team/svc"}), run=_happy_runner(), write=write)
        content = captured["content"]
        assert "token: TOKEN123" in content
        assert "server: https://k8s.example:6443" in content
        assert "certificate-authority-data: CADATA==" in content

    def test_explicit_sa_does_not_provision(self) -> None:
        seen: list[list[str]] = []
        _run_k8s(_cfg({"CLAUDE_SANDBOX_K8S_SA": "team/svc"}), run=_happy_runner(seen))
        flat = [" ".join(c) for c in seen]
        assert not any("create serviceaccount" in f for f in flat)
        assert not any("rolebinding" in f for f in flat)


class TestMaybeK8sAutoProvisionDefault:
    def test_namespace_scoped_view_binding(self) -> None:
        seen: list[list[str]] = []
        result, _ = _run_k8s(_cfg(), run=_happy_runner(seen), prompt=_namespace_scope_prompt)
        assert result is not None
        flat = [" ".join(c) for c in seen]
        # Default least-privilege: a namespace RoleBinding to the `view` ClusterRole.
        assert any("create serviceaccount claude-code-alice-corp -n default" in f for f in flat)
        assert any(
            "create rolebinding claude-code-alice-corp -n default --clusterrole=view" in f
            for f in flat
        )
        assert not any("clusterrolebinding" in f for f in flat)
        assert any("create token claude-code-alice-corp -n default" in f for f in flat)

    def test_binding_is_delete_then_create(self) -> None:
        seen: list[list[str]] = []
        _run_k8s(_cfg(), run=_happy_runner(seen), prompt=_namespace_scope_prompt)
        flat = [" ".join(c) for c in seen]
        del_idx = next(i for i, f in enumerate(flat) if "delete rolebinding" in f)
        create_idx = next(i for i, f in enumerate(flat) if "create rolebinding" in f)
        assert del_idx < create_idx

    def test_prompted_choices_are_echoed_for_persistence(self) -> None:
        _result, emitted = _run_k8s(_cfg(), run=_happy_runner(), prompt=_namespace_scope_prompt)
        joined = "\n".join(emitted)
        assert "export CLAUDE_SANDBOX_K8S_TOKEN_LIFETIME=8h" in joined
        assert "export CLAUDE_SANDBOX_K8S_ROLE=view" in joined
        assert "export CLAUDE_SANDBOX_K8S_CLUSTER_WIDE=0" in joined


class TestMaybeK8sAutoProvisionFromEnv:
    def test_cluster_wide_admin_from_env_no_prompts(self) -> None:
        seen: list[list[str]] = []

        def prompt(_q: str) -> bool:  # must never be called for scope/role
            raise AssertionError("no prompt expected when env vars are set")

        result, emitted = _run_k8s(
            _cfg(
                {
                    "CLAUDE_SANDBOX_K8S_CLUSTER_WIDE": "1",
                    "CLAUDE_SANDBOX_K8S_ROLE": "admin",
                    "CLAUDE_SANDBOX_K8S_TOKEN_LIFETIME": "1h",
                }
            ),
            run=_happy_runner(seen),
            prompt=prompt,
        )
        assert result is not None
        flat = [" ".join(c) for c in seen]
        assert any("create serviceaccount claude-code-alice-corp -n kube-system" in f for f in flat)
        assert any(
            "create clusterrolebinding claude-code-alice-corp --clusterrole=admin" in f
            for f in flat
        )
        joined = "\n".join(emitted)
        assert "(from CLAUDE_SANDBOX_K8S_CLUSTER_WIDE)" in joined
        assert "(from CLAUDE_SANDBOX_K8S_ROLE)" in joined

    def test_all_from_env_emits_no_export_lines(self) -> None:
        _result, emitted = _run_k8s(
            _cfg(
                {
                    "CLAUDE_SANDBOX_K8S_CLUSTER_WIDE": "1",
                    "CLAUDE_SANDBOX_K8S_ROLE": "admin",
                    "CLAUDE_SANDBOX_K8S_TOKEN_LIFETIME": "1h",
                }
            ),
            run=_happy_runner(),
            prompt=lambda q: True,
        )
        joined = "\n".join(emitted)
        assert "export " not in joined  # nothing to persist; all came from env

    def test_namespace_env_implies_namespace_scope(self) -> None:
        seen: list[list[str]] = []

        def prompt(q: str) -> bool:
            # Opt-in is fine; a scope prompt must NOT happen (namespace implies it).
            assert "cluster-wide" not in q.lower(), "scope prompt should be skipped"
            return True

        result, _ = _run_k8s(
            _cfg({"CLAUDE_SANDBOX_K8S_NAMESPACE": "team-a"}),
            run=_happy_runner(seen),
            prompt=prompt,
        )
        assert result is not None
        flat = [" ".join(c) for c in seen]
        assert any("create rolebinding claude-code-alice-corp -n team-a" in f for f in flat)


class TestMaybeK8sGracefulDegrade:
    def test_runner_raises_returns_none(self) -> None:
        def run(cmd):
            raise OSError("kubectl exploded")

        result, _ = _run_k8s(_cfg({"CLAUDE_SANDBOX_K8S_SA": "team/svc"}), run=run)
        assert result is None

    def test_empty_token_returns_none(self) -> None:
        def run(cmd):
            if cmd[:3] == ["kubectl", "create", "token"]:
                return _cp(0, "")
            return _cp(0, "x")

        result, _ = _run_k8s(_cfg({"CLAUDE_SANDBOX_K8S_SA": "team/svc"}), run=run)
        assert result is None

    def test_no_server_returns_none(self) -> None:
        def run(cmd):
            if cmd[:3] == ["kubectl", "create", "token"]:
                return _cp(0, "TOKEN")
            if "server}" in cmd[-1]:
                return _cp(1, "")  # failure
            return _cp(0, "")

        result, _ = _run_k8s(_cfg({"CLAUDE_SANDBOX_K8S_SA": "team/svc"}), run=run)
        assert result is None
