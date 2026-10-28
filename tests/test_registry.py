"""The registry's shape and the runner's dependency rules, with no network."""

from layerwise.models import CheckResult, Status
from layerwise.registry import REGISTRY, CheckSpec, Context, Layer
from layerwise.runner import run_registry
from layerwise.targets import Target


def test_names_are_unique():
    names = [spec.name for spec in REGISTRY]
    assert len(names) == len(set(names))


def test_dependencies_exist_on_a_lower_layer():
    by_name = {spec.name: spec for spec in REGISTRY}
    for spec in REGISTRY:
        if spec.depends_on is not None:
            assert spec.depends_on in by_name, spec.name
            assert by_name[spec.depends_on].layer < spec.layer, spec.name


def test_disabled_check_is_transparent():
    def ok(name):
        return lambda ctx: [CheckResult(name, Status.OK, "ok")]

    specs = [
        CheckSpec("base", Layer.TRANSPORT, None, ok("base")),
        CheckSpec("off", Layer.SECURITY, "base", ok("off"), enabled=lambda ctx: False),
        CheckSpec("top", Layer.APPLICATION, "off", ok("top")),
    ]
    ctx = Context(target=Target("example.com", 80), timeout=1, tls=False, http=True)
    assert [r.name for r in run_registry(specs, ctx)] == ["base", "top"]


def test_skipped_checks_name_the_root_cause():
    def result(name, status):
        return lambda ctx: [CheckResult(name, status, name)]

    specs = [
        CheckSpec("tcp", Layer.TRANSPORT, None, result("tcp", Status.FAIL)),
        CheckSpec("tls", Layer.SECURITY, "tcp", result("tls", Status.OK)),
        CheckSpec("http", Layer.APPLICATION, "tls", result("http", Status.OK)),
        CheckSpec("off", Layer.APPLICATION, "tcp", result("off", Status.OK), lambda ctx: False),
    ]
    ctx = Context(target=Target("example.com", 443), timeout=1, tls=True, http=True)
    run_registry(specs, ctx)
    # HTTP blames TCP, not TLS; a disabled check is not "not tested", it was not requested.
    assert ctx.skipped == [("tls", "tcp"), ("http", "tcp")]
