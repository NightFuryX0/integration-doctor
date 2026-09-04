from pathlib import Path

from analyzer.analysis.imports import build_import_table
from analyzer.analysis.models import ResolutionStatus
from analyzer.analysis.parser import parse_file
from analyzer.analysis.resolver import (
    CallResolver,
    collect_call_sites,
)
from analyzer.analysis.symbols import build_symbol_table


def build_analysis(
    tmp_path: Path,
    files: dict[str, str],
):
    """Build the analysis state for a temporary repository."""

    for relative_path, source in files.items():
        file_path = tmp_path / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(source)

    modules = [
        parse_file(tmp_path / relative_path, tmp_path)
        for relative_path in files
    ]

    symbol_table = build_symbol_table(modules)
    import_table = build_import_table(modules)

    module_map = {
        module.module_name: module
        for module in modules
    }

    resolver = CallResolver(
        symbol_table=symbol_table,
        import_table=import_table,
        modules=module_map,
    )

    return modules, resolver


def calls_for_module(modules, module_name):
    """Return call sites belonging to one module."""
    module = next(
        module
        for module in modules
        if module.module_name == module_name
    )

    return collect_call_sites(module)


def resolve_call(
    modules,
    resolver,
    module_name,
    expression,
):
    """Resolve a specific call expression in a module."""
    calls = calls_for_module(modules, module_name)

    matching = [
        call
        for call in calls
        if call.expression == expression
    ]

    assert matching, (
        f"Could not find call expression {expression!r} "
        f"in module {module_name!r}"
    )

    return resolver.resolve(matching[0])


def test_resolves_local_function(tmp_path: Path):
    files = {
        "app.py": """
def verify():
    pass


def webhook():
    verify()
"""
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "app",
        "verify",
    )

    assert result.status == ResolutionStatus.RESOLVED
    assert result.targets == ("app.verify",)


def test_resolves_imported_function(tmp_path: Path):
    files = {
        "app.py": """
from payments import capture_payment


def webhook():
    capture_payment()
""",
        "payments.py": """
def capture_payment():
    pass
""",
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "app",
        "capture_payment",
    )

    assert result.status == ResolutionStatus.RESOLVED
    assert result.targets == ("payments.capture_payment",)


def test_resolves_aliased_import(tmp_path: Path):
    files = {
        "app.py": """
from payments import capture_payment as capture


def webhook():
    capture()
""",
        "payments.py": """
def capture_payment():
    pass
""",
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "app",
        "capture",
    )

    assert result.status == ResolutionStatus.RESOLVED
    assert result.targets == ("payments.capture_payment",)


def test_resolves_module_qualified_call(tmp_path: Path):
    files = {
        "app.py": """
import payments


def webhook():
    payments.capture_payment()
""",
        "payments.py": """
def capture_payment():
    pass
""",
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "app",
        "payments.capture_payment",
    )

    assert result.status == ResolutionStatus.RESOLVED
    assert result.targets == ("payments.capture_payment",)


def test_resolves_relative_import(tmp_path: Path):
    files = {
        "app/__init__.py": "",
        "app/webhook.py": """
from .payments import capture_payment


def webhook():
    capture_payment()
""",
        "app/payments.py": """
def capture_payment():
    pass
""",
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "app.webhook",
        "capture_payment",
    )

    assert result.status == ResolutionStatus.RESOLVED
    assert result.targets == ("app.payments.capture_payment",)


def test_resolves_self_method(tmp_path: Path):
    files = {
        "service.py": """
class PaymentService:

    def verify(self):
        pass

    def capture(self):
        self.verify()
"""
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "service",
        "self.verify",
    )

    assert result.status == ResolutionStatus.RESOLVED
    assert result.targets == ("service.PaymentService.verify",)


def test_resolves_cls_method(tmp_path: Path):
    files = {
        "service.py": """
class PaymentService:

    @classmethod
    def verify(cls):
        pass

    @classmethod
    def capture(cls):
        cls.verify()
"""
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "service",
        "cls.verify",
    )

    assert result.status == ResolutionStatus.RESOLVED
    assert result.targets == ("service.PaymentService.verify",)


def test_module_level_call_is_collected(tmp_path: Path):
    files = {
        "app.py": """
def initialize():
    pass


initialize()
"""
    }

    modules, _ = build_analysis(tmp_path, files)

    calls = calls_for_module(modules, "app")

    assert len(calls) == 1
    assert calls[0].caller == "app"
    assert calls[0].expression == "initialize"


def test_class_body_call_is_collected(tmp_path: Path):
    files = {
        "app.py": """
def initialize():
    pass


class Service:
    initialize()
"""
    }

    modules, _ = build_analysis(tmp_path, files)

    calls = calls_for_module(modules, "app")

    class_calls = [
        call
        for call in calls
        if call.expression == "initialize"
    ]

    assert len(class_calls) == 1
    assert class_calls[0].caller == "app.Service"
    assert class_calls[0].enclosing_class == "app.Service"


def test_nested_function_has_qualified_caller(tmp_path: Path):
    files = {
        "app.py": """
def outer():

    def inner():
        target()

    inner()


def target():
    pass
"""
    }

    modules, _ = build_analysis(tmp_path, files)

    calls = calls_for_module(modules, "app")

    inner_call = next(
        call
        for call in calls
        if call.expression == "target"
    )

    assert inner_call.caller == "app.outer.inner"


def test_dynamic_call_is_unresolved(tmp_path: Path):
    files = {
        "app.py": """
def webhook(handler):
    handler()
"""
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "app",
        "handler",
    )

    assert result.status == ResolutionStatus.UNRESOLVED


def test_external_import_is_external(tmp_path: Path):
    files = {
        "app.py": """
import requests


def webhook():
    requests.post()
"""
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "app",
        "requests.post",
    )

    assert result.status == ResolutionStatus.EXTERNAL


def test_unresolved_dotted_call_is_not_assumed_external(tmp_path: Path):
    files = {
        "app.py": """
def webhook(service):
    service.capture()
"""
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "app",
        "service.capture",
    )

    assert result.status == ResolutionStatus.UNRESOLVED


def test_wildcard_import_prevents_bare_name_guess(tmp_path: Path):
    files = {
        "app.py": """
from payments import *


def webhook():
    capture_payment()
""",
        "payments.py": """
def capture_payment():
    pass
""",
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "app",
        "capture_payment",
    )

    assert result.status == ResolutionStatus.UNRESOLVED


def test_recursive_call_resolves_to_same_function(tmp_path: Path):
    files = {
        "app.py": """
def process():
    process()
"""
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "app",
        "process",
    )

    assert result.status == ResolutionStatus.RESOLVED
    assert result.targets == ("app.process",)


def test_ambiguous_bare_name_is_unresolved(tmp_path: Path):
    files = {
        "app.py": """
def webhook():
    capture_payment()
""",
        "payments.py": """
def capture_payment():
    pass
""",
        "other.py": """
def capture_payment():
    pass
""",
    }

    modules, resolver = build_analysis(tmp_path, files)

    result = resolve_call(
        modules,
        resolver,
        "app",
        "capture_payment",
    )

    assert result.status == ResolutionStatus.UNRESOLVED
