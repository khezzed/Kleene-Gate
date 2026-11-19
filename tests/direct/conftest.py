import sys
import types
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Generic, TypeVar

import pytest

K = TypeVar("K")
V = TypeVar("V")
T = TypeVar("T")


class u256(int):
    """GenLayer u256 primitive type."""

    def __new__(cls, val: int = 0):
        v = int(val)
        if v < 0 or v >= (1 << 256):
            raise OverflowError("u256 overflow or negative value")
        return super().__new__(cls, v)

    def __add__(self, other: Any) -> "u256":
        return u256(int(self) + int(other))

    def __sub__(self, other: Any) -> "u256":
        res = int(self) - int(other)
        if res < 0:
            raise OverflowError("u256 underflow")
        return u256(res)

    def __mul__(self, other: Any) -> "u256":
        return u256(int(self) * int(other))

    def __floordiv__(self, other: Any) -> "u256":
        return u256(int(self) // int(other))


class Address(str):
    """GenLayer Address primitive type."""

    def __new__(cls, val: str = "0x0000000000000000000000000000000000000000"):
        v = str(val).lower()
        if not v.startswith("0x") or len(v) != 42:
            raise ValueError(f"Invalid Address format: {val}")
        return super().__new__(cls, v)


class TreeMap(Generic[K, V], dict):
    pass


class DynArray(Generic[T], list):
    pass


def allow_storage(cls: Any) -> Any:
    cls.__allow_storage__ = True
    return cls


class _ReturnWrapper:
    """Wrapper matching gl.vm.Return."""

    def __init__(self, calldata: Any):
        self.calldata = calldata


class UserError(Exception):
    """Contract revert corresponding to gl.vm.UserError."""
    pass


class ConsensusDisagreementError(Exception):
    """Raised by harness when validator_fn rejects leader_fn's output."""
    pass


@dataclass
class MockWebResponse:
    status: int
    body: bytes | None
    headers: dict[str, bytes] = field(default_factory=dict)


@dataclass
class EmittedTransfer:
    recipient: Address
    value: u256


class _MessageContext:
    def __init__(self) -> None:
        self.contract_address = Address("0x9999999999999999999999999999999999999999")
        self.sender_address = Address("0x1111111111111111111111111111111111111111")
        self.origin_address = Address("0x1111111111111111111111111111111111111111")
        self.value = u256(0)
        self.chain_id = u256(61999)
        self.timestamp = 1763500000


class _WriteDecorator:
    def __call__(self, fn: Callable) -> Callable:
        fn.__gl_public__ = True
        fn.__gl_write__ = True
        return fn

    def payable(self, fn: Callable) -> Callable:
        fn.__gl_public__ = True
        fn.__gl_write__ = True
        fn.__gl_payable__ = True
        return fn


def _view_decorator(fn: Callable) -> Callable:
    fn.__gl_public__ = True
    fn.__gl_view__ = True
    return fn


class _ContractHandle:
    def __init__(self, addr: Address, transfers_sink: list[EmittedTransfer]):
        self._addr = addr
        self._transfers = transfers_sink

    def emit_transfer(self, value: u256 | int = 0) -> None:
        self._transfers.append(EmittedTransfer(recipient=self._addr, value=u256(int(value))))


class GenVMMockState:
    """Controllable deterministic state for direct-mode contract tests."""

    def __init__(self) -> None:
        self.message = _MessageContext()
        self.message_raw: dict[str, Any] = {}
        self.web_responses: dict[str, MockWebResponse | Exception] = {}
        self.llm_handler: Callable[[str], Any] | None = None
        self.adversarial_leader_override: Callable[[Any], Any] | None = None
        self.emitted_transfers: list[EmittedTransfer] = []
        self.web_call_count: int = 0
        self.llm_call_count: int = 0
        self.set_time(1763500000)

    def reset(self) -> None:
        self.message = _MessageContext()
        self.web_responses.clear()
        self.llm_handler = None
        self.adversarial_leader_override = None
        self.emitted_transfers.clear()
        self.web_call_count = 0
        self.llm_call_count = 0
        self.set_time(1763500000)

    def set_time(self, epoch_seconds: int) -> None:
        self.message.timestamp = int(epoch_seconds)
        dt = datetime.fromtimestamp(int(epoch_seconds), tz=timezone.utc)
        self.message_raw["datetime"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def set_caller(self, addr: str, value: int = 0) -> None:
        a = Address(addr)
        self.message.sender_address = a
        self.message.origin_address = a
        self.message.value = u256(value)


_MOCK_STATE = GenVMMockState()


def _install_genlayer_mock() -> None:
    if "genlayer" in sys.modules and getattr(sys.modules["genlayer"], "_kleene_mock", False):
        return

    genlayer_mod = types.ModuleType("genlayer")
    genlayer_mod._kleene_mock = True

    class Contract:
        def __init_subclass__(cls, **kwargs: Any) -> None:
            super().__init_subclass__(**kwargs)

        def __new__(cls, *args: Any, **kwargs: Any) -> Any:
            obj = super().__new__(cls)
            # Auto-initialize TreeMap and DynArray annotations like GenVM runtime
            for name, ann in getattr(cls, "__annotations__", {}).items():
                ann_str = str(ann)
                if "TreeMap" in ann_str:
                    setattr(obj, name, TreeMap())
                elif "DynArray" in ann_str:
                    setattr(obj, name, DynArray())
            return obj

    def _web_get(url: str) -> MockWebResponse:
        _MOCK_STATE.web_call_count += 1
        if url not in _MOCK_STATE.web_responses:
            return MockWebResponse(status=404, body=b"Not Found")
        item = _MOCK_STATE.web_responses[url]
        if isinstance(item, Exception):
            raise item
        return item

    def _exec_prompt(prompt: str, response_format: str = "text") -> Any:
        _MOCK_STATE.llm_call_count += 1
        if _MOCK_STATE.llm_handler is None:
            raise RuntimeError("No llm_handler configured in test")
        return _MOCK_STATE.llm_handler(prompt)

    def _run_nondet_unsafe(leader_fn: Callable[[], Any], validator_fn: Callable[[Any], bool]) -> Any:
        leader_out = leader_fn()
        if _MOCK_STATE.adversarial_leader_override is not None:
            leader_out = _MOCK_STATE.adversarial_leader_override(leader_out)
        wrapped = _ReturnWrapper(leader_out)
        ok = validator_fn(wrapped)
        if not ok:
            raise ConsensusDisagreementError("Validator rejected leader result")
        return leader_out

    def _get_contract_at(addr: Address | str) -> _ContractHandle:
        return _ContractHandle(Address(str(addr)), _MOCK_STATE.emitted_transfers)

    gl_ns = types.SimpleNamespace(
        Contract=Contract,
        message=_MOCK_STATE.message,
        message_raw=_MOCK_STATE.message_raw,
        public=types.SimpleNamespace(write=_WriteDecorator(), view=_view_decorator),
        vm=types.SimpleNamespace(
            UserError=UserError,
            Return=_ReturnWrapper,
            run_nondet_unsafe=_run_nondet_unsafe,
        ),
        nondet=types.SimpleNamespace(
            web=types.SimpleNamespace(get=_web_get),
            exec_prompt=_exec_prompt,
        ),
        get_contract_at=_get_contract_at,
    )

    genlayer_mod.gl = gl_ns
    genlayer_mod.u256 = u256
    genlayer_mod.Address = Address
    genlayer_mod.TreeMap = TreeMap
    genlayer_mod.DynArray = DynArray
    genlayer_mod.allow_storage = allow_storage
    genlayer_mod.__all__ = ["gl", "u256", "Address", "TreeMap", "DynArray", "allow_storage"]

    sys.modules["genlayer"] = genlayer_mod


_install_genlayer_mock()


@pytest.fixture
def env() -> GenVMMockState:
    _MOCK_STATE.reset()
    # Keep gl.message and gl.message_raw synced after reset
    import genlayer
    genlayer.gl.message = _MOCK_STATE.message
    genlayer.gl.message_raw = _MOCK_STATE.message_raw
    return _MOCK_STATE
