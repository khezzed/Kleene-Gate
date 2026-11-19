# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from genlayer import *


class ProbeRunner(gl.Contract):
    """Minimal pre-flight probe contract verifying live runner acceptance."""

    counter: u256
    last_tag: str

    def __init__(self, initial_tag: str):
        self.counter = u256(0)
        self.last_tag = initial_tag

    @gl.public.write
    def ping(self, tag: str) -> u256:
        self.counter = u256(int(self.counter) + 1)
        self.last_tag = tag
        return self.counter

    @gl.public.view
    def status(self) -> dict:
        return {
            "counter": int(self.counter),
            "last_tag": self.last_tag,
        }
