from __future__ import annotations

from dataclasses import dataclass


class BudgetExhausted(RuntimeError):
    pass


@dataclass
class Budget:
    max_steps: int
    max_requests: int
    max_tokens: int
    steps: int = 0
    requests: int = 0
    tokens: int = 0
    exhausted_reason: str | None = None

    def step(self) -> None:
        self.steps += 1
        if self.steps >= self.max_steps:
            self.exhausted_reason = f"max_steps={self.max_steps}"
            raise BudgetExhausted(self.exhausted_reason)

    def request(self, n: int = 1) -> None:
        self.requests += n
        if self.requests > self.max_requests:
            self.exhausted_reason = f"max_requests={self.max_requests}"
            raise BudgetExhausted(self.exhausted_reason)

    def add_tokens(self, n: int) -> None:
        self.tokens += n
        if self.tokens > self.max_tokens:
            self.exhausted_reason = f"max_tokens={self.max_tokens}"
            raise BudgetExhausted(self.exhausted_reason)

    def snapshot(self) -> dict:
        return {
            "steps": self.steps,
            "requests": self.requests,
            "tokens": self.tokens,
            "exhausted_reason": self.exhausted_reason,
        }
