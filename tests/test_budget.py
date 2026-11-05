import pytest
from hackbot.budget import Budget, BudgetExhausted


def test_step_exhaustion():
    b = Budget(max_steps=2, max_requests=10, max_tokens=1000)
    b.step()
    with pytest.raises(BudgetExhausted):
        b.step()


def test_request_exhaustion():
    b = Budget(max_steps=10, max_requests=2, max_tokens=1000)
    b.request(2)
    with pytest.raises(BudgetExhausted):
        b.request(1)


def test_token_exhaustion():
    b = Budget(max_steps=10, max_requests=10, max_tokens=100)
    b.add_tokens(100)
    with pytest.raises(BudgetExhausted):
        b.add_tokens(1)
