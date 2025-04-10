from typing import Generic, TypeVar, Union

T = TypeVar("T")


class ResponseBase:
    ok: bool


class Success(ResponseBase, Generic[T]):
    def __init__(self, result: T):
        self.ok = True
        self.result = result


class Fail(ResponseBase):
    def __init__(self, message: str):
        self.ok = False
        self.result = message


Response = Union[Success[T], Fail]
