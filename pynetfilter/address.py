from __future__ import annotations

import abc
from typing import List, Tuple

Ip = Tuple[int, int, int, int]


class IpSelector(abc.ABC):
    @classmethod
    def from_str(cls, ip: str):
        if "*" in ip:
            return AnyIp()
        selectors = ip.split(",")
        if len(selectors) != 1:
            return IpUnion.from_str(ip)
        else:
            parts = ip.split("-")
            if len(parts) == 1:
                return SingleIp.from_str(ip)
            elif len(parts) == 2:
                return IpRange.from_str(*parts)
            else:
                raise ValueError("Invalid IP selector")

    @abc.abstractmethod
    def is_any(self) -> bool:
        pass

    @abc.abstractmethod
    def __str__(self):
        pass

    def __repr__(self):
        return f"{type(self).__name__}({self})"

    @abc.abstractmethod
    def __eq__(self, other: IpSelector):
        pass

    @abc.abstractmethod
    def __contains__(self, ip: Ip):
        pass


class SingleIp(IpSelector):
    def __init__(self, ip: Ip):
        self.ip = ip

    @classmethod
    def from_str(cls, ip: str):
        parts = tuple(map(int, ip.split(".")))
        if len(parts) != 4:
            raise ValueError("Invalid IP address")
        return cls(parts)

    def is_any(self) -> bool:
        return False

    def __str__(self):
        return ".".join(map(str, self.ip))

    def __eq__(self, other: IpSelector):
        return isinstance(other, SingleIp) and self.ip == other.ip

    def __contains__(self, ip: Ip):
        return self.ip == ip


class IpRange(IpSelector):
    def __init__(self, start: Ip, end: Ip):
        self.start = start
        self.end = end

    @classmethod
    def from_str(cls, start: str, end: str):
        start_parts = tuple(map(int, start.split(".")))
        end_parts = tuple(map(int, end.split(".")))
        if len(start_parts) != 4 or len(end_parts) != 4:
            raise ValueError("Invalid IP address")
        return cls(start_parts, end_parts)

    @classmethod
    def from_str_range(cls, ip_range: str):
        parts = ip_range.split("-")
        if len(parts) != 2:
            raise ValueError("Invalid IP range")
        return cls.from_str(*parts)

    def is_any(self) -> bool:
        return False

    def __str__(self):
        return f"{SingleIp(self.start)}-{SingleIp(self.end)}"

    def __eq__(self, other: IpSelector):
        return (
            isinstance(other, IpRange)
            and self.start == other.start
            and self.end == other.end
        )

    def __contains__(self, ip: Ip):
        return self.start <= ip <= self.end


class AnyIp(IpSelector):
    def is_any(self) -> bool:
        return True

    def __str__(self):
        return "*"

    def __eq__(self, other: IpSelector):
        return isinstance(other, AnyIp)

    def __contains__(self, ip: Ip):
        return True


class IpUnion(IpSelector, list[IpSelector]):
    def __init__(self, selectors: List[IpSelector] | None = None):
        super().__init__(selectors or [])

    @classmethod
    def from_str(cls, ip_union: str):
        return cls(list(map(IpSelector.from_str, ip_union.split(","))))

    @classmethod
    def from_str_list(cls, ip_list: List[str]):
        return cls(list(map(IpSelector.from_str, ip_list)))

    def is_any(self) -> bool:
        return any(selector.is_any() for selector in self)

    def __str__(self):
        return ",".join(map(str, self))

    def __eq__(self, other: IpSelector):
        return isinstance(other, IpUnion) and list.__eq__(self, other)

    def __contains__(self, ip: Ip):
        return any(ip in selector for selector in self)


Port = int


class PortSelector(abc.ABC):
    @classmethod
    def from_str(cls, port: str):
        if "*" in port:
            return AnyPort()
        selectors = port.split(",")
        if len(selectors) != 1:
            return PortUnion.from_str(port)
        else:
            parts = port.split("-")
            if len(parts) == 1:
                return SinglePort.from_str(port)
            elif len(parts) == 2:
                return PortRange.from_str(*parts)
            else:
                raise ValueError("Invalid port selector")

    @abc.abstractmethod
    def is_any(self) -> bool:
        pass

    @abc.abstractmethod
    def __str__(self):
        pass

    def __repr__(self):
        return f"{type(self).__name__}({self})"

    @abc.abstractmethod
    def __eq__(self, other: PortSelector):
        pass

    @abc.abstractmethod
    def __contains__(self, port: Port):
        pass


class SinglePort(PortSelector):
    def __init__(self, port: Port):
        self.port = port

    @classmethod
    def from_str(cls, port: str):
        return cls(int(port))

    def is_any(self) -> bool:
        return False

    def __str__(self):
        return str(self.port)

    def __eq__(self, other: PortSelector):
        return isinstance(other, SinglePort) and self.port == other.port

    def __contains__(self, port: Port):
        return self.port == port


class PortRange(PortSelector):
    def __init__(self, start: Port, end: Port):
        self.start = start
        self.end = end

    @classmethod
    def from_str(cls, start: str, end: str):
        return cls(int(start), int(end))

    @classmethod
    def from_str_range(cls, port_range: str):
        parts = port_range.split("-")
        if len(parts) != 2:
            raise ValueError("Invalid port range")
        return cls.from_str(*parts)

    def is_any(self) -> bool:
        return False

    def __str__(self):
        return f"{self.start}-{self.end}"

    def __eq__(self, other: PortSelector):
        return (
            isinstance(other, PortRange)
            and self.start == other.start
            and self.end == other.end
        )

    def __contains__(self, port: Port):
        return self.start <= port <= self.end


class AnyPort(PortSelector):
    def is_any(self) -> bool:
        return True

    def __str__(self):
        return "*"

    def __eq__(self, other: PortSelector):
        return isinstance(other, AnyPort)

    def __contains__(self, port: Port):
        return True


class PortUnion(PortSelector, list[PortSelector]):
    def __init__(self, selectors: List[PortSelector] | None = None):
        super().__init__(selectors or [])

    @classmethod
    def from_str(cls, port_union: str):
        return cls(list(map(PortSelector.from_str, port_union.split(","))))

    def is_any(self) -> bool:
        return any(selector.is_any() for selector in self)

    def __str__(self):
        return ",".join(map(str, self))

    def __eq__(self, other: PortSelector):
        return isinstance(other, PortUnion) and list.__eq__(self, other)

    def __contains__(self, port: Port):
        return any(port in selector for selector in self)
