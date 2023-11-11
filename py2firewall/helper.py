import socket
from typing import List


def get_ip_list(domain: str) -> List[str]:
    info = socket.getaddrinfo(domain, 0, 0, 0, 0)
    return list(set([result[-1][0] for result in info]))
