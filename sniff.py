from typing import List
import pyshark  # type: ignore
import asyncio

def get_bytes(filter: str | None=None, timeout: int=0) -> int:
    capture = pyshark.LiveCapture(interface='eth0', bpf_filter=filter)
    capture.sniff(timeout=timeout)

    return sum([int(packet.length) for packet in capture._packets])


def main() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    packtes = get_bytes(timeout=5)
    print(packtes)
    


if __name__ == "__main__":
    main()