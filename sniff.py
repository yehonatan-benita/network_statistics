from typing import List
import pyshark  # type: ignore
import asyncio

def get_bytes() -> int:
    capture = pyshark.LiveCapture(interface='eth0')
    capture.sniff(timeout=5)

    return sum([int(packet.length) for packet in capture._packets])


def main() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    packtes = get_bytes()
    print(packtes)
    


if __name__ == "__main__":
    main()