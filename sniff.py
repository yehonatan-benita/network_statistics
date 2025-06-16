import pyshark  # type: ignore
import asyncio

def sniff() -> None:
    capture = pyshark.LiveCapture(interface='eth0')
    capture.sniff(timeout=50)
    for packet in capture:
        print(packet)


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

sniff()