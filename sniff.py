from typing import Tuple
import pyshark  # type: ignore
import asyncio


UPLINK_FILTER_TEMPLATE = "(ip.src=={host_ip})&&(ip.dst=={remote_ip})"
DOWNLINK_FILTER_TEMPLATE = "(ip.src=={remote_ip})&&(ip.dst=={host_ip})"


def capture_packets_bytes(filter: str | None = None, timeout: int = 0) -> int:
    capture = pyshark.LiveCapture(interface="eth0", capture_filter=filter)
    capture.sniff(timeout=timeout)

    return sum([int(packet.length) for packet in capture._packets])


async def async_wrapper_capture_packets_bytes(
    loop: asyncio.AbstractEventLoop, filter: str | None = None, timeout: int = 0
) -> int:
    return await loop.run_in_executor(None, capture_packets_bytes, filter, timeout)


async def capture_uplink_and_downlink_bytes(
    host_ip: str, remote_ip: str, loop: asyncio.AbstractEventLoop
) -> Tuple[int, int]:
    uplink_filter = UPLINK_FILTER_TEMPLATE.format(host_ip=host_ip, remote_ip=remote_ip)
    downlink_filter = DOWNLINK_FILTER_TEMPLATE.format(
        host_ip=host_ip, remote_ip=remote_ip
    )

    uplink_bytes, downlink_bytes = await asyncio.gather(
        async_wrapper_capture_packets_bytes(loop, uplink_filter, 1),
        async_wrapper_capture_packets_bytes(loop, downlink_filter, 1),
    )
    return uplink_bytes, downlink_bytes  # type: ignore


def main() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    while True:
        print(
            loop.run_until_complete(
                capture_uplink_and_downlink_bytes(
                    host_ip="172.23.69.87", remote_ip="91.189.91.157", loop=loop
                )
            )
        )


if __name__ == "__main__":
    main()
