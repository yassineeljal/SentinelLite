from redis.asyncio import Redis

# The API sends short commands (XLEN, a transaction of XADD): a stalled Redis must turn into an
# error (and a 503) within seconds instead of hanging every ingest request.
API_SOCKET_TIMEOUT_SECONDS = 5.0


def build_redis(url: str, socket_timeout: float) -> Redis:
    return Redis.from_url(
        url,
        decode_responses=True,
        socket_timeout=socket_timeout,
        socket_connect_timeout=5,
    )
