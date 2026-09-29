from sentinel_core.normalizers.base import Normalizer
from sentinel_core.normalizers.linux_auth import LinuxAuthNormalizer
from sentinel_core.normalizers.traefik_access import TraefikAccessNormalizer
from sentinel_core.schema.event import Source

# One normalizer per source. Sources absent from this map (nginx.access, which nothing
# ships on the VPS) are sent to the dead-letter table by the worker, never silently dropped.
NORMALIZERS: dict[Source, Normalizer] = {
    Source.LINUX_AUTH: LinuxAuthNormalizer(),
    Source.TRAEFIK_ACCESS: TraefikAccessNormalizer(),
}
