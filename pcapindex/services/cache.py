"""Utilities for managing packet cache entries."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import timedelta
from typing import Iterable

from django.db import transaction
from django.db.models import Count, Max, Min
from django.utils import timezone

from pcapindex.models import PacketCache, PacketIndex, PcapFile

CacheBuilder = Callable[[PcapFile], dict]


def summary_cache_builder(pcap_file: PcapFile) -> dict:
    """Build a lightweight summary of indexed packets for ``pcap_file``."""

    aggregates = PacketIndex.objects.filter(pcap_file=pcap_file).aggregate(
        first_timestamp=Min("packet_timestamp"),
        last_timestamp=Max("packet_timestamp"),
        packets=Count("id"),
    )
    return {
        "first_timestamp": aggregates.get("first_timestamp"),
        "last_timestamp": aggregates.get("last_timestamp"),
        "packet_count": aggregates.get("packets", 0),
    }


DEFAULT_CACHE_BUILDERS: Mapping[str, CacheBuilder] = {
    "summary": summary_cache_builder,
}


def refresh_cache(
    pcap_file: PcapFile,
    cache_key: str,
    builder: CacheBuilder,
) -> PacketCache:
    """Regenerate ``cache_key`` for ``pcap_file`` using ``builder``."""

    payload = builder(pcap_file)

    with transaction.atomic():
        cache_entry, _ = PacketCache.objects.update_or_create(
            pcap_file=pcap_file,
            cache_key=cache_key,
            defaults={"payload": payload},
        )
    return cache_entry


def refresh_predefined_caches(
    pcap_file: PcapFile,
    cache_builders: Mapping[str, CacheBuilder] | None = None,
) -> dict[str, PacketCache]:
    """Regenerate all configured caches for ``pcap_file``."""

    builders = cache_builders or DEFAULT_CACHE_BUILDERS
    refreshed: dict[str, PacketCache] = {}
    for cache_key, builder in builders.items():
        refreshed[cache_key] = refresh_cache(pcap_file, cache_key, builder)
    return refreshed


def cleanup_stale_caches(
    *,
    older_than: timedelta | None = None,
    cache_keys: Iterable[str] | None = None,
) -> int:
    """Remove cache entries outside the retention policy.

    Parameters
    ----------
    older_than:
        When provided, entries with ``last_updated`` earlier than ``now - older_than``
        are removed.
    cache_keys:
        Optional iterable to restrict removal to a subset of cache keys.
    """

    queryset = PacketCache.objects.all()
    if older_than is not None:
        cutoff = timezone.now() - older_than
        queryset = queryset.filter(last_updated__lt=cutoff)
    if cache_keys is not None:
        queryset = queryset.filter(cache_key__in=list(cache_keys))

    deleted, _ = queryset.delete()
    return deleted


__all__ = [
    "CacheBuilder",
    "DEFAULT_CACHE_BUILDERS",
    "refresh_cache",
    "refresh_predefined_caches",
    "cleanup_stale_caches",
    "summary_cache_builder",
]
