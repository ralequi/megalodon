from django.db import models
from django.utils import timezone


class PcapFile(models.Model):
    """Metadata describing a pcap file indexed by the system."""

    path = models.CharField(max_length=1024, unique=True)
    file_timestamp = models.DateTimeField()
    size_bytes = models.BigIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["path"]

    def __str__(self) -> str:  # pragma: no cover - representational helper
        return self.path

    @property
    def file_modified_at(self):
        """Return the stored timestamp or now if missing."""

        return self.file_timestamp or timezone.now()


class PacketIndex(models.Model):
    """Represents an indexed packet location inside a pcap file."""

    pcap_file = models.ForeignKey(
        PcapFile, related_name="packet_indices", on_delete=models.CASCADE
    )
    packet_id = models.BigIntegerField()
    packet_timestamp = models.DateTimeField()
    offset = models.BigIntegerField()
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["pcap_file", "packet_id"]
        unique_together = ("pcap_file", "packet_id")
        indexes = [
            models.Index(fields=["pcap_file", "packet_id"]),
            models.Index(fields=["pcap_file", "packet_timestamp"]),
        ]

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.pcap_file.path}#{self.packet_id}"


class PacketCache(models.Model):
    """Caches derived information for a packet capture file."""

    pcap_file = models.ForeignKey(
        PcapFile, related_name="caches", on_delete=models.CASCADE
    )
    cache_key = models.CharField(max_length=255)
    payload = models.JSONField(default=dict, blank=True)
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("pcap_file", "cache_key")
        indexes = [
            models.Index(fields=["pcap_file", "cache_key"]),
            models.Index(fields=["last_updated"]),
        ]

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.pcap_file.path}:{self.cache_key}"
