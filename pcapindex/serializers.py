"""Serializers for the PCAP indexing REST API."""

from __future__ import annotations

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from .models import PacketIndex, PcapFile


class IndexLaunchSerializer(serializers.Serializer):
    """Validates requests that launch asynchronous indexing jobs."""

    path = serializers.CharField(help_text=_("Absolute or relative path to the pcap file."))
    reindex = serializers.BooleanField(default=False)


class PacketDetailQuerySerializer(serializers.Serializer):
    """Validates query parameters for packet detail lookups."""

    filter = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text=_("Optional Wireshark display filter to apply."),
    )


class PacketSearchSerializer(serializers.Serializer):
    """Validates Wireshark style packet search queries."""

    pcap = serializers.PrimaryKeyRelatedField(queryset=PcapFile.objects.all())
    query = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text=_("Display filter expression (Wireshark syntax)."),
    )
    limit = serializers.IntegerField(default=25, min_value=1, max_value=500)


class PcapUploadSerializer(serializers.Serializer):
    """Validates PCAP file uploads sent through multipart requests."""

    file = serializers.FileField()

    def validate_file(self, value):
        filename = value.name or ""
        if not filename.lower().endswith((".pcap", ".pcapng")):
            raise serializers.ValidationError(
                _("Only .pcap or .pcapng files are accepted for upload."),
            )
        if value.size is not None and value.size <= 0:
            raise serializers.ValidationError(_("Uploaded files must not be empty."))
        return value


class PcapFileSerializer(serializers.ModelSerializer):
    """Serializer exposing :class:`~pcapindex.models.PcapFile` metadata."""

    class Meta:
        model = PcapFile
        fields = [
            "id",
            "path",
            "file_timestamp",
            "size_bytes",
            "created_at",
            "updated_at",
        ]


class PacketIndexSerializer(serializers.ModelSerializer):
    """Serializer for search responses that include packet metadata."""

    class Meta:
        model = PacketIndex
        fields = [
            "id",
            "packet_id",
            "packet_timestamp",
            "offset",
            "metadata",
        ]
        read_only_fields = fields
