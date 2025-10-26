"""HTML views that consume the REST API via fetch."""

from __future__ import annotations

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView


class DashboardView(LoginRequiredMixin, TemplateView):
    """Render a small dashboard that interacts with the PCAP API."""

    template_name = "pcapindex/dashboard.html"


__all__ = ["DashboardView"]
