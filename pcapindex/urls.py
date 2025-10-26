"""URL configuration for the pcapindex application."""

from __future__ import annotations

from django.urls import path

from . import api, views

app_name = "pcapindex"

urlpatterns = [
    path("dashboard/", views.DashboardView.as_view(), name="dashboard"),
    path("api/index/", api.IndexLaunchView.as_view(), name="api-index"),
    path("api/packets/search/", api.PacketSearchView.as_view(), name="api-search"),
    path("api/packets/<int:pk>/", api.PacketDetailView.as_view(), name="api-packet-detail"),
    path("api/pcaps/upload/", api.PcapUploadView.as_view(), name="api-upload"),
    path("api/pcaps/", api.PcapListView.as_view(), name="api-pcaps"),
]
