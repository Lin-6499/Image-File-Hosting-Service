"""Request / response models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class UploadResponse(BaseModel):
    file_id: str
    mime_type: str
    size_bytes: int
    sha256: str
    is_image: bool
    download_url: str
    download_expires_at: int
    download_expires_in: int
    image_url: str | None = None
    deduplicated: bool = False
    created_at: int
    # Scanning is optional; when disabled these report "skipped"/True so the
    # response shape stays stable for callers that ignore the feature.
    scan_status: str = "skipped"
    scan_detail: str | None = None
    servable: bool = True


class LinkRequest(BaseModel):
    ttl: int | None = Field(default=None, description="link lifetime in seconds")
    purpose: str = Field(default="dl", pattern="^(dl|img)$")


class LinkResponse(BaseModel):
    url: str
    expires_at: int
    expires_in: int
    purpose: str


class ImageResponse(BaseModel):
    image_url: str
    embedded_markdown: str
    embedded_html: str
    width: int | None = None
    height: int | None = None
    format: str | None = None


class FileMeta(BaseModel):
    file_id: str
    sha256: str
    size_bytes: int
    mime_type: str
    orig_name: str | None
    is_image: bool
    width: int | None
    height: int | None
    uploader: str | None
    created_at: int
    expires_at: int | None
    scan_status: str = "skipped"
    scan_detail: str | None = None
    scanned_at: int | None = None
    servable: bool = True


class FileListResponse(BaseModel):
    items: list[FileMeta]
    total_returned: int


class DeleteResponse(BaseModel):
    file_id: str
    deleted: bool
    message: str


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody


class StatsResponse(BaseModel):
    total_records: int
    live_records: int
    total_bytes: int
    disk_usage_ratio: float
