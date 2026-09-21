"""API v1 routes: upload, link re-issue, image link, metadata."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status

from ..auth import Principal, enforce_quota, require_api_key
from ..config import settings
from ..db import db
from ..images import NotAnImage, inspect_image, make_thumbnail, sniff_mime, strip_exif
from ..schemas import (
    DeleteResponse,
    FileListResponse,
    FileMeta,
    ImageResponse,
    LinkRequest,
    LinkResponse,
    StatsResponse,
    UploadResponse,
)
from ..signing import clamp_ttl
from ..scanservice import initial_status, scan_and_apply
from ..storage import (
    FileTooLarge,
    StorageFull,
    check_capacity,
    delete_blob,
    disk_usage_ratio,
    stream_to_blob,
)
from ..urls import build_download_url, build_image_url

router = APIRouter(prefix="/api/v1", tags=["v1"])


def _to_meta(rec) -> FileMeta:
    return FileMeta(
        file_id=rec.file_id,
        sha256=rec.sha256,
        size_bytes=rec.size_bytes,
        mime_type=rec.mime_type,
        orig_name=rec.orig_name,
        is_image=rec.is_image,
        width=rec.width,
        height=rec.height,
        uploader=rec.uploader,
        created_at=rec.created_at,
        expires_at=rec.expires_at,
        scan_status=rec.scan_status,
        scan_detail=rec.scan_detail,
        scanned_at=rec.scanned_at,
        servable=rec.is_servable,
    )


@router.post(
    "/files",
    response_model=UploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a file or image",
)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    # The descriptions spell out what omitting each field does. Without that,
    # /docs shows three blank boxes with no hint of what is sensible, and a
    # hand-typed ttl of a few seconds makes the link look broken: the signature
    # is valid, the clock skew just has not run out yet, and it expires while
    # you are copying it. Read from settings so the stated default cannot drift
    # from the real one.
    ttl: int | None = Form(
        default=None,
        description=(
            f"download link lifetime in seconds; omit for the server default "
            f"of {settings.default_ttl} (max {settings.max_ttl})"
        ),
        examples=[settings.default_ttl],
    ),
    retain: int | None = Form(
        default=None,
        description=(
            "how long to keep the file, in seconds; omit to keep it "
            "indefinitely. After this elapses the cleanup sweep marks the "
            "record deleted and the blob is reclaimed"
        ),
    ),
    name: str | None = Form(default=None, description="override original filename"),
    principal: Principal = Depends(require_api_key),
) -> UploadResponse:
    # Capacity first: a full disk breaks SQLite commits, taking the whole
    # service down rather than just failing this request.
    try:
        check_capacity()
    except StorageFull as exc:
        raise HTTPException(status.HTTP_507_INSUFFICIENT_STORAGE, str(exc)) from exc

    try:
        # strip_exif runs as a pre-commit hook, not afterwards. See
        # stream_to_blob's docstring: sanitising a committed blob would leave
        # it not hashing to its own filename, which breaks content addressing
        # and makes the sha256/size_bytes we return unverifiable.
        blob = await stream_to_blob(file, sanitize=strip_exif)
    except FileTooLarge as exc:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, str(exc)) from exc

    # Quota is checked against actual bytes, not a declared length.
    enforce_quota(principal, blob.size_bytes)

    path = blob.path
    mime = sniff_mime(path.read_bytes()[:64])

    is_image = mime.startswith("image/")
    width = height = None
    img_format: str | None = None

    if is_image:
        try:
            info = inspect_image(path)
            mime, width, height, img_format = (
                info.mime_type,
                info.width,
                info.height,
                info.format,
            )
            make_thumbnail(path, blob.sha256)
        except NotAnImage:
            # Magic bytes said image but it is not decodable. Keep it as an
            # opaque download rather than rejecting outright.
            is_image = False

    retain_seconds = None if retain is None else max(1, min(retain, settings.max_ttl))
    expires_at = None if retain_seconds is None else int(time.time()) + retain_seconds

    link_ttl = clamp_ttl(ttl, settings.default_ttl, settings.max_ttl)

    rec, deduplicated = db.insert_file(
        sha256=blob.sha256,
        size_bytes=blob.size_bytes,
        mime_type=mime,
        orig_name=name or file.filename,
        is_image=is_image,
        width=width,
        height=height,
        uploader=principal.key_id,
        expires_at=expires_at,
        scan_status=initial_status(),
    )

    # Scan before responding. Doing it here rather than in a background task
    # means the caller never receives a link to a file whose safety is still
    # unknown. Uploads are infrequent relative to downloads, so the added
    # latency does not affect the throughput that matters.
    scan = None
    if rec.scan_status == "pending":
        scan = scan_and_apply(rec.file_id, rec.sha256)
        rec = db.get_file(rec.file_id) or rec

    db.add_used_bytes(principal.key_id, blob.size_bytes)
    db.log(
        key_id=principal.key_id,
        action="upload",
        file_id=rec.file_id,
        ip=request.client.host if request.client else None,
        status=201,
    )

    download_url, download_exp = build_download_url(rec.file_id, link_ttl)
    image_url = build_image_url(rec.file_id, rec.sha8) if is_image else None

    return UploadResponse(
        file_id=rec.file_id,
        mime_type=mime,
        size_bytes=blob.size_bytes,
        sha256=blob.sha256,
        is_image=is_image,
        download_url=download_url,
        download_expires_at=download_exp,
        download_expires_in=link_ttl,
        image_url=image_url,
        deduplicated=deduplicated,
        created_at=rec.created_at,
        scan_status=rec.scan_status,
        scan_detail=rec.scan_detail,
        servable=rec.is_servable,
    )


@router.post(
    "/files/{file_id}/links",
    response_model=LinkResponse,
    summary="Issue a fresh download link",
)
async def create_link(
    file_id: str,
    body: LinkRequest,
    request: Request,
    principal: Principal = Depends(require_api_key),
) -> LinkResponse:
    """Re-issue a signed link.

    This endpoint is authenticated and rate-limited for a specific reason: the
    signature protects the *recipient* of a link, not the caller. A caller
    already holding a valid API key has full access, so an unauthenticated
    re-issue endpoint would make the expiry mechanism meaningless.
    """
    rec = db.get_file(file_id)
    if rec is None or rec.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "file not found")

    ttl = clamp_ttl(body.ttl, settings.default_ttl, settings.max_ttl)
    url, exp = build_download_url(file_id, ttl)

    db.log(
        key_id=principal.key_id,
        action="issue_link",
        file_id=file_id,
        ip=request.client.host if request.client else None,
        status=200,
    )

    return LinkResponse(url=url, expires_at=exp, expires_in=ttl, purpose="dl")


@router.get(
    "/files/{file_id}/image",
    response_model=ImageResponse,
    summary="Get a public image display link",
)
async def get_image_link(
    file_id: str,
    principal: Principal = Depends(require_api_key),
) -> ImageResponse:
    rec = db.get_file(file_id)
    if rec is None or rec.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "file not found")
    if not rec.is_image:
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            f"file is not an image (mime: {rec.mime_type})",
        )

    url = build_image_url(rec.file_id, rec.sha8)
    return ImageResponse(
        image_url=url,
        embedded_markdown=f"![image]({url})",
        embedded_html=f'<img src="{url}" alt="image" />',
        width=rec.width,
        height=rec.height,
        format=rec.mime_type,
    )


@router.get("/files/{file_id}", response_model=FileMeta, summary="Get file metadata")
async def get_file_meta(
    file_id: str,
    principal: Principal = Depends(require_api_key),
) -> FileMeta:
    rec = db.get_file(file_id)
    if rec is None or rec.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "file not found")
    return _to_meta(rec)


@router.get("/files", response_model=FileListResponse, summary="List files")
async def list_files(
    uploader: str | None = None,
    limit: int = 50,
    offset: int = 0,
    principal: Principal = Depends(require_api_key),
) -> FileListResponse:
    rows = db.list_files(uploader=uploader, limit=limit, offset=offset)
    items = [_to_meta(r) for r in rows]
    return FileListResponse(items=items, total_returned=len(items))


@router.delete(
    "/files/{file_id}",
    response_model=DeleteResponse,
    summary="Soft-delete a file",
)
async def delete_file(
    file_id: str,
    request: Request,
    principal: Principal = Depends(require_api_key),
) -> DeleteResponse:
    rec = db.get_file(file_id)
    # Treat an already-soft-deleted file as absent, matching GET /files/{id}.
    # Returning 200 with deleted:false here would be inconsistent: the same
    # resource is a 404 on read but a 200 on delete.
    if rec is None or rec.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "file not found")

    ok = db.soft_delete(file_id)
    db.log(
        key_id=principal.key_id,
        action="delete",
        file_id=file_id,
        ip=request.client.host if request.client else None,
        status=200 if ok else 404,
    )

    # The blob is intentionally NOT removed here. Content addressing means
    # other uploads may share this content, so reclamation goes through the
    # reference-counting sweep, which re-checks before unlinking.
    return DeleteResponse(
        file_id=file_id,
        deleted=ok,
        message="marked for deletion; blob reclaimed by the cleanup sweep",
    )


@router.get("/stats", response_model=StatsResponse, summary="Storage statistics")
async def stats(principal: Principal = Depends(require_api_key)) -> StatsResponse:
    s = db.stats()
    return StatsResponse(disk_usage_ratio=round(disk_usage_ratio(), 4), **s)
