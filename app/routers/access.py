"""Access routes: signed download links and public image links.

These are the two public, unauthenticated entry points. Everything here is
verification logic, so the ordering of checks matters.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, Response

from ..config import settings
from ..db import db
from ..signing import SignatureError, verify
from ..storage import blob_path, local_path_for_serving, thumb_path
from ..urls import content_disposition

router = APIRouter(tags=["access"])


@router.get("/d/{file_id}", summary="Download via signed link")
async def download(
    file_id: str,
    request: Request,
    exp: int = Query(...),
    p: str = Query(default="dl"),
    sig: str = Query(...),
):
    """Serve a file for a valid signed link.

    Status code choice is deliberate:

    * ``403`` -- signature invalid. Never retry; the URL is wrong or forged.
    * ``410`` -- link expired. Retry by requesting a fresh link. Distinct from
      404 so an automated caller can tell "expired, re-issue" apart from
      "bad url, surface an error".
    * ``404`` -- file genuinely absent.
    """
    try:
        verify(
            file_id,
            exp,
            p,
            sig,
            settings.secret_key,
            clock_skew=settings.clock_skew,
        )
    except SignatureError as exc:
        if exc.reason == "expired":
            raise HTTPException(status.HTTP_410_GONE, "link expired") from exc
        db.log(
            key_id=None,
            action="download_denied",
            file_id=file_id,
            ip=request.client.host if request.client else None,
            status=403,
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid signature") from exc

    rec = db.get_file(file_id)
    if rec is None or rec.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "file not found")

    # Antivirus gate. A signature-valid link is not sufficient: the file must
    # also have cleared scanning.
    #
    #  * infected -> 403. The verdict is final; the caller must not retry.
    #  * pending  -> 409. Transient: scanning has not finished, so retrying the
    #                same URL later may succeed. 409 rather than 403 is
    #                deliberate, so an automated caller retries instead of
    #                treating the link as permanently broken.
    #  * error    -> 409 as well, since the scanner may recover.
    if rec.scan_status == "infected":
        db.log(
            key_id=None,
            action="download_blocked",
            file_id=file_id,
            ip=request.client.host if request.client else None,
            status=403,
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "file failed malware scan and will not be served",
        )
    if not rec.is_servable:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"file is not available yet (scan status: {rec.scan_status})",
        )

    path = local_path_for_serving(rec.sha256)
    if not path.exists():
        # Metadata without a blob means the store is inconsistent; surface it
        # rather than returning a confusing empty 200.
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "blob missing")

    if not settings.serve_files_directly:
        # Production path: nginx reads the file, the Python process only
        # writes a header. Keeps large transfers out of the app's memory.
        return Response(
            status_code=200,
            headers={
                "X-Accel-Redirect": f"/_blobs/{rec.sha256[:2]}/{rec.sha256}",
                "Content-Type": rec.mime_type,
                "Content-Disposition": content_disposition(rec.orig_name),
                "X-Content-Type-Options": "nosniff",
            },
        )

    return FileResponse(
        path,
        media_type=rec.mime_type,
        filename=rec.orig_name,
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.get("/i/{file_id}/{sha8}.{ext}", summary="Public image display link")
async def serve_image(
    file_id: str,
    sha8: str,
    ext: str,
    request: Request,
):
    """Serve a thumbnail or the original image at a long-lived URL.

    No expiry: image links are meant to stay embedded in documents. The
    protection is the unguessable 128-bit ``file_id`` plus the content hash in
    the path. ``sha8`` is verified against stored metadata so a URL cannot be
    reused to probe for different content under the same id.
    """
    rec = db.get_file(file_id)
    if rec is None or rec.deleted_at is not None or not rec.is_image:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")

    # Same antivirus gate as /d/. Image links are public and long-lived, so an
    # infected image must not be displayable through this path either.
    if not rec.is_servable:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"not found (scan status: {rec.scan_status})",
        )

    if rec.sha8 != sha8:
        # Content changed but the URL was not updated -> stale cache key.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "content mismatch")

    is_thumb = ext == "webp"
    path = thumb_path(rec.sha256) if is_thumb else blob_path(rec.sha256)

    if is_thumb and not path.exists():
        # Thumbnail may be absent for animated GIFs; fall back to the original.
        path = blob_path(rec.sha256)

    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")

    headers = {
        "Cache-Control": "public, max-age=31536000, immutable",
        "X-Content-Type-Options": "nosniff",
    }

    if not settings.serve_files_directly:
        kind = "thumbs" if (is_thumb and path.parent.parent == settings.thumbs_dir) else "blobs"
        return Response(
            status_code=200,
            headers={
                **headers,
                "X-Accel-Redirect": f"/_{kind}/{rec.sha256[:2]}/{path.name}",
                "Content-Type": "image/webp" if path.suffix == ".webp" else rec.mime_type,
            },
        )

    return FileResponse(
        path,
        media_type="image/webp" if path.suffix == ".webp" else rec.mime_type,
        headers=headers,
    )
