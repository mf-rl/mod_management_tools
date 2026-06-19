#!/usr/bin/env python3
"""Download all .package files from a SimFileShare folder."""

from __future__ import annotations

import argparse
import html
import http.client
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import Message
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Iterable


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0 Safari/537.36"
)
TEXT_CONTENT_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "text/plain",
}
WINDOWS_FORBIDDEN_CHARS = '<>:"/\\|?*'


@dataclass(frozen=True)
class PackageLink:
    filename: str
    url: str
    prefer_remote_filename: bool = False


@dataclass(frozen=True)
class RequestCandidate:
    url: str
    method: str = "GET"
    data: bytes | None = None

    @property
    def key(self) -> tuple[str, str, bytes | None]:
        return (self.method.upper(), self.url, self.data)


class FolderParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[PackageLink] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        attr_map = dict(attrs)
        href = attr_map.get("href")
        if href:
            self._href = href
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self._href is None:
            return

        text = html.unescape("".join(self._text)).strip()
        if text.lower().endswith(".package"):
            self.links.append(
                PackageLink(
                    filename=text,
                    url=urllib.parse.urljoin(self.base_url, self._href),
                )
            )

        self._href = None
        self._text = []


class DownloadPageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.anchors: list[tuple[str, str]] = []
        self.forms: list[dict[str, object]] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._form: dict[str, object] | None = None
        self._button_text: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr_map = {key.lower(): value for key, value in attrs}

        if tag == "a":
            href = attr_map.get("href")
            if href:
                self._href = href
                self._anchor_text = []
            return

        if tag == "form":
            self._form = {
                "action": attr_map.get("action") or self.base_url,
                "method": (attr_map.get("method") or "GET").upper(),
                "fields": [],
                "has_download_submit": False,
            }
            return

        if self._form is None:
            return

        if tag == "input":
            input_type = (attr_map.get("type") or "text").lower()
            name = attr_map.get("name")
            value = attr_map.get("value") or ""
            if name:
                fields = self._form["fields"]
                assert isinstance(fields, list)
                fields.append((name, value))
            if input_type in {"submit", "button"} and "download" in value.lower():
                self._form["has_download_submit"] = True
            return

        if tag == "button":
            self._button_text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._anchor_text.append(data)
        if self._button_text is not None:
            self._button_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()

        if tag == "a" and self._href is not None:
            text = html.unescape("".join(self._anchor_text)).strip()
            self.anchors.append((text, urllib.parse.urljoin(self.base_url, self._href)))
            self._href = None
            self._anchor_text = []
            return

        if tag == "button" and self._form is not None and self._button_text is not None:
            text = html.unescape("".join(self._button_text)).strip()
            if "download" in text.lower():
                self._form["has_download_submit"] = True
            self._button_text = None
            return

        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def download_candidates(self, current_url: str) -> list[RequestCandidate]:
        candidates: list[RequestCandidate] = []
        normalized_current = strip_fragment(current_url)

        for text, href in self.anchors:
            normalized_href = strip_fragment(href)
            link_text = text.lower()
            path = urllib.parse.urlparse(href).path.lower()
            if normalized_href == normalized_current:
                continue
            if "download" in link_text or path.endswith(".package") or "/download/" in path:
                candidates.append(RequestCandidate(href))

        for form in self.forms:
            if not form.get("has_download_submit"):
                continue
            action = urllib.parse.urljoin(self.base_url, str(form["action"]))
            method = str(form["method"]).upper()
            fields = form["fields"]
            assert isinstance(fields, list)
            data = urllib.parse.urlencode(fields).encode("utf-8")
            if method == "POST":
                candidates.append(RequestCandidate(action, method="POST", data=data))
            else:
                separator = "&" if urllib.parse.urlparse(action).query else "?"
                url = action if not data else action + separator + data.decode("utf-8")
                candidates.append(RequestCandidate(url))

        return candidates


def strip_fragment(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def make_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))


def make_request(candidate: RequestCandidate, *, range_start: int | None = None) -> urllib.request.Request:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    }
    if range_start and range_start > 0 and candidate.method.upper() == "GET":
        headers["Range"] = f"bytes={range_start}-"

    return urllib.request.Request(
        candidate.url,
        data=candidate.data,
        headers=headers,
        method=candidate.method.upper(),
    )


def read_response_bytes(response: object) -> bytes:
    chunks: list[bytes] = []
    total = 0
    content_length = response.headers.get("Content-Length")
    expected_length: int | None = None

    if content_length:
        try:
            expected_length = int(content_length)
        except ValueError:
            expected_length = None

    while True:
        chunk = response.read(1024 * 64)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)

    if expected_length is not None and total < expected_length:
        raise http.client.IncompleteRead(b"".join(chunks), expected_length - total)

    return b"".join(chunks)


def response_text(response: object) -> str:
    raw = read_response_bytes(response)
    charset = response.headers.get_content_charset() or "utf-8"
    return raw.decode(charset, errors="replace")


def fetch_text(opener: urllib.request.OpenerDirector, url: str, timeout: float) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    with opener.open(request, timeout=timeout) as response:
        return response_text(response)


def fetch_text_with_retries(
    opener: urllib.request.OpenerDirector,
    url: str,
    timeout: float,
    retries: int,
    sleep_seconds: float,
) -> str:
    attempts = max(1, retries)

    for attempt in range(1, attempts + 1):
        try:
            return fetch_text(opener, url, timeout)
        except (OSError, urllib.error.URLError, http.client.HTTPException) as exc:
            if attempt >= attempts:
                raise
            print(f"WARN folder scan failed: {exc}; retrying ({attempt + 1}/{attempts})")
            time.sleep(sleep_seconds)

    raise RuntimeError(f"could not fetch {url}")


def parse_folder(html_text: str, folder_url: str) -> list[PackageLink]:
    parser = FolderParser(folder_url)
    parser.feed(html_text)
    return parser.links


def is_file_response(response: object) -> bool:
    headers = response.headers
    content_type = headers.get_content_type().lower()
    content_disposition = headers.get("Content-Disposition", "").lower()
    response_url = getattr(response, "url", "")
    path = urllib.parse.unquote(urllib.parse.urlparse(response_url).path).lower()

    return (
        "attachment" in content_disposition
        or path.endswith(".package")
        or content_type not in TEXT_CONTENT_TYPES
    )


def filename_from_content_disposition(value: str | None) -> str | None:
    if not value:
        return None

    message = Message()
    message["Content-Disposition"] = value
    filename = message.get_filename()
    if filename:
        return filename
    return None


def fallback_filename_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path_name = urllib.parse.unquote(Path(parsed.path.rstrip("/")).name)
    if path_name.lower().endswith(".package"):
        return path_name

    download_id = download_id_from_url(url)
    if download_id:
        return f"download_{download_id}.package"

    return "download.package"


def resolved_filename(response: object, fallback: str, prefer_remote_filename: bool) -> str:
    remote_filename = filename_from_content_disposition(response.headers.get("Content-Disposition"))
    if prefer_remote_filename and remote_filename:
        return sanitize_filename(remote_filename)
    return sanitize_filename(fallback)


def parse_content_range_total(value: str | None) -> int | None:
    if not value:
        return None
    match = re.search(r"/(\d+|\*)\s*$", value)
    if not match or match.group(1) == "*":
        return None
    return int(match.group(1))


def expected_total_size(response: object, start_size: int) -> int | None:
    content_range_total = parse_content_range_total(response.headers.get("Content-Range"))
    if content_range_total is not None:
        return content_range_total

    content_length = response.headers.get("Content-Length")
    if not content_length:
        return None

    try:
        length = int(content_length)
    except ValueError:
        return None

    status = getattr(response, "status", None)
    if status == 206:
        return start_size + length
    return length


def sanitize_filename(filename: str) -> str:
    cleaned = "".join("_" if char in WINDOWS_FORBIDDEN_CHARS else char for char in filename)
    cleaned = "".join("_" if ord(char) < 32 else char for char in cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip().rstrip(".")
    return cleaned or "download.package"


def unique_package_names(links: Iterable[PackageLink]) -> list[PackageLink]:
    seen: set[str] = set()
    unique: list[PackageLink] = []

    for link in links:
        safe = sanitize_filename(link.filename)
        candidate = safe
        stem = Path(safe).stem
        suffix = Path(safe).suffix
        download_id = download_id_from_url(link.url)
        counter = 2

        while candidate.casefold() in seen:
            label = download_id if counter == 2 and download_id else str(counter)
            candidate = f"{stem} ({label}){suffix}"
            counter += 1

        seen.add(candidate.casefold())
        unique.append(
            PackageLink(
                filename=candidate,
                url=link.url,
                prefer_remote_filename=link.prefer_remote_filename,
            )
        )

    return unique


def download_id_from_url(url: str) -> str | None:
    match = re.search(r"/download/([^/]+)/?", urllib.parse.urlparse(url).path)
    if match:
        return match.group(1)
    return None


def human_size(size: int | None) -> str:
    if size is None:
        return "unknown size"

    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024

    return f"{size} B"


def stream_file_response(
    response: object,
    output_dir: Path,
    filename_hint: str,
    overwrite: bool,
    prefer_remote_filename: bool,
) -> tuple[Path, bool]:
    target_path = output_dir / resolved_filename(response, filename_hint, prefer_remote_filename)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if should_skip_existing(target_path, overwrite):
        print(f"SKIP {target_path.name} (already exists)")
        return target_path, True

    temp_path = target_path.with_name(target_path.name + ".part")

    status = getattr(response, "status", None)
    requested_resume = temp_path.exists() and not overwrite
    append = requested_resume and status == 206

    if requested_resume and not append:
        temp_path.unlink(missing_ok=True)

    mode = "ab" if append else "wb"
    start_size = temp_path.stat().st_size if append and temp_path.exists() else 0
    total_size = expected_total_size(response, start_size)
    downloaded = start_size
    last_report = 0.0

    print(f"  -> {target_path.name} ({human_size(total_size)})")
    with temp_path.open(mode) as file:
        while True:
            chunk = response.read(1024 * 256)
            if not chunk:
                break
            file.write(chunk)
            downloaded += len(chunk)
            now = time.monotonic()
            if now - last_report >= 2.0:
                if total_size:
                    percent = downloaded / total_size * 100
                    print(f"     {human_size(downloaded)} / {human_size(total_size)} ({percent:.1f}%)")
                else:
                    print(f"     {human_size(downloaded)}")
                last_report = now

    final_size = temp_path.stat().st_size
    if total_size is not None and final_size < total_size:
        raise OSError(f"incomplete download: got {final_size} of {total_size} bytes")

    if target_path.exists() and overwrite:
        target_path.unlink()
    os.replace(temp_path, target_path)
    return target_path, False


def parse_download_page(html_text: str, page_url: str) -> list[RequestCandidate]:
    parser = DownloadPageParser(page_url)
    parser.feed(html_text)
    return parser.download_candidates(page_url)


def download_with_resolution(
    opener: urllib.request.OpenerDirector,
    initial_url: str,
    output_dir: Path,
    filename_hint: str,
    timeout: float,
    overwrite: bool,
    max_depth: int,
    prefer_remote_filename: bool,
) -> tuple[Path, bool]:
    queue = [RequestCandidate(initial_url)]
    seen: set[tuple[str, str, bytes | None]] = set()

    while queue and len(seen) < max_depth:
        candidate = queue.pop(0)
        if candidate.key in seen:
            continue
        seen.add(candidate.key)

        fallback_target_path = output_dir / sanitize_filename(filename_hint)
        temp_path = fallback_target_path.with_name(fallback_target_path.name + ".part")
        range_start = temp_path.stat().st_size if temp_path.exists() and not overwrite else None
        request = make_request(candidate, range_start=range_start)

        with opener.open(request, timeout=timeout) as response:
            if is_file_response(response):
                return stream_file_response(
                    response=response,
                    output_dir=output_dir,
                    filename_hint=filename_hint,
                    overwrite=overwrite,
                    prefer_remote_filename=prefer_remote_filename,
                )

            html_text = response_text(response)
            next_candidates = parse_download_page(html_text, response.url)
            queue.extend(next_candidates)

    raise RuntimeError(f"could not find a downloadable file behind {initial_url}")


def should_skip_existing(path: Path, overwrite: bool) -> bool:
    return path.exists() and not overwrite


def download_one(
    opener: urllib.request.OpenerDirector,
    link: PackageLink,
    output_dir: Path,
    timeout: float,
    retries: int,
    sleep_seconds: float,
    overwrite: bool,
    max_depth: int,
) -> bool:
    target_path = output_dir / link.filename
    if not link.prefer_remote_filename and should_skip_existing(target_path, overwrite):
        print(f"SKIP {link.filename} (already exists)")
        return True

    for attempt in range(1, retries + 1):
        try:
            print(f"GET  {link.filename}")
            final_path, skipped = download_with_resolution(
                opener=opener,
                initial_url=link.url,
                output_dir=output_dir,
                filename_hint=link.filename,
                timeout=timeout,
                overwrite=overwrite,
                max_depth=max_depth,
                prefer_remote_filename=link.prefer_remote_filename,
            )
            if not skipped:
                print(f"OK   {final_path.name}")
            return True
        except (
            OSError,
            urllib.error.URLError,
            urllib.error.HTTPError,
            http.client.HTTPException,
            RuntimeError,
        ) as exc:
            if attempt >= retries:
                print(f"FAIL {link.filename}: {exc}", file=sys.stderr)
                return False
            print(f"WARN {link.filename}: {exc}; retrying ({attempt + 1}/{retries})")
            time.sleep(sleep_seconds)

    return False


def is_folder_url(url: str) -> bool:
    path = urllib.parse.urlparse(url).path.lower()
    return "/folder/" in path


def direct_link_from_url(url: str) -> PackageLink:
    return PackageLink(
        filename=sanitize_filename(fallback_filename_from_url(url)),
        url=url,
        prefer_remote_filename=True,
    )


def links_from_input_urls(
    opener: urllib.request.OpenerDirector,
    urls: Iterable[str],
    timeout: float,
    retries: int,
    sleep_seconds: float,
) -> list[PackageLink]:
    links: list[PackageLink] = []

    for url in urls:
        if is_folder_url(url):
            print(f"Scanning folder {url}")
            folder_html = fetch_text_with_retries(
                opener=opener,
                url=url,
                timeout=timeout,
                retries=retries,
                sleep_seconds=sleep_seconds,
            )
            folder_links = parse_folder(folder_html, url)
            print(f"Found {len(folder_links)} .package files in {url}")
            links.extend(folder_links)
        else:
            print(f"Adding direct URL {url}")
            links.append(direct_link_from_url(url))

    return unique_package_names(links)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Download .package files from SimFileShare folder or direct download URLs."
    )
    parser.add_argument(
        "urls",
        nargs="+",
        help="One or more SimFileShare folder URLs or direct download/file URLs.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="simfileshare_packages",
        help="Directory where .package files will be saved.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List package links without downloading them.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Download only the first N package files. Useful for testing.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing completed files instead of skipping them.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=4,
        help="Attempts per file. Partial .part files are resumed when possible.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=2.0,
        help="Seconds to wait between file retries.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=6,
        help="Maximum number of intermediate download pages to follow per file.",
    )
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    opener = make_opener()

    all_links = links_from_input_urls(
        opener=opener,
        urls=args.urls,
        timeout=args.timeout,
        retries=args.retries,
        sleep_seconds=args.sleep,
    )
    links = all_links

    if args.limit is not None:
        links = links[: args.limit]

    print(f"Resolved {len(all_links)} download item(s)")
    if args.limit is not None:
        print(f"Using first {len(links)} because --limit was set")
    if args.dry_run:
        for index, link in enumerate(links, start=1):
            print(f"{index:>4}. {link.filename} -> {link.url}")
        return 0

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    succeeded = 0
    for index, link in enumerate(links, start=1):
        print(f"[{index}/{len(links)}]")
        if download_one(
            opener=opener,
            link=link,
            output_dir=output_dir,
            timeout=args.timeout,
            retries=args.retries,
            sleep_seconds=args.sleep,
            overwrite=args.overwrite,
            max_depth=args.max_depth,
        ):
            succeeded += 1

    failed = len(links) - succeeded
    print(f"Done: {succeeded} succeeded, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
