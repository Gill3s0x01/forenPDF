# Nova Versão: argparse, logging, extração de attachments/JS, OCR seguro, validação de IOCs

import argparse
import fitz  # PyMuPDF
import os
import shutil
import time
import json
import hashlib
import datetime
import re
import logging
import sys
from io import BytesIO


# Optional OCR
OCR_ENABLED = False
try:
    from PIL import Image
    import pytesseract

    OCR_ENABLED = True
except Exception:
    OCR_ENABLED = False


# -----------------------
# Utilitários
# -----------------------
def setup_logging(quiet=False):
    lvl = logging.DEBUG if not quiet else logging.WARNING
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def calculate_hashes_bytes(b: bytes):
    md5 = hashlib.md5(b).hexdigest()
    sha1 = hashlib.sha1(b).hexdigest()
    sha256 = hashlib.sha256(b).hexdigest()
    return {"MD5": md5, "SHA1": sha1, "SHA256": sha256}


def calculate_hashes_file(path):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
    return {
        "MD5": md5_hash.hexdigest(),
        "SHA1": sha1_hash.hexdigest(),
        "SHA256": sha256_hash.hexdigest(),
    }


def safe_decode(obj):
    if isinstance(obj, (bytes, bytearray)):
        return obj.decode("utf-8", errors="ignore")
    return str(obj)


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


# Regexes mais robustas
URL_RE = re.compile(r"https?://[^\s\)\]\}\'\"<>]+", re.IGNORECASE)
# IP valid: 0-255 per octet
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")


# -----------------------
# Main processing
# -----------------------
def process_pdf(
    pdf_input, out_base=None, max_xref=200, do_ocr=True, extract_embedded=True
):
    if not os.path.isfile(pdf_input):
        raise FileNotFoundError(pdf_input)
    ts = int(time.time())
    case_folder = os.path.abspath(out_base or f"evidence_{ts}")
    ensure_dir(case_folder)

    original_copy_path = os.path.join(case_folder, os.path.basename(pdf_input))
    shutil.copy2(pdf_input, original_copy_path)
    logging.info("Copied original to evidence folder: %s", original_copy_path)

    hashes = calculate_hashes_file(original_copy_path)
    st = os.stat(original_copy_path)
    created_time = datetime.datetime.fromtimestamp(st.st_ctime)
    modified_time = datetime.datetime.fromtimestamp(st.st_mtime)

    manifest = {
        "case_folder": case_folder,
        "source_path": os.path.abspath(pdf_input),
        "evidence_path": original_copy_path,
        "file_size": st.st_size,
        "created_time": str(created_time),
        "modified_time": str(modified_time),
        "hashes": hashes,
        "pages": [],
        "images": [],
        "links": [],
        "suspicious": {"javascript_xrefs": [], "embeddedfile_xrefs": []},
        "extracted_files": [],
        "tool": {
            "python_version": sys.version,
            "pymupdf_version": fitz.__doc__ if hasattr(fitz, "__doc__") else str(fitz),
        },
    }

    # Prepare output dirs
    images_dir = os.path.join(case_folder, "extracted_images")
    ensure_dir(images_dir)
    reports_dir = os.path.join(case_folder, "reports")
    ensure_dir(reports_dir)
    txt_report_path = os.path.join(
        reports_dir,
        f"{os.path.splitext(os.path.basename(original_copy_path))[0]}_report.txt",
    )
    json_report_path = os.path.join(
        reports_dir,
        f"{os.path.splitext(os.path.basename(original_copy_path))[0]}_manifest.json",
    )

    # Open doc
    doc = fitz.open(original_copy_path)
    try:
        # Extrai metadados padrão do PDF e adiciona no manifest
        metadata_pdf = doc.metadata
        manifest["pdf_metadata"] = metadata_pdf
        # Password handling — PyMuPDF: doc.needs_pass é True se estiver criptografado
        if getattr(doc, "needs_pass", False):
            logging.warning(
                "PDF encrypted; cannot proceed without password in this flow."
            )
            doc.close()
            raise RuntimeError("Encrypted PDF")

        manifest["page_count"] = doc.page_count

        # open text report
        with open(txt_report_path, "w", encoding="utf-8") as report:
            # header
            report.write("FORENSIC PDF REPORT\n\n")
            report.write(f"Source: {pdf_input}\n")
            report.write(f"Evidence copy: {original_copy_path}\n")
            report.write(f"Size: {st.st_size} bytes\n")
            report.write(f"Hashes: {json.dumps(hashes)}\n\n")

            # attempt header/xref sample
            try:
                header = doc.xref_object(0, compressed=False)
                header_s = safe_decode(header)
                if header_s.startswith("%PDF-"):
                    report.write(f"PDF header: {header_s.splitlines()[0]}\n\n")
                    manifest["pdf_version"] = header_s[5:8]
            except Exception as e:
                logging.debug("Could not extract xref 0 header: %s", e)

            # quick xref triage
            for xref in range(1, min(max_xref + 1, doc.xref_length() + 1)):
                try:
                    raw = doc.xref_object(xref, compressed=False)
                    s = safe_decode(raw).lower()
                    if "/javascript" in s or "/js " in s:
                        manifest["suspicious"]["javascript_xrefs"].append(xref)
                        # try to dump it
                        js_path = os.path.join(case_folder, f"js_xref_{xref}.txt")
                        with open(
                            js_path, "w", encoding="utf-8", errors="ignore"
                        ) as fh:
                            fh.write(s)
                        manifest["extracted_files"].append(
                            os.path.relpath(js_path, case_folder)
                        )
                    if "/embeddedfile" in s or "/embeddedfiles" in s:
                        manifest["suspicious"]["embeddedfile_xrefs"].append(xref)
                except Exception:
                    continue

            if (
                manifest["suspicious"]["javascript_xrefs"]
                or manifest["suspicious"]["embeddedfile_xrefs"]
            ):
                report.write("SUSPICIOUS XREFS (triage)\n")
                report.write(
                    json.dumps(manifest["suspicious"], indent=2, ensure_ascii=False)
                    + "\n\n"
                )

            total_lines = total_images = total_links = 0
            seen_image_hashes = set()
            seen_links = set()

            for pno in range(doc.page_count):
                page = doc.load_page(pno)
                report.write(f"\n=== PAGE {pno+1} ===\n")
                page_text = page.get_text() or ""
                report.write("[PAGE TEXT START]\n")
                # Write a limited preview if huge
                report.write(
                    (page_text[:20000] + "...(truncated)\n")
                    if len(page_text) > 20000
                    else page_text + "\n"
                )
                report.write("[PAGE TEXT END]\n\n")

                # IOCs
                urls = URL_RE.findall(page_text)
                ips = IP_RE.findall(page_text)
                emails = EMAIL_RE.findall(page_text)

                urls = list(dict.fromkeys(urls))
                ips = list(dict.fromkeys(ips))
                emails = list(dict.fromkeys(emails))

                manifest["pages"].append(
                    {"page_number": pno + 1, "urls": urls, "ips": ips, "emails": emails}
                )
                for u in urls:
                    if u not in seen_links:
                        manifest["links"].append(u)
                        seen_links.add(u)
                        total_links += 1

                report.write(f"IOCs: urls={urls} ips={ips} emails={emails}\n")

                # images
                imgs = page.get_images(full=True)
                if imgs:
                    for imginfo in imgs:
                        try:
                            xref = imginfo[0]
                            base = doc.extract_image(xref)
                            b = base["image"]
                            h = hashlib.sha256(b).hexdigest()
                            if h in seen_image_hashes:
                                logging.debug(
                                    "Duplicate image on page %s, xref %s => skipping duplicate write",
                                    pno + 1,
                                    xref,
                                )
                                continue
                            seen_image_hashes.add(h)
                            ext = base.get("ext", "bin")
                            img_fname = os.path.join(
                                images_dir, f"p{pno+1}_xref{xref}.{ext}"
                            )
                            with open(img_fname, "wb") as imf:
                                imf.write(b)
                            manifest["images"].append(
                                {
                                    "page": pno + 1,
                                    "file": os.path.relpath(img_fname, case_folder),
                                    "hash": h,
                                    "size": len(b),
                                    "xref": xref,
                                }
                            )
                            total_images += 1
                            report.write(f"Saved image: {img_fname} (sha256={h})\n")

                            # optional OCR
                            if do_ocr and OCR_ENABLED:
                                try:
                                    im = Image.open(BytesIO(b))
                                    # convert to RGB to avoid palette/CMYK issues
                                    if im.mode != "RGB":
                                        im = im.convert("RGB")
                                    ocr_text = pytesseract.image_to_string(im)
                                    if ocr_text and ocr_text.strip():
                                        snippet = ocr_text.strip()[:1000]
                                        manifest["images"][-1]["ocr_snippet"] = snippet
                                        report.write(f"[OCR snippet]: {snippet}\n")
                                except Exception as e:
                                    logging.debug(
                                        "OCR error on image xref %s: %s", xref, e
                                    )
                        except Exception as e:
                            logging.debug(
                                "Image extraction error on page %s: %s", pno + 1, e
                            )
                else:
                    report.write("No images on page.\n")

                # links (annotations)
                try:
                    page_links = page.get_links()
                    if page_links:
                        for lk in page_links:
                            report.write(f"Annotation link: {lk}\n")
                            uri = lk.get("uri") if isinstance(lk, dict) else None
                            if uri and uri not in seen_links:
                                manifest["links"].append(uri)
                                seen_links.add(uri)
                                total_links += 1
                except Exception as e:
                    logging.debug("Error reading page links: %s", e)

            # Extract embedded files (if requested)
            if extract_embedded:
                try:
                    # PyMuPDF supports attachments via doc.embeddedFileNames() (if available)
                    if hasattr(doc, "embeddedFileNames"):
                        for name in doc.embeddedFileNames():
                            try:
                                fileinfo = doc.embeddedFileGet(name)
                                data = fileinfo.get("content")
                                if data:
                                    outp = os.path.join(
                                        case_folder, "embedded_files", name
                                    )
                                    ensure_dir(os.path.dirname(outp))
                                    with open(outp, "wb") as fh:
                                        fh.write(data)
                                    manifest["extracted_files"].append(
                                        os.path.relpath(outp, case_folder)
                                    )
                                    report.write(f"Extracted embedded file: {outp}\n")
                            except Exception as e:
                                logging.debug(
                                    "Error extracting embedded file %s: %s", name, e
                                )
                except Exception as e:
                    logging.debug(
                        "Embedded file extraction not supported or failed: %s", e
                    )

            manifest["summary"] = {
                "total_images": total_images,
                "total_links": total_links,
            }
            report.write("\nSUMMARY:\n")
            report.write(
                json.dumps(manifest["summary"], indent=2, ensure_ascii=False) + "\n"
            )
            report.write(f"Manifest saved to: {json_report_path}\n")
    finally:
        try:
            doc.close()
        except Exception:
            pass

    with open(json_report_path, "w", encoding="utf-8") as jf:
        json.dump(manifest, jf, indent=2, ensure_ascii=False)

    logging.info(
        "Processing done. Reports: %s and %s", txt_report_path, json_report_path
    )
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Forensic PDF processor")
    parser.add_argument("pdf", help="Path to PDF to analyze")
    parser.add_argument("--out", help="Output folder base", default=None)
    parser.add_argument(
        "--no-ocr", action="store_true", help="Disable OCR even if available"
    )
    parser.add_argument(
        "--max-xref", type=int, default=200, help="Max xref objects to triage"
    )
    parser.add_argument(
        "--no-embedded",
        action="store_true",
        help="Do not attempt to extract embedded files",
    )
    parser.add_argument("--quiet", action="store_true", help="Less logging")
    args = parser.parse_args()

    setup_logging(quiet=args.quiet)
    manifest = process_pdf(
        args.pdf,
        out_base=args.out,
        max_xref=args.max_xref,
        do_ocr=(not args.no_ocr) and OCR_ENABLED,
        extract_embedded=(not args.no_embedded),
    )


if __name__ == "__main__":
    main()
