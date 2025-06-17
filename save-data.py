import fitz
import os
import hashlib
import datetime


# Function to calculate file hashes
def calculate_hashes(file_path):
    hashes = {"MD5": "", "SHA1": "", "SHA256": ""}
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    hashes["MD5"] = md5_hash.hexdigest()
    hashes["SHA1"] = sha1_hash.hexdigest()
    hashes["SHA256"] = sha256_hash.hexdigest()

    return hashes


# Ask the user to input the PDF file path
pdf_path = input("📄 Enter the full path and filename of the PDF to process: ").strip()

# Check if the file exists
if not os.path.isfile(pdf_path):
    print(f"❌ File not found: {pdf_path}")
    exit(1)

# Collect file information
file_stats = os.stat(pdf_path)
file_size = file_stats.st_size
created_time = datetime.datetime.fromtimestamp(file_stats.st_ctime)
modified_time = datetime.datetime.fromtimestamp(file_stats.st_mtime)
file_hashes = calculate_hashes(pdf_path)
absolute_path = os.path.abspath(pdf_path)

# Open the PDF document
doc = fitz.open(pdf_path)

# Create a directory for extracted images if it doesn't exist
if not os.path.exists("extracted_images"):
    os.makedirs("extracted_images")

total_lines = 0
image_counter = 0
total_images = 0
total_links = 0

# Define report filename based on the PDF name
pdf_name = os.path.splitext(os.path.basename(pdf_path))[0]
report_filename = f"{pdf_name}_full_report.txt"

# Open a text file to write the full report
with open(report_filename, "w", encoding="utf-8") as report:

    report.write("=== 📄 FORENSIC FILE INFORMATION ===\n\n")
    report.write(f"File name: {pdf_name}\n")
    report.write(f"Absolute path: {absolute_path}\n")
    report.write(f"File size: {file_size} bytes\n")
    report.write(f"Created: {created_time}\n")
    report.write(f"Last modified: {modified_time}\n\n")

    report.write("=== 🔐 FILE HASHES ===\n\n")
    for algo, hash_value in file_hashes.items():
        report.write(f"{algo}: {hash_value}\n")
    report.write("\n")

    report.write("=== 📄 PDF METADATA ===\n\n")
    for key, value in doc.metadata.items():
        report.write(f"{key}: {value}\n")
    report.write("\n")

    # Get PDF version from first line of xref 0 object
    try:
        header = doc.xref_object(0, compressed=False)
        if header.startswith(b"%PDF-"):
            pdf_version = header[5:8].decode("utf-8")
            report.write(f"PDF Version: {pdf_version}\n")
        else:
            report.write("PDF Version: Not found in header.\n")
    except:
        report.write("PDF Version: Unable to extract.\n")

    report.write(f"Number of Pages: {doc.page_count}\n\n")

    report.write("=== 📦 PDF INTERNAL OBJECTS (FIRST 20) ===\n\n")
    for xref in range(1, min(21, doc.xref_length())):
        obj_info = doc.xref_object(xref, compressed=False)
        report.write(f"Object {xref}:\n{obj_info[:300]}...\n\n")

    for page_num in range(doc.page_count):
        page = doc[page_num]
        report.write(f"\n\n=== 📖 PAGE {page_num + 1} ===\n\n")

        # Extract and write text
        report.write("=== 📖 TEXT ===\n\n")
        page_text = page.get_text()
        report.write(page_text + "\n\n")
        lines_in_page = len(page_text.splitlines())
        total_lines += lines_in_page

        # Extract and save images
        report.write("=== 🖼️ IMAGES ===\n\n")
        images = page.get_images(full=True)
        if images:
            for img in images:
                xref = img[0]
                base_image = doc.extract_image(xref)
                image_bytes = base_image["image"]
                image_ext = base_image["ext"]
                image_filename = f"extracted_images/{pdf_name}_page{page_num + 1}_image{image_counter}.{image_ext}"
                with open(image_filename, "wb") as image_file:
                    image_file.write(image_bytes)
                report.write(f"Image {image_counter}: {image_filename}\n")
                image_counter += 1
                total_images += 1
        else:
            report.write("No images found on this page.\n")
        report.write("\n")

        # Extract links
        report.write("=== 🔗 LINKS ===\n\n")
        links = page.get_links()
        if links:
            for link in links:
                report.write(str(link) + "\n")
                total_links += 1
        else:
            report.write("No links found on this page.\n")
        report.write("\n")

        # Extract text blocks
        report.write("=== 📦 TEXT BLOCKS ===\n\n")
        for block in page.get_text("blocks"):
            report.write(block[4] + "\n\n")

        # Extract words
        report.write("=== 📝 WORDS ===\n\n")
        words = page.get_text("words")
        if words:
            for word in words:
                report.write(str(word) + "\n")
        else:
            report.write("No words detected.\n")
        report.write("\n")

        report.write(f"=== 📊 TOTAL LINES ON THIS PAGE: {lines_in_page} ===\n\n")

    # Extract raw XMP metadata if available
    report.write("=== 📜 XMP CONTENT (RAW) ===\n\n")
    try:
        xmp = doc.xref_object(1, compressed=False)
        report.write(xmp + "\n\n")
    except:
        report.write("No XMP content found.\n\n")

    report.write(f"=== 📊 TOTAL LINES IN DOCUMENT: {total_lines} ===\n")
    report.write(f"Total images extracted: {total_images}\n")
    report.write(f"Total links extracted: {total_links}\n")

# Save the cleaned and optimized PDF
optimized_pdf_filename = f"{pdf_name}_extracted.pdf"
doc.save(optimized_pdf_filename, garbage=4, deflate=True)
doc.close()

print(f"✅ Full forensic report saved as '{report_filename}'")
print(f"✅ Images saved in 'extracted_images' folder")
