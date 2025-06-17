import fitz
import os

# Ask the user to input the PDF file path
pdf_path = input("📄 Enter the full path and filename of the PDF to process: ").strip()

# Check if the file exists
if not os.path.isfile(pdf_path):
    print(f"❌ File not found: {pdf_path}")
    exit(1)

# Open the PDF document
doc = fitz.open(pdf_path)

# Create a directory for extracted images if it doesn't exist
if not os.path.exists("extracted_images"):
    os.makedirs("extracted_images")

total_lines = 0
image_counter = 0

# Define report filename based on the PDF name
pdf_name = os.path.splitext(os.path.basename(pdf_path))[0]
report_filename = f"{pdf_name}_full_report.txt"

# Open a text file to write the full report
with open(report_filename, "w", encoding="utf-8") as report:

    report.write("=== 📄 METADATA ===\n\n")
    for key, value in doc.metadata.items():
        report.write(f"{key}: {value}\n")
    report.write("\n")

    report.write(f"=== 📑 NUMBER OF PAGES ===\n\nTotal pages: {doc.page_count}\n\n")

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
        else:
            report.write("No images found on this page.\n")
        report.write("\n")

        # Extract links
        report.write("=== 🔗 LINKS ===\n\n")
        links = page.get_links()
        if links:
            for link in links:
                report.write(str(link) + "\n")
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

# Save the cleaned and optimized PDF
optimized_pdf_filename = f"{pdf_name}_extracted.pdf"
doc.save(optimized_pdf_filename, garbage=4, deflate=True)
doc.close()

print(
    f"✅ Full report saved as '{report_filename}' and images in the 'extracted_images' folder"
)
