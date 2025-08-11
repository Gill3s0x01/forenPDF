<h1 align="center">ForenPDF</h1>

<p align="center">
  <img src="./assets/forenPDF.png" alt="ForenPDF Logo" width="250"/>
</p>

## PDF Forensic Data Extractor

Uma ferramenta Python para coleta forense de metadados, conteúdo de texto, imagens, links e informações estruturadas de arquivos PDF, com geração de hashes de integridade e informações do sistema de arquivos.


## 📑 Sumário

- [PDF Forensic Data Extractor](#pdf-forensic-data-extractor)
- [📑 Sumário](#-sumário)
- [📌 Descrição](#-descrição)
- [📦 Dependências](#-dependências)
  - [Instalação](#instalação)
- [🛠️ Como Usar](#️-como-usar)
- [📋 Relatório Gerado](#-relatório-gerado)
- [📁 Estrutura de Saída](#-estrutura-de-saída)
- [📊 Exemplo de Uso](#-exemplo-de-uso)
- [⚠️ Avisos e Boas Práticas](#️-avisos-e-boas-práticas)
- [📚 Referências Técnicas](#-referências-técnicas)
- [📖 Licença](#-licença)
- [👨‍💻 Autor](#-autor)

## 📌 Descrição

O **ForenPDF** realiza extração forense detalhada de informações de arquivos PDF para uso em investigações digitais e perícia, incluindo:

- **file_size** — tamanho do arquivo em bytes.
- **created_time / modified_time** — datas de criação e modificação do arquivo no sistema.
- **hashes** — MD5, SHA1, SHA256 para validação de integridade.
- **pdf_version** — versão do PDF extraída do cabeçalho.
- **pages** — lista com URLs, IPs e e-mails extraídos por página.
- **images** — informações das imagens extraídas (com hashes e OCR opcional).
- **links** — links identificados no texto e anotações.
- **suspicious** — referências a objetos suspeitos (JavaScript, arquivos embutidos).
- **extracted_files** — lista de arquivos embutidos extraídos.

---

## 📦 Dependências

- Python 3.8+
- [PyMuPDF (fitz)](https://pypi.org/project/PyMuPDF/)
- [Pillow](https://pypi.org/project/Pillow/) (opcional, para OCR)
- [pytesseract](https://pypi.org/project/pytesseract/) (opcional, para OCR)
- Bibliotecas nativas:
  - `hashlib`
  - `datetime`
  - `os`
  - `re`
  - `json`
  - `argparse`
  - `logging`

### Instalação

```bash
pip install PyMuPDF Pillow pytesseract
```

## 🛠️ Como Usar

Execute o script pelo terminal ou CMD:

```bash
python forenpdf.py arquivo.pdf --out ./saida
```

Parâmetros principais:

| Parâmetro            | Descrição |
|----------------------|-----------|
| `pdf`                | Caminho do PDF a analisar |
| `--out`              | Pasta base para saída (opcional) |
| `--no-ocr`           | Desativa OCR mesmo se disponível |
| `--max-xref`         | Máximo de objetos XREF a inspecionar (padrão: 200) |
| `--no-embedded`      | Não extrai arquivos embutidos |
| `--quiet`            | Reduz a verbosidade do log |

---

## 📋 Relatório Gerado

O relatório JSON (`*_manifest.json`) gerado inclui:

```json
{
  "file_size": 123456,
  "created_time": "2025-08-11 14:35:21",
  "modified_time": "2025-08-11 14:35:21",
  "hashes": {
    "MD5": "...",
    "SHA1": "...",
    "SHA256": "..."
  },
  "pdf_version": "1.7",
  "pages": [
    {
      "page_number": 1,
      "urls": ["https://exemplo.com"],
      "ips": ["192.168.0.1"],
      "emails": ["contato@exemplo.com"]
    }
  ],
  "images": [
    {
      "page": 1,
      "file": "extracted_images/p1_xref12.png",
      "hash": "sha256...",
      "size": 54321,
      "xref": 12,
      "ocr_snippet": "Texto OCR..."
    }
  ],
  "links": ["https://exemplo.com/link"],
  "suspicious": {
    "javascript_xrefs": [5, 20],
    "embeddedfile_xrefs": [33]
  },
  "extracted_files": ["embedded_files/planilha.xls"]
}
```

---

## 📁 Estrutura de Saída

```
.
├── evidence_1691768483/
│   ├── original.pdf
│   ├── extracted_images/
│   │   ├── p1_xref12.png
│   │   └── ...
│   ├── embedded_files/
│   │   ├── arquivo_embutido.docx
│   └── reports/
│       ├── original_report.txt
│       └── original_manifest.json
```

---

## 📊 Exemplo de Uso

```bash
python forenpdf.py "F:/Investigacao/Amostra.pdf" --out "./caso_amostra"
```

Saída esperada:

```
✅ Evidência copiada para ./caso_amostra/original.pdf
✅ Manifest salvo em ./caso_amostra/reports/original_manifest.json
✅ Relatório TXT salvo em ./caso_amostra/reports/original_report.txt
✅ Imagens extraídas em ./caso_amostra/extracted_images
```

---

## ⚠️ Avisos e Boas Práticas

- Sempre gere e registre hashes antes e depois de manipular arquivos.
- Mantenha uma cópia imutável do arquivo original.
- Use ambiente controlado para processamento de PDFs potencialmente maliciosos.
- O OCR pode extrair texto sensível; revise antes de compartilhar.
- A extração de arquivos embutidos pode conter malware; analise com segurança.

---

## 📚 Referências Técnicas

- [PDF Reference, Sixth Edition (Adobe Systems)](https://opensource.adobe.com/dc-acrobat-sdk-docs/)
- [PyMuPDF Documentation](https://pymupdf.readthedocs.io/)
- Digital Forensics Principles (Carrier, 2019)

---

## 📖 Licença

MIT License. Uso livre para fins acadêmicos, profissionais e periciais.

## 👨‍💻 Autor

**Gilles**
Perito Digital | OSINT & Security Developer Specialist
GitHub: [@Gill3s0x01](https://github.com/Gill3s0x01)
