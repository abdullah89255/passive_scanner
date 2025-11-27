# passive_scanner
Here’s a clear step‑by‑step guide to running the passive reconnaissance tool I shared with you:

---

## 🛠️ Setup

1. **Install Python 3**  
   Make sure you have Python 3.8+ installed. You can check with:
   ```bash
   python3 --version
   ```

2. **Install dependencies**  
   The script uses the `requests` library. Install it with:
   ```bash
   pip install requests
   ```

3. **Save the script**  
   Copy the full code I gave you into a file, for example:
   ```
   passive_scanner.py
   ```

---

## ▶️ Running the tool

Use the command line to run it against a target domain that is *in scope* for your bug bounty program:

```bash
python3 passive_scanner.py https://example.com
```

By default it will:
- Crawl up to **75 URLs** within the same domain
- Respect `robots.txt`
- Limit depth to **2 levels**
- Wait **0.75 seconds** between requests
- Save results into `report.json`

---

## ⚙️ Options

You can customize behavior with flags:

- `--max-urls N` → limit number of pages scanned  
  ```bash
  python3 passive_scanner.py https://example.com --max-urls 30
  ```

- `--max-depth N` → control crawl depth  
  ```bash
  python3 passive_scanner.py https://example.com --max-depth 1
  ```

- `--delay SECONDS` → set delay between requests  
  ```bash
  python3 passive_scanner.py https://example.com --delay 1.5
  ```

- `--output FILE` → choose output file name  
  ```bash
  python3 passive_scanner.py https://example.com --output example_report.json
  ```

---

## 📊 Understanding the output

The tool produces a JSON file with:

- **Summary**: number of pages scanned, total findings
- **Metadata findings**: e.g. presence of `security.txt`
- **Per‑page reports**:
  - URL, status code, final URL
  - Whether HTTPS was used
  - Headers and cookies observed
  - Findings (missing headers, weak CSP, cookie flags, mixed content, etc.)

You can open the JSON in any viewer or process it with Python/Excel for analysis.

---

## ✅ Best practices

- Only run against domains explicitly listed in your bug bounty scope.
- Keep crawl limits modest to avoid overwhelming servers.
- Use the findings as **signals** to investigate further manually.  
  For example, missing CSP → check for XSS risk; weak cookies → check session handling.

---

