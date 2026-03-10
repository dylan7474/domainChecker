import csv

ORIGINAL_FILE = 'domains.csv'
INPUT_FILE = 'results.csv'
OUTPUT_REPORT = 'live_domains_summary.csv'


def summarize_results():
    category_order = [
        "Tier 1: Verified Application (Definitively Live)",
        "Tier 1b: Browser Verified (DNS/IP Mismatch or WAF)",
        "Tier 2: SSL/TLS Protected (Definitively Live)",
        "Tier 3: Silent/Firewalled (Network Live)",
        "Tier 4: Inactive / Unreachable",
        "Other"
    ]
    category_rank = {name: index for index, name in enumerate(category_order)}

    all_original_domains = set()
    domain_categories = {}

    def normalize_domain(value):
        cleaned = value.strip().lower().rstrip('.')
        return cleaned.lstrip('*. -').replace('*', '')

    def pick_category(status):
        if "Verified" in status and "OPEN" in status:
            return "Tier 1: Verified Application (Definitively Live)"
        if "IP Mismatch/WAF" in status:
            return "Tier 1b: Browser Verified (DNS/IP Mismatch or WAF)"
        if "SSL-Error" in status:
            return "Tier 2: SSL/TLS Protected (Definitively Live)"
        if "Silent" in status:
            return "Tier 3: Silent/Firewalled (Network Live)"
        return "Other"

    # 1. Read the original domains list to know the baseline
    print(f"Reading {ORIGINAL_FILE} to determine baseline...")
    try:
        with open(ORIGINAL_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = normalize_domain((row.get('Domain') or row.get('Hostname') or ''))
                if domain:
                    all_original_domains.add(domain)
    except FileNotFoundError:
        print(f"Warning: {ORIGINAL_FILE} not found. Cannot determine inactive domains.\n")

    # 2. Read the results from the scan
    print(f"Reading {INPUT_FILE}...\n")
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                hostname = normalize_domain(row.get('Hostname', '').strip())
                status = row.get('Status', '').strip()

                if not hostname:
                    continue

                category = pick_category(status)
                existing = domain_categories.get(hostname)
                if existing is None or category_rank[category] < category_rank[existing]:
                    domain_categories[hostname] = category

        # 3. Calculate the completely inactive domains
        if all_original_domains:
            inactive = all_original_domains - set(domain_categories.keys())
            for domain in inactive:
                domain_categories[domain] = "Tier 4: Inactive / Unreachable"

        # 4. Write the report to a CSV file
        print(f"Writing results to {OUTPUT_REPORT}...")
        with open(OUTPUT_REPORT, 'w', encoding='utf-8', newline='') as out_f:
            writer = csv.writer(out_f)
            writer.writerow(['Domain', 'Category'])

            for domain in sorted(domain_categories):
                writer.writerow([domain, domain_categories[domain]])

        print(f"\nSuccess! Full summary CSV saved to: {OUTPUT_REPORT}")

    except FileNotFoundError:
        print(f"Error: Could not find {INPUT_FILE}. Make sure the scanner has finished running.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    summarize_results()
