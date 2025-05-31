import requests
import time
import csv
import os

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

def import_ips(file_path="ip.txt"):
    """Read IP addresses from a text file, one per line."""
    try:
        with open(file_path, "r") as file:
            ips = [line.strip() for line in file if line.strip()]
        return ips
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return []

def get_ip_info(ip):
    """Query VirusTotal for info about an IP."""
    headers = {
        "x-apikey": API_KEY
    }
    url = VT_URL.format(ip)
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            malicious = attributes.get("last_analysis_stats", {}).get("malicious", 0)
            country = attributes.get("country", "Unknown")
            return ip, malicious, country
        else:
            print(f"Error {response.status_code} for IP {ip}: {response.text}")
            return ip, 0, "Unknown"
    except Exception as e:
        print(f"Exception for IP {ip}: {e}")
        return ip, 0, "Unknown"

def write_to_csv(results, filename):
    """Write the list of malicious IPs to a CSV file."""
    if not results:
        print("✅ No malicious IPs to write.")
        return

    with open(filename, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Country", "Malicious Score"])
        writer.writerows(results)

    abs_path = os.path.abspath(filename)
    print(f"📄 Results written to: {abs_path}")

# ----------------------------
# Main execution
# ----------------------------
if __name__ == "__main__":
    output_filename = "malicious_ips.csv"
    ips = import_ips()
    print("Imported IPs:", ips)

    results = []
    for ip in ips:
        ip, malicious, country = get_ip_info(ip)
        print(f"{ip} | Malicious: {malicious} | Country: {country}")
        if malicious > 0:
            results.append((ip, country, malicious))
        time.sleep(15)  # Rate limit

    write_to_csv(results, output_filename)
