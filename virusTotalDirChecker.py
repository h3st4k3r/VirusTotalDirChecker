import hashlib
import requests
import sys
import os

def calculate_hash(file):
    sha256 = hashlib.sha256()
    try:
        with open(file, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except FileNotFoundError:
        print(f"[ERROR] File '{file}' not found.")
        return None

def search_in_virustotal(file_hash, api_key, file):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        creation_date = attributes.get("creation_date", "Unknown")
        original_name = attributes.get("meaningful_name", "Unknown")
        
        print(f"[VirusTotal] File: {file}")
        print(f"  - SHA256: {file_hash}")
        print(f"  - Original name: {original_name}")
        print(f"  - Creation date: {creation_date}")
        print(f"  - {malicious} malicious detections, {suspicious} suspicious out of {total} engines.")
    elif response.status_code == 404:
        print("[INFO] No matches found in VirusTotal.")
    else:
        print(f"[ERROR] Could not query VirusTotal. Code {response.status_code}")

def analyze_directory(directory, api_key):
    if not os.path.isdir(directory):
        print(f"[ERROR] The path '{directory}' is not a valid directory.")
        sys.exit(1)
    
    print(f"[INFO] Analyzing directory: {directory}")
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            print(f"[INFO] Analyzing file: {full_path}")
            file_hash = calculate_hash(full_path)
            if file_hash:
                search_in_virustotal(file_hash, api_key, full_path)

def main():
    if len(sys.argv) != 2:
        print("Usage: python virusTotalDirChecker.py <directory>")
        sys.exit(1)
    
    api_key = ""  # Your API KEY
    directory = sys.argv[1]
    analyze_directory(directory, api_key)

if __name__ == "__main__":
    main()
