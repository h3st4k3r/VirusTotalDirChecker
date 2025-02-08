# VirusTotal Directory Checker

## Description

`virusTotalDirChecker.py` is a Python script that scans all files in a given directory, calculates their SHA256 hash, and checks for matches in [VirusTotal](https://www.virustotal.com). If a match is found, the script retrieves useful information such as the number of detections, the original file name, and the creation date.

<img width="541" alt="image" src="https://github.com/user-attachments/assets/fb1e87e3-62a4-4e85-99e5-c8aba4c07897" />

## Requirements

- Python 3.x
- `requests` library
- A valid VirusTotal API key

## Installation

1. Clone or download this repository.
2. Install the required dependencies:
   ```bash
   pip install requests
   ```
3. Obtain an API key from [VirusTotal](https://www.virustotal.com/gui/my-apikey).

## Usage

Run the script with the following command:
```bash
python virusTotalDirChecker.py <directory>
```
Replace `<directory>` with the absolute or relative path to the directory you want to scan.

### Example
```bash
python virusTotalDirChecker.py /home/user/documents
```

## Features
- Computes the SHA256 hash of each file in a directory.
- Queries VirusTotal to check if the hash has been reported before.
- Displays relevant information including:
  - Number of malicious and suspicious detections.
  - Original file name (if available).
  - Creation date of the file.

## Notes
- If a file is not found in VirusTotal, it will not be reported.
- The script requires an active internet connection.
- Be mindful of the API rate limits imposed by VirusTotal.

## License
This project is licensed under the MIT License. Feel free to use and modify it as needed.

## Author
Developed by h3st4k3r
