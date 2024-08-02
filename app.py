import sys
import subprocess
import os
import hashlib
import json
import tempfile
import time
import requests
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
CORS(app)

# Constants
CACHE_FILE = 'cache.json'
# Replace with your actual API key
API_KEY = os.environ.get('API_SECRET')
VT_API_URL = "https://www.virustotal.com/api/v3/"
EXTRACTED_FILES_DIR = "extracted_files"
HASHES_FILE = "extracted-hashes.txt"
RESULTS_FILE = "vt_results.txt"

# Helper functions from the previous scripts


def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=4)


def calculate_hashes(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def extract_files(pcap_file, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    protocols = ['http', 'imf', 'smb', 'tftp', 'ftp-data']
    for protocol in protocols:
        tshark_cmd = [
            'tshark',
            '-r', pcap_file,
            '--export-objects', f'{protocol},{output_dir}'
        ]
        subprocess.run(tshark_cmd, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def analyze_files(output_dir):
    files_by_protocol = defaultdict(list)
    protocols = ['http', 'imf', 'smb', 'tftp', 'ftp-data']
    for filename in os.listdir(output_dir):
        file_path = os.path.join(output_dir, filename)
        if os.path.isfile(file_path):
            file_size = os.path.getsize(file_path) / (1024 * 1024)
            sha256_hash = calculate_hashes(file_path)
            protocol = 'unknown'
            for p in protocols:
                if p in filename.lower():
                    protocol = p
                    break
            files_by_protocol[protocol].append(
                (filename, file_size, sha256_hash))
    for protocol in files_by_protocol:
        files_by_protocol[protocol].sort(key=lambda x: x[1], reverse=True)
    return files_by_protocol


def scan_hash(session, hash_item):
    hash_value, filename = hash_item
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    response = session.get(
        f"{VT_API_URL}files/{hash_value}", headers=headers, timeout=(3.05, 27))
    return {'filename': filename, 'hash': hash_value, 'data': response.json().get('data')}


def upload_and_analyze_file(session, file_path, filename):
    headers = {"x-apikey": API_KEY}
    with open(file_path, 'rb') as file:
        files = {"file": (filename, file)}
        upload_response = session.post(
            f"{VT_API_URL}files", headers=headers, files=files)
    if upload_response.status_code != 200:
        return None
    analysis_id = upload_response.json()['data']['id']
    while True:
        analysis_response = session.get(
            f"{VT_API_URL}analyses/{analysis_id}", headers=headers)
        if analysis_response.status_code == 200:
            result = analysis_response.json()
            if result['data']['attributes']['status'] == 'completed':
                return result
        time.sleep(20)

# Flask routes


@app.route('/analyze', methods=['POST'])
def analyze_pcap_route():
    if 'pcap' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['pcap']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file:
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        file.save(temp_file.name)
        try:
            # Extract files
            extract_files(temp_file.name, EXTRACTED_FILES_DIR)

            # Analyze extracted files
            files_by_protocol = analyze_files(EXTRACTED_FILES_DIR)

            # Scan files with VirusTotal
            results = []
            with requests.Session() as session:
                with ThreadPoolExecutor(max_workers=10) as executor:
                    for protocol in files_by_protocol:
                        for filename, _, hash_value in files_by_protocol[protocol]:
                            results.append(executor.submit(
                                scan_hash, session, (hash_value, filename)))

            # Process results
            processed_results = []
            for future in results:
                result = future.result()
                if result['data']:
                    last_analysis_stats = result['data']['attributes'].get(
                        'last_analysis_stats', {})
                    malicious_count = last_analysis_stats.get('malicious', 0)
                    total_count = sum(last_analysis_stats.values())
                    processed_results.append({
                        'filename': result['filename'],
                        'hash': result['hash'],
                        'score': f"{malicious_count}/{total_count}",
                        'vt_link': f"https://www.virustotal.com/gui/file/{result['hash']}",
                        'is_malicious': malicious_count > 0
                    })
                else:
                    processed_results.append({
                        'filename': result['filename'],
                        'hash': result['hash'],
                        'status': 'unknown'
                    })

            return jsonify({
                'extracted_files': files_by_protocol,
                'vt_results': processed_results
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            temp_file.close()
            os.unlink(temp_file.name)
    return jsonify({"error": "Unknown error occurred"}), 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
else:
    # This will be used when the app is run with Gunicorn
    gunicorn_app = app