import json
import logging
import sys
from flask import Flask, request, jsonify
from google.cloud import secretmanager, storage
import gnupg

# Configure logging
logging.basicConfig(level=logging.INFO)

decryprtion_over_cloud_run = Flask(__name__)
storage_client = storage.Client()
gpg = gnupg.GPG()

# Function to fetch secret from Google Cloud Secret Manager
def fetch_secret(secret_id):
    client = secretmanager.SecretManagerServiceClient()
    name = f"{secret_id}/versions/latest"
    try:
        response = client.access_secret_version({"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception as e:
        logging.error(f"Failed to fetch secret: {name} - {e}")
        return None

# Function to read configuration file from Google Cloud Storage
def fetch_conf_details(bucket_name, conf_file_name):
    logging.info(f"Reading config file from GCS: {conf_file_name}")
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(conf_file_name)
        return blob.download_as_text()
    except Exception as e:
        logging.error(f"Failed to read config file: {conf_file_name} - {e}")
        return None

# Endpoint for decryption
@decryprtion_over_cloud_run.route("/decryption", methods=['GET'])
def decrypt():
    conf_path = request.args.get('conf_path')
    if not conf_path:
        logging.error("Missing 'conf_path' parameter in request.")
        return jsonify({"error": "Missing 'conf_path' parameter"}), 400

    try:
        bucket_name = conf_path.split("/")[2]
        conf_file_name = conf_path.split(bucket_name)[-1].lstrip('/')
        conf_details = fetch_conf_details(bucket_name, conf_file_name)
        if conf_details is None:
            return jsonify({"error": "Failed to fetch configuration details"}), 500

        # Example of reading and using fetched config details
        config = json.loads(conf_details)
        gpg_passphrase = fetch_secret(config['gpg_passphrase'])
        if gpg_passphrase is None:
            return jsonify({"error": "Failed to fetch GPG passphrase"}), 500

        encrypted_file_path = config['gcs_file_path_encrypt'] + config['gpg_filename']
        bucket = storage_client.bucket(config['gcs_bucket'])
        blob = bucket.blob(encrypted_file_path)
        encrypted_data = blob.download_as_text()

        gpg.import_keys(config['gpg_private_key'])
        decrypted_data = gpg.decrypt(encrypted_data, passphrase=gpg_passphrase)

        if not decrypted_data.ok:
            logging.error(f"GPG decryption failed: {decrypted_data.stderr}")
            return jsonify({"error": "Decryption failed"}), 500

        decrypted_file_path = config['gcs_file_path_decrypt'] + config['standard_file_name'] + ".decrypted"
        decrypted_blob = bucket.blob(decrypted_file_path)
        decrypted_blob.upload_from_string(str(decrypted_data))

        logging.info("Decrypted file stored successfully in GCS.")
        return jsonify({"message": "File decrypted and stored successfully"}), 200

    except Exception as e:
        logging.error(f"Error during decryption process: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    decryprtion_over_cloud_run.run(host="0.0.0.0", port=8080)
