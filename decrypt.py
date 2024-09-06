import json
import logging
import sys
import io
from flask import Flask, request, jsonify
from distutils.log import INFO
from google.cloud import secretmanager
from google.cloud import storage
import gnupg
import datetime

logging.basicConfig(level=INFO)
decryprtion_over_cloud_run = Flask(__name__)

storage_client = storage.Client()
gpg = gnupg.GPG()

#Function To Read Secret Details From  SM
def fetch_secret(id):
    client = secretmanager.SecretManagerServiceClient()
    id = {"name": f"{id}/versions/latest"}
    try:
        response = client.access_secret_version(id)
    except Exception as e:
        logging.error("Failed to Get SM for key : "+str(id))
        sys.exit(1)
    return response.payload.data.decode("UTF-8")
   
#Function to read config file and return dict
def fetch_conf_details(bucket_name, conf_file_name):
    logging.info("Reading conf file from GCS : "+str(conf_file_name))
    bucket = storage_client.get_bucket(bucket_name)
    try:
        blob = bucket.blob(conf_file_name)
        with blob.open("r") as file:
            file_content =  file.read()
    except Exception as e:
        logging.error("Failed to read config File : "+str(conf_file_name))
        logging.error(e)
        sys.exit(1)
    return file_content


#gs://pg_procedure_py/scripts/config_file.json
#End Point For Loading Delimieted File
@decryprtion_over_cloud_run.route("/decryption" , methods = ['GET'])    
def decrypt():

    try:
        conf_path = request.args.get('conf_path')
        logging.info(" Reading Config File From Path : "+str(conf_path))    
        bucket_name = str(conf_path).split("/")[2]
        conf_file_path = str(conf_path).split(bucket_name)[-1] #
    except Exception as e:
        logging.error("Invalid Request... : "+str(e))
        sys.exit(1)    
   
    #Removing first / from path
    conf_file_name= conf_file_path.replace("/","", 1)
   
    #Read Config File Details
    try:
        conf_details = fetch_conf_details(bucket_name, conf_file_name)
        conf_dict = json.loads(conf_details)
    except Exception as e:
        logging.error("Failed reading the conf file : "+str(e))
        sys.exit(1)

    try:    
        gpg_private_key = conf_dict.get('gpg_private_key')
        gpg_passphrase = conf_dict.get('gpg_passphrase')
        gpg_filename = conf_dict.get('gpg_filename')
        gcs_file_path_encrypt = conf_dict.get('gcs_file_path_encrypt')
        gcs_file_path_decrypt = conf_dict.get('gcs_file_path_decrypt')
        gcs_bucket = conf_dict.get('gcs_bucket')
        
    except Exception as e:
        logging.error("Failed reading the conf file : "+str(e))
        sys.exit(1)

    #Reading configuration and SSl from SM
    try:
        gpg_private_key=fetch_secret(gpg_private_key)
        #gpg_filename=fetch_secret(gpg_filename)
        #gcs_file_path_encrypt=fetch_secret(gcs_file_path_encrypt)
        #gcs_file_path_decrypt=fetch_secret(gcs_file_path_decrypt)
        #gcs_bucket=fetch_secret(gcs_bucket)
        gpg_passphrase = fetch_secret(gpg_passphrase)

    except Exception as e:
        logging.error('Error occured reading from secret manager : '+str(e))
        sys.exit(1)

    encrypted_file_path = gcs_file_path_encrypt + gpg_filename

    try:
        logging.info("########################################)
        logging.info("#######Decryption process started#######)
        logging.info("########################################)
        bucket = storage_client.bucket(gcs_bucket)
        blob = bucket.blob(encrypted_file_path)
        encrypted_data = blob.download_as_text()
        gpg.import_keys(gpg_private_key)
        decypted_data = gpg.decrypt(encrypted_data, passphrase=gpg_passphrase)
        logging.info("########################################)
        logging.info("##########Decryption Completed##########)
        logging.info("########################################)
    except Exception as e:
        logging.error("Failed to decrypt")
        logging.error(e)
        return str(e)
        
    decrypted_file_path = gcs_file_path_decrypt + standard_file_name +".decrypted"
       
    #Export the updated data to csv.
    try:
        bucket = storage_client.get_bucket(gcs_bucket)
        blob = bucket.blob(decrypted_file_path)
        bytes_io = str(decypted_data).encode(encoding='UTF-8')
        blob.upload_from_string(bytes_io)
        logging.info("Decrypted file stored to GCS bucket successfully!!!!!!")        
    except (Exception, psycopg2.DatabaseError) as e:
        logging.error("Failed exporting data to GCS bucket")
        logging.error(e)
        return error

    return "success, File was Decrypted and successfully stored in GCS"
   
   

if __name__ == "__main__":
    decryprtion_over_cloud_run.run(host="0.0.0.0", port=8080)

