# Librairies
import boto3
import subprocess

def create_s3(name : str):
    """
        Abstract : Create a s3 bucket

        Input : 
        - name (str) : Desired name for s3 bucket

        Output : None
    """
    
    client = boto3.client('s3', region_name='us-east-1')
    
    # Create S3 bucket with default parameters
    client.create_bucket(Bucket=name)
    client.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )

def enable_bucket_encryption(name : str):
    """
        Abstract : Add encryption to bucket with AWS KMS key

        Input : 
        - name (str) : Name of target bucket

        Output : None
    """

    client = boto3.client('s3', region_name='us-east-1')
    
    # Add encryption to bucket with AWS KMS key
    client.put_bucket_encryption(
        Bucket=name,
        ServerSideEncryptionConfiguration={
        'Rules': [
                {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': "aws:kms",
                        "KMSMasterKeyID": "arn:aws:kms:us-east-1:107079351100:key/f5ae5842-83c1-4d5c-bf68-7a878fa55877"
                    }
                }
            ]
        }
    )

def enable_bucket_versioning(name : str):
    """
        Abstract : Enable bucket versioning

        Input : 
        - name (str) : Name of target bucket

        Output : None
    """

    client = boto3.client('s3', region_name='us-east-1')

    # Enable bucker versioning
    client.put_bucket_versioning(
        Bucket=name,
        VersioningConfiguration={
            'Status': 'Enabled'
        }
    )

def upload_sourcefile(name : str, folder_name : str, filename : str):
    """
        Abstract : Upload sourcefile in bucket

        Input : 
        - name (str) : Name of target bucket
        - folder_name (str) : Folder to create in bucket
        - filename (str) : Name of target file to upload

        Output : None
    """

    client = boto3.client('s3', region_name='us-east-1')

    # Upload sourcefile in bucket
    client.put_object(Bucket=name, Key=f"{folder_name}/")
    client.upload_file(filename, name, f"{folder_name}/sourcecode.py")

def scan(filename : str, create_filename : str):
    """
        Abstract : Scan a file and save results

        Input : 
        - filename (str) : Filename to scan
        - create_filename (str) : Filename to store results

        Output : None
    """

    scan_command = (f"bandit -r {filename}").split(" ") # Trivy cannot scan python object, so we use bandit instead
    output = subprocess.run(scan_command, capture_output=True, text=True, encoding='utf-8', errors='replace')

    with open(f"./{create_filename}", 'w') as file:
        file.write(output.stdout)


if __name__ == "__main__":
    s3_name = "s3-114-python"

    filename_on_s3 = "sourcecode"
    local_filename = "ex2.py"

    result_file_name = "scan_result.txt"
    
    print("[INFO] Connection to aws session")
    session = boto3.Session()

    print("[INFO] Create S3")
    create_s3(s3_name)

    print("[INFO] Enable encryption")
    enable_bucket_encryption(s3_name)

    print("[INFO] Enable versionning")
    enable_bucket_versioning(s3_name)

    print("[INFO] Upload sourcefile to bucket")
    upload_sourcefile(s3_name, filename_on_s3, local_filename)

    print("[INFO] Execute a scan on sourcecode")
    scan(local_filename, result_file_name)

    print("[INFO] End")


