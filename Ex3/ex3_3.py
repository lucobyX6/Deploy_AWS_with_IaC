# Librairies
import boto3
import subprocess
import json

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

def enable_cloudtrail_s3(name : str, id_user : str):
    """
        Abstract : Scan a file and save results

        Input : 
        - name (str) : Name of target bucket
        - id_user (str) : id of CLI user

        Output : None
    """
    client_s3 = boto3.client('s3', region_name='us-east-1')
    client_cloudtrail = boto3.client('cloudtrail', region_name='us-east-1')

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{name}"
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{name}/AWSLogs/{id_user}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            }
        ]
    }
    policy_str = json.dumps(policy)
    client_s3.put_bucket_policy(Bucket=name, Policy=policy_str)

    # Create a trail for bucket
    client_cloudtrail.create_trail(  
        Name="cloudtrail-s3-python",  
        S3BucketName=name,  
        IsMultiRegionTrail=False,
        EnableLogFileValidation=False
    )

    client_cloudtrail.put_event_selectors(
        TrailName="cloudtrail-s3-python",
        EventSelectors=[
            {
                'ReadWriteType': 'WriteOnly',
                'IncludeManagementEvents': False,
                'DataResources': [
                    {
                        'Type': 'AWS::S3::Object',
                        'Values': [f"arn:aws:s3:::{name}/"]
                    }
                ]
            }
        ]
    )

    # Start record
    client_cloudtrail.start_logging(Name="cloudtrail-s3-python")

def enable_replication(name_source : str, name_dest : str):
    """
        Abstract : Scan a file and save results

        Input : 
        - name_source (str) : Name of source bucket
        - name_dest (str) : Name of destination bucket

        Output : None
    """
    
    client = boto3.client('s3', region_name='us-east-1')

    # Enable bucket replication
    client.put_bucket_replication(
            Bucket=name_source,
            ReplicationConfiguration={
                'Role': 'arn:aws:iam::107079351100:role/Labrole_tp4',
                'Rules': [
                    {
                        'Status': 'Enabled',
                        'Priority': 1,
                        'DeleteMarkerReplication': {'Status': 'Disabled'},
                        'Filter': {
                            'Prefix': ''
                        },
                        'Destination': {
                            'Bucket': f'arn:aws:s3:::{name_dest}',
                        },
                    },

                ],
            },
        )

if __name__ == "__main__":
    s3_name = "s3-114-python"
    s3_replicate_name = "s3-114-replicate-python"

    filename_on_s3 = "sourcecode"
    local_filename = "ex3_3.py"

    result_file_name = "scan_result.txt"

    id_cli_user = "107079351100"
    
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

    print("[INFO] Enable cloudtrail for S3 bucket")
    enable_cloudtrail_s3(s3_name, id_cli_user)

    print("[INFO] Execute a scan on sourcecode")
    scan(local_filename, result_file_name)

    print("[INFO] Create replication S3")
    create_s3(s3_replicate_name)

    print("[INFO] Enable encryption")
    enable_bucket_encryption(s3_replicate_name)

    print("[INFO] Enable versionning")
    enable_bucket_versioning(s3_replicate_name)

    print("[INFO] Enable replication")
    enable_replication(s3_name, s3_replicate_name)

    print("[INFO] End")