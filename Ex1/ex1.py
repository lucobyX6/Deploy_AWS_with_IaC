# Librairies
import boto3
import subprocess

def create_basic_vpc(name : str, cidr_block : str):
    """
        Abstract : Create the base VPC with CIDR

        Input : 
        - name (str) : Desired name for vpc
        - cidr_bloc (str) : Desired cidr for vpc

        Output :
        - vpc_id (str) : Aws id of vpc in us-east-1
    """

    client = boto3.client('ec2', region_name='us-east-1')

    # Create VPC
    output = client.create_vpc(
        CidrBlock=cidr_block,
        InstanceTenancy='default',
        AmazonProvidedIpv6CidrBlock=False
    )

    vpc_id = output['Vpc']['VpcId'] # Get VPC ID

    client.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": name}]) # Give a name to VPC
    
    return vpc_id # VPC identifier

def create_subnet(name :str, cidr_block : str, vpc_id : str, avaibility_zone : str):
    """
        Abstract : Create a subnet in VPC

        Input : 
        - name (str) : Desired name for subnet
        - cidr_bloc (str) : Desired cidr for subnet (need to be contains in cidr vpc)
        - vpc_id (str) : Id of vpc
        - avaibility_zone (str) : Link to this avaibility zone

        Output : 
        - output['Subnet']['SubnetId'] (str) : Id of subnet
    """

    client = boto3.client('ec2', region_name='us-east-1')
    
    # Create a subnet in $avaibility_zone
    output = client.create_subnet(
                VpcId=vpc_id,
                CidrBlock=cidr_block,
                AvailabilityZone=avaibility_zone,
                TagSpecifications=[
                    {
                        'ResourceType': 'subnet',
                        'Tags': [
                            {'Key': 'Name', 'Value': name}
                        ]
                    }
                ]
            )

    return output['Subnet']['SubnetId'] # Subnet identifier

def create_internet_gateway(vpc_id : str, subnet : list):
    """
        Abstract : Create an internet gateway for vpc and connect subnets

        Input : 
        - vpc_id (str) : Id of vpc
        - subnet (list) : List of subnet to link to internet gateway

        Output : None
    """
    
    client = boto3.client('ec2', region_name='us-east-1')

    # Create an internet gateway and atach it to vpc
    output = client.create_internet_gateway()
    internet_gateway_id = output['InternetGateway']['InternetGatewayId']
    client.attach_internet_gateway(InternetGatewayId=internet_gateway_id, VpcId=vpc_id)

    # Create route table and create routes to specify subnets
    output = client.create_route_table(VpcId=vpc_id)
    extern_table_id = output['RouteTable']['RouteTableId']

    client.create_route(
        RouteTableId=extern_table_id,
        DestinationCidrBlock='0.0.0.0/0',
        GatewayId=internet_gateway_id
    )

    for subnet_id in subnet:
        client.associate_route_table(
            RouteTableId=extern_table_id,
            SubnetId=subnet_id
        )

def enable_auto_public_ip(subnet_id : str):
    """
        Abstract : Create an internet gateway for vpc and connect subnets

        Input : 
        - subnet_id (str) : Enable in this subnet

        Output : None
    """

    client = boto3.client('ec2', region_name='us-east-1')

    # Enable auto public ip for $subnet_id 
    client.modify_subnet_attribute(
        SubnetId=subnet_id,
        MapPublicIpOnLaunch={'Value': True}
    )

def create_nat_gateway(vpc_id : str, subnet_id : str, subnet_id_private : str):
    """
        Abstract : Create a nat gateway

        Input : 
        - vpc_id (str) : Id of vpc
        - subnet_id (str) : Sunet source
        - subnet_id_private (str) : Subnet target

        Output : None
    """

    client = boto3.client('ec2', region_name='us-east-1')

    # Create a NAT for $subnet_id
    output = client.allocate_address(Domain='vpc')
    elastic_ip = output['AllocationId']
    
    output = client.create_nat_gateway(SubnetId=subnet_id, AllocationId=elastic_ip)
    nat_gateway_id = output['NatGateway']['NatGatewayId']

    # Wait until nat is avaible
    output = client.get_waiter('nat_gateway_available')
    output.wait(NatGatewayIds=[nat_gateway_id])

    # Associate public subnet and private subnet to nat
    output = client.create_route_table(VpcId=vpc_id)
    intern_route_id = output['RouteTable']['RouteTableId']

    client.create_route(
        RouteTableId=intern_route_id,
        DestinationCidrBlock='0.0.0.0/0',
        GatewayId=nat_gateway_id
    )

    client.associate_route_table(
        RouteTableId=intern_route_id,
        SubnetId=subnet_id_private
    )

def create_security_group(name : str, description : str, vpc_id : str):
    """
        Abstract : Create a security group

        Input : 
        - name (str) : Desired name for security group
        - description (str) : Desired description for security group
        - vpc_id (str) : Id of vpc

        Output :
        - security_group_id (str) : Security group identifier
    """
    client = boto3.client('ec2', region_name='us-east-1')
    
    # Create security group
    output = client.create_security_group(
        GroupName=name,
        Description=description,
        VpcId=vpc_id
    )

    security_group_id = output['GroupId'] # Security group identifier

    # Security group ingress rules
    client.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 53, 'ToPort': 53, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 1433, 'ToPort': 1433, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 5432, 'ToPort': 5432, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 3389, 'ToPort': 3389, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 1514, 'ToPort': 1514, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 9200, 'ToPort': 9300, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        ]
    )

    return security_group_id

def run_ec2_subnet(region : str, imageID : str, subnetID : str, name : str, security_group_id : str, kms_key : str):
    """
        Abstract : Create a EC2 with specific parameters

        Input : 
        - region (str) : Target region
        - imageID (str) : Desired image for EC2
        - subnetID (str) : Id of target subnet
        - name (str) : Desired name for EC2
        - security_group_id (str) : Id of security group to attach 

        Output :
        - security_group_id (str) : Security group identifier
    """

    ec2 = boto3.client('ec2', region_name=region)

    # Create EC2
    ec2.run_instances(
        BlockDeviceMappings=[
            {
                'Ebs': {
                    'DeleteOnTermination': True,
                    'VolumeSize': 80,
                    'VolumeType': 'gp3',
                    'KmsKeyId': kms_key,
                    'Encrypted': True,
                },
                'DeviceName': '/dev/xvda',
            }
        ],
        ImageId=imageID,
        InstanceType="t3.micro", 
        MaxCount=1,
        MinCount=1,
        Monitoring={
            'Enabled': True
        },
        SubnetId=subnetID,
        SecurityGroupIds=[security_group_id],
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {
                        'Key': 'Name',
                        'Value': name
                    },
                ]
            },
        ],
    )

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
    # Parameters
    vp_name = "vpc-114-python"
    vpc_cidr = "10.0.0.0/16"

    subnet_name = ["public_az1", "private_az1", "public_az2", "private_az2"]
    subnet_cidr = ["10.0.0.0/24", "10.0.128.0/24", "10.0.16.0/24", "10.0.144.0/24"]
    avaibility_zone = ["us-east-1a", "us-east-1a", "us-east-1b", "us-east-1b"]

    security_group_name = "vpc-114-security-group"
    security_group_description = "Security group allows SSH, HTTP, HTTPS, MSSQL, etc ..."

    ec2_region = "us-east-1"
    ec2_ami = "ami-0360c520857e3138f"
    ec2_name = ["tp4-linux-public-AZ1", "tp4-windows-private-AZ1", "tp4-linux-public-AZ2", "tp4-windows-private-AZ2"]
    ec2_key = "arn:aws:kms:us-east-1:107079351100:key/f5ae5842-83c1-4d5c-bf68-7a878fa55877"

    # Generation begin
    print("[INFO] Connection to aws session")
    session = boto3.Session()

    print("[INFO] Create VPC")
    vpc_id = create_basic_vpc(vp_name, vpc_cidr)
    print(f"VPC Id : {vpc_id}")
    
    print("[INFO] Create subnets")
    subnet = {}
    for i in range(len(subnet_name)):
        subnet[subnet_name[i]] = create_subnet(subnet_name[i], subnet_cidr[i], vpc_id, avaibility_zone[i])
    print(f"Subnets Id : {subnet}")

    print("[INFO] Create internet gateway")
    create_internet_gateway(vpc_id, [subnet[subnet_name[0]], subnet[subnet_name[2]]])

    print("[INFO] Create nat gateways")
    create_nat_gateway(vpc_id, subnet[subnet_name[0]], subnet[subnet_name[1]])
    create_nat_gateway(vpc_id, subnet[subnet_name[2]], subnet[subnet_name[3]])

    print("[INFO] Create security group")
    security_group_id = create_security_group(security_group_name, security_group_description, vpc_id)
    print(f"[INFO] Security group : {security_group_id}")

    print("[INFO] Enable automatic public IP")
    enable_auto_public_ip(subnet[subnet_name[0]])
    enable_auto_public_ip(subnet[subnet_name[2]])

    print("[INFO] Create EC2 in private and public subnets")
    for i in range(len(subnet_name)):
        run_ec2_subnet(ec2_region, ec2_ami, subnet[subnet_name[i]], ec2_name[i], security_group_id, ec2_key)

    print("[INFO] End")