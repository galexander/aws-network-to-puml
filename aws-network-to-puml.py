import os
import json
import logging
import boto3
from argparse import ArgumentParser, HelpFormatter, BooleanOptionalAction
from botocore.exceptions import ClientError
from mergedeep import merge
import hashlib


# logger config
logger = logging.getLogger()
logging.basicConfig(level=logging.INFO,
                    format='%(message)s')

# Argument parser config
formatter = lambda prog: HelpFormatter(prog, max_help_position=52)
parser = ArgumentParser(formatter_class=formatter)
parser.add_argument("-v", "--vpc",
                    type=str, action='append', default=[], help="vpcs to include")
parser.add_argument("-r", "--region",
                    default = "ap-southeast-1", help="region to query")
parser.add_argument("-a", "--account",
                    type=str, action='append')
parser.add_argument("-o", "--output-file",
                    dest='outfile',
                    default=None, help="puml file to create")
parser.add_argument('-c', "--cache",
                    action=BooleanOptionalAction, help='enable caching, must be used with "-o"')
parser.add_argument("-p"  "--puml-render",
                    dest='render', type=str, action='append', default=[],
                    help="vpc-elements, connectivity")

global_args = parser.parse_args()
global_aws_client_cache = dict()
global_session = boto3.Session()
global_sts_client = global_session.client('sts', region_name=global_args.region)

def get_aws_client(service:str, region:str, account_id:str, role=None):
    global global_aws_client_cache
    global global_session
    if region is None or account_id is None:
        logger.error('region and account is required for get_aws_client')
        exit(-1)

    if (account_id in global_aws_client_cache and 
        region     in global_aws_client_cache[account_id] and
        service    in global_aws_client_cache[account_id][region]):
            return global_aws_client_cache[account_id][region][service]
    
    client_session = None
    if role is not None:
        sts = global_session.client(sts, region)
        response = sts.assume_role(
            RoleArn=f'arn:aws:iam::{account_id}/{role}',
            RoleSessionName='aws-network-to-puml'
        )
        client_session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                                       aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                                       aws_session_token=response['Credentials']['SessionToken'])
    else:
        client_session = global_session


    global_aws_client_cache[account_id] = dict()
    global_aws_client_cache[account_id][region] = dict()
    global_aws_client_cache[account_id][region][service] = client_session.client(service, region_name=region)

    return global_aws_client_cache[account_id][region][service]


def asg_in_vpc(vpc_id:str, asg:str, client_ctx:dict):
    subnets_list = asg['VPCZoneIdentifier'].split(',')
    vpc_client = get_aws_client('ec2', **client_ctx)
    for subnet in subnets_list:
        try:
            sub_description = vpc_client.describe_subnets(SubnetIds=[subnet])['Subnets']
            if sub_description[0]['VpcId'] == vpc_id:
                logger.info("{} resides in {}".format(asg['AutoScalingGroupName'], vpc_id))
                return True
        except ClientError:
            pass

    return False

def get_asgs(vpc_id:str, client_ctx:dict):
    asg_client = get_aws_client('autoscaling', **client_ctx)
    logger.debug("asgs in vpc {}:".format(vpc_id))
    asgs = asg_client.describe_auto_scaling_groups()['AutoScalingGroups']
    asgs = []
    for asg in asgs:
        asg_name = asg['AutoScalingGroupName']
        if asg_in_vpc(vpc_id, asg, client_ctx):
            asgs.append(asg)
            logger.debug(asg_name)
    
    return asgs

def get_peerings(vpc_id:str, client_ctx:dict):
    logger.debug("vpc peering in vpc({})".format(vpc_id))
    ec2_client = get_aws_client('ec2',**client_ctx)
    response = ec2_client.describe_vpc_peering_connections()

    peerings = []
    for connection in response['VpcPeeringConnections']:
        accepter_vpc = connection['AccepterVpcInfo']
        requester_vpc = connection['RequesterVpcInfo']

        if accepter_vpc['VpcId'] == vpc_id or requester_vpc['VpcId'] == vpc_id:
            peerings.append(connection)
            logging.debug("{},{},{},{},{}".format(
                connection['VpcPeeringConnectionId'],
                accepter_vpc['OwnerId'],
                accepter_vpc['VpcId'],
                requester_vpc['OwnerId'],
                requester_vpc['VpcId']))

    return peerings

def get_ekss(vpc_id:str, client_ctx:dict):
    eks_client = get_aws_client('eks',**client_ctx)
    
    clusters = eks_client.list_clusters()['clusters']

    logger.debug("ekss in vpc({})".format(vpc_id))
    ekss = []
    for eks in clusters:
        eks_desc = eks_client.describe_cluster(name=eks)['cluster']
        if eks_desc['resourcesVpcConfig']['vpcId'] == vpc_id:
            ekss.append(eks)
            logger.debug(eks_desc['name'])

    return ekss

def get_ec2s(vpc_id:str, client_ctx:dict):
    vpc_client = get_aws_client('ec2',**client_ctx)
    reservations = vpc_client.describe_instances(Filters=[{"Name": "vpc-id",
                                                           "Values": [vpc_id]}])['Reservations']
    instances = [ec2['InstanceId'] for reservation in reservations for ec2 in reservation['Instances']]

    logger.debug(f'ec2s in vpc ({vpc_id} {instances})')
    return instances

def get_lambdas(vpc_id:str, client_ctx:dict):
    lambda_client = get_aws_client('lambda', **client_ctx)
    lmbds = lambda_client.list_functions()['Functions']

    lambda_list = [lmbd['FunctionName'] for lmbd in lmbds 
                    if 'VpcConfig' in lmbd and lmbd['VpcConfig']['VpcId'] == vpc_id]

    logger.debug(f'lambdas in vpc({vpc_id} {lambda_list}')
    return lambda_list

def get_rdss(vpc_id:str, client_ctx:dict):
    rds_client = get_aws_client('rds', **client_ctx)

    instances = rds_client.describe_db_instances()['DBInstances']

    rds_list = [rds['DBInstanceIdentifier'] for rds in instances if rds['DBSubnetGroup']['VpcId'] == vpc_id]

    logger.debug(f'rdss in vpc({vpc_id}) {rds_list}')
    return rds_list

def get_elbs(vpc_id:str, client_ctx:dict):
    elb_client = get_aws_client('elb', **client_ctx)
    elb_descriptions = elb_client.describe_load_balancers()['LoadBalancerDescriptions']

    elb_list = [elb['LoadBalancerName'] for elb in elb_descriptions if elb['VPCId'] == vpc_id]

    logger.debug(f'classic elbs in vpc({vpc_id}) {elb_list}')
    return elb_list

def get_elbV2s(vpc_id:str, client_ctx:dict):
    elbV2_client = get_aws_client('elbv2', **client_ctx)
    elbv2_descriptions = elbV2_client.describe_load_balancers()['LoadBalancers']

    elbv2_list = [elb['LoadBalancerArn'] for elb in elbv2_descriptions if elb['VpcId'] == vpc_id]
    logger.debug(f'elbv2s in vpc({vpc_id}) {elbv2_list}')
    return elbv2_list

def get_natgws(vpc_id:str, client_ctx:dict):
    vpc_client = get_aws_client('ec2', **client_ctx)
    nats = vpc_client.describe_nat_gateways(Filters=[{"Name": "vpc-id",
                                                      "Values": [vpc_id]}])['NatGateways']

    nat_list = [nat['NatGatewayId'] for nat in nats]
    logger.debug(f'natgws in vpc({vpc_id}) {nat_list}')
    return nat_list

def get_enis(vpc_id:str, client_ctx:dict):
    vpc_client = get_aws_client('ec2', **client_ctx)
    eni_list = vpc_client.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])['NetworkInterfaces']

    eni_id_list = [eni['NetworkInterfaceId'] for eni in eni_list]
    logger.debug(f'enis in vpc({vpc_id}) {eni_id_list}')
    return eni_id_list

def get_igws(vpc_id:str, client_ctx:dict):
    vpc_client = get_aws_client('ec2', **client_ctx)
    igw_list = vpc_client.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id",
                  "Values": [vpc_id]}])['InternetGateways']

    igw_id_list = [igw['InternetGatewayId'] for igw in igw_list]
    logger.debug(f'igws in vpc({vpc_id}) {igw_list}')
    return igw_id_list

def get_vpgws(vpc_id:str, client_ctx:dict):
    vpc_client = get_aws_client('ec2', **client_ctx)
    vpgw_list = vpc_client.describe_vpn_gateways(
        Filters=[{"Name": "attachment.vpc-id",
                  "Values": [vpc_id]}])['VpnGateways']

    vpgw_id_list = [vpgw['VpnGatewayId'] for vpgw in vpgw_list]
    logger.debug(f'vpgws in vpc({vpc_id}) {vpgw_id_list}')
    return vpgw_id_list

def get_subnets(vpc_id:str, client_ctx:dict):
    vpc_client = get_aws_client('ec2', **client_ctx)
    subnet_list = vpc_client.describe_subnets(Filters=[{"Name": "vpc-id",
                                                    "Values": [vpc_id]}])['Subnets']

    subnet_id_list = [subnet['SubnetId'] for subnet in subnet_list]

    logger.debug(f'subnets in vpc({vpc_id}) {subnet_id_list}')
    return subnet_id_list

def get_nacls(vpc_id:str, client_ctx:dict):
    vpc_client = get_aws_client('ec2', **client_ctx)
    nacl_list = vpc_client.describe_network_acls(Filters=[{"Name": "vpc-id",
                                                      "Values": [vpc_id]}])['NetworkAcls']

    nacl_id_list = [acl['NetworkAclId'] for acl in nacl_list]
    logger.debug(f'acls in vpc({vpc_id}) {nacl_id_list}')
    return nacl_id_list

def get_sgs(vpc_id:str, client_ctx:dict):
    vpc_client = get_aws_client('ec2', **client_ctx)
    sg_list = vpc_client.describe_security_groups(Filters=[{"Name": "vpc-id",
                                                        "Values": [vpc_id]}])['SecurityGroups']
    sg_id_list = [sg['GroupId'] for sg in sg_list]

    logger.debug(f'security groups in vpc({vpc_id}) {sg_id_list}')
    return sg_id_list

def get_rtbs(vpc_id:str, client_ctx:dict):
    vpc_client = get_aws_client('ec2', **client_ctx)
    rtb_list = vpc_client.describe_route_tables(Filters=[{"Name": "vpc-id",
                                                      "Values": [vpc_id]}])['RouteTables']

    rtb_id_list = [rtb['RouteTableId'] for rtb in rtb_list]
    logger.debug(f'Routing tables in vpc({vpc_id}) {rtb_id_list}')
    return rtb_id_list


def get_vpces(vpc_id:str, client_ctx:dict):
    vpc_client = get_aws_client('ec2', **client_ctx)

    vpce_list  = vpc_client.describe_vpc_endpoints(Filters=[{"Name": "vpc-id",
                                                       "Values": [vpc_id]}])['VpcEndpoints']

    vpce_id_list  = [ept['VpcEndpointId'] for ept in vpce_list]
    logger.debug(f'VPC EndPoints in vpc({vpc_id}) {vpce_id_list}')
    return vpce_id_list

def get_tag(tags:list, key):
    if tags is None or len(tags) == 0:
        return None
    for tag in tags:
        if tag['Key'].lower() == key.lower():
            return tag['Value']
        
    return None

def get_vpcs(client_ctx:dict, vpc_filter:list=None):
    vpc_client = get_aws_client('ec2', **client_ctx)

    vpc_list = []
    if vpc_filter is not None:
        vpc_list = (vpc_client.describe_vpcs(VpcIds=vpc_filter))['Vpcs']
    else:
        vpc_list = (vpc_client.describe_vpcs())['Vpcs']

    vpc_id_name_list = [{'id': vpc['VpcId'], 'name': get_tag(vpc['Tags'], 'Name'), 'cidr': vpc['CidrBlock'] }
                            for vpc in vpc_list]

    return vpc_id_name_list

def get_client_ctx(account_conf, region):
    client_ctx = {'account_id': account_conf['id'],
                  'region': region}
    if 'role' in account_conf:
        client_ctx['role'] = account_conf['role']

    return client_ctx

def get_account_region_vpc_topology(account_conf:dict, region:str, vpc:dict):
    client_ctx = get_client_ctx(account_conf, region)
    vpc_id   = vpc['id']
    vpc_name = vpc['name']  if vpc['name'] is not None else "<unknown>"
    vpc_cidr = vpc['cidr']
    account_region_vpc_topology = { 
        'id':      vpc_id,
        'name':    vpc_name,
        'cidr':    vpc_cidr,
        'asg':     get_asgs(vpc_id, client_ctx),
        'peering': get_peerings(vpc_id, client_ctx),
        'eks':     get_ekss(vpc_id, client_ctx),
        'ec2':     get_ec2s(vpc_id, client_ctx),
        'lambda':  get_lambdas(vpc_id, client_ctx),
        'rds':     get_rdss(vpc_id, client_ctx),
        'elb':     get_elbs(vpc_id, client_ctx),
        'elbv2':   get_elbV2s(vpc_id, client_ctx),
        'natgw':   get_natgws(vpc_id, client_ctx),
        'eni':     get_enis(vpc_id, client_ctx),
        'igw':     get_igws(vpc_id, client_ctx),
        'vpgw':    get_vpgws(vpc_id, client_ctx),
        'subnet':  get_subnets(vpc_id, client_ctx),
        'nacl':    get_nacls(vpc_id, client_ctx),
        'sg':      get_sgs(vpc_id, client_ctx),
        'rtb':     get_rtbs(vpc_id, client_ctx),
        'vpce':    get_vpces(vpc_id, client_ctx)
    }

    return account_region_vpc_topology

def get_account_region_topology(account_conf:dict, region:str):
    client_ctx = get_client_ctx(account_conf, region)
    vpcs = get_vpcs(client_ctx, account_conf['vpcs'])
    account_region_topology = dict()
    for vpc in vpcs:
        account_region_topology[vpc['id']] = get_account_region_vpc_topology(account_conf, region, vpc)

    return account_region_topology

def get_account_topology(account_conf:dict):
    account_topology = dict()
    for region in account_conf['regions']:
        account_topology[region] = get_account_region_topology(account_conf, region)

    return account_topology

def get_topology(conf:dict):

    cache_file_name = f"{conf['cache_key']}.cache.json"
    if 'cache' in conf and conf['cache']:
        with open(cache_file_name) as f:
            return json.load(f)

    topology = dict()

    for account in conf['accounts'].values():
        topology[account['id']] = get_account_topology(account)

    with open(cache_file_name, 'w') as f:
        json.dump(topology, f)

    return topology

def add_vpc_to_toplogy(topology, account_id, region, vpc_id, vpc_cidr, vpc_name="<unknown>"):
    topology[account_id] = { region: { vpc_id: { 'id': vpc_id, 'cidr': vpc_cidr, 'name': vpc_name}}}

def in_toplogy(topology, account_id, region, vpc_id):
    if (account_id in topology and
        region in topology[account_id] and
        vpc_id in topology[account_id][region]):
        return True
    
    return False

def expand_topology_by_vpc_peering(topology, account_id, region, vpc_id):
    vpc = topology[account_id][region][vpc_id]
    new_topologies = dict()
    if 'peering' not in vpc or len(vpc['peering']) == 0:
        return new_topologies

    for connection in vpc['peering']:
        accepter = connection['AccepterVpcInfo']
        if not in_toplogy(topology,
                          accepter['OwnerId'],
                          accepter['Region'],
                          accepter['VpcId']):

            add_vpc_to_toplogy(new_topologies,
                               accepter['OwnerId'],
                               accepter['Region'],
                               accepter['VpcId'],
                               accepter['CidrBlock'])

        requester = connection['RequesterVpcInfo']
        if not in_toplogy(topology,
                          requester['OwnerId'],
                          requester['Region'],
                          requester['VpcId']):

            add_vpc_to_toplogy(new_topologies,
                               requester['OwnerId'],
                               requester['Region'],
                               requester['VpcId'],
                               requester['CidrBlock'])

    return new_topologies

def expand_topology(topology:dict):

    new_topologies = dict()
    for account_id in topology:
        for region in topology[account_id]:
            for vpc_id in topology[account_id][region]:
                merge(new_topologies, expand_topology_by_vpc_peering(topology, account_id, region, vpc_id))

    return merge(topology, new_topologies)

def _puml_alias(string:str):
    return string.replace('-','_')

def render_vpc_element(vpc:dict, type:str, puml_element:str):
    if type not in vpc:
        return ""
    count = len(vpc[type])
    id    = f'{_puml_alias(vpc["id"])}_{type}'

    return f'{puml_element}({id}, "{type} x{count}", "")'


def render_vpc(vpc:dict, conf:dict):
    if 'vpc-elements' in conf['render']:
        return f'''\n\t\tVPCGroup({_puml_alias(vpc['id'])},"{vpc['id']} ({vpc['name']}) \\n {vpc['cidr']}") {{
            \t\t\t{render_vpc_element(vpc, 'igw',     'VPCInternetGateway' )}
            \t\t\t{render_vpc_element(vpc, 'natgw',   'VPCNATGateway')}
            \t\t\t{render_vpc_element(vpc, 'peering', 'VPCPeeringConnection' )}
            \t\t\t{render_vpc_element(vpc, 'ec2',     'EC2' )}
            \t\t\t{render_vpc_element(vpc, 'eks',     'ElasticKubernetesService' )}
            \t\t\t{render_vpc_element(vpc, 'lambda',  'Lambda' )}
            \t\t\t{render_vpc_element(vpc, 'rds',     'RDS' )}
            \t\t\t{render_vpc_element(vpc, 'elb',     'ElasticLoadBalancingClassicLoadBalancer' )}
            \t\t\t{render_vpc_element(vpc, 'elbv2',   'ElasticLoadBalancing' )}
            \t\t\t{render_vpc_element(vpc, 'eni',     'VPCElasticNetworkInterface' )}
            \t\t\t{render_vpc_element(vpc, 'vpce',    'VPCEndpoints' )}
            \t\t\t{render_vpc_element(vpc, 'vpgw',    'VPCVPNGateway')}
            \t\t\t{render_vpc_element(vpc, 'nacl',    'VPCNetworkAccessControlList')}
\t\t}}
'''
            # TODO: evaluate if these are useful and how to render them
            #'subnet':  get_subnets(vpc_id, client_ctx),
            #'sg':      get_sgs(vpc_id, client_ctx),
            #'rtb':     get_rtbs(vpc_id, client_ctx),
    else:
        return f'''\n\t\tVPCGroup({_puml_alias(vpc['id'])},"{vpc['id']} ({vpc['name']}) \\n {vpc['cidr']}") {{
        
\t\t}}
'''

def render_region_vpcs(region:dict, conf:dict):
    puml = ""
    for vpc_id in region:
        puml += render_vpc(region[vpc_id], conf)

    return puml


def render_account_region(account_id:str, region_name:str, region, conf:dict):
    account_puml = f'''\n\tRegionGroup({_puml_alias(account_id + "-" + region_name)},"{region_name}") {{
        {render_region_vpcs(region, conf)}
\t}}
'''
    return account_puml 

def render_account_regions(account_id:str, account:dict, conf:dict):
    puml = ""
    for region_name in account:
        puml += render_account_region(account_id, region_name, account[region_name], conf)

    return puml

def render_account(account_id:str, account:dict, conf:dict):
    account_puml = f'''\nAWSCloudGroup(account_{account_id},"{account_id}") {{
        {render_account_regions(account_id, account, conf)}
}}
'''
    return account_puml 

def render_topology(topology:dict, conf:dict):
    puml = ""
    for account_id in topology:
        puml += render_account(account_id, topology[account_id], conf)

    return puml

def render_vpc_connectivity(vpc:dict, seen_connections:dict):
    puml = ""

    if 'peering' not in vpc:
        return puml

    # peering connectivity
    for connection in vpc['peering']:
        if connection['VpcPeeringConnectionId'] not in seen_connections:
            puml += f'{_puml_alias(connection["RequesterVpcInfo"]["VpcId"])}'
            puml += " -u-> "
            puml += f'{_puml_alias(connection["AccepterVpcInfo"]["VpcId"])}'
            puml += "\n"

    return puml

def render_region_connectivity(region_topology:dict, seen_connections:dict):
    puml = ""
    for vpc_id in region_topology:
        vpc = region_topology[vpc_id]
        puml += render_vpc_connectivity(vpc, seen_connections)

    return puml

def render_account_connectivity(account_topology:dict, seen_connections:dict):
    puml = ""
    for region_name in account_topology:
        puml += render_region_connectivity(account_topology[region_name], seen_connections)

    return puml

def render_topology_connectivity(topology:dict):
    seen_connections = dict()
    puml = ""
    for account_id in topology:
        puml += render_account_connectivity(topology[account_id], seen_connections)

    return puml

def render_layout(topology:dict, conf:dict):
    puml = ""
    current_account_id = conf['current_account_id']
    accounts = sorted(topology.keys())
    for account_id in accounts:
        if account_id != current_account_id:
            puml += f"account_{account_id} .u[hidden].> account_{current_account_id}\n"

    return puml

        
def render_puml(topology:dict, conf:dict):
    puml = f"""@startuml {(conf['outfile'].replace('.puml','') if 'outfile' in conf else "topology")}
'Uncomment the line below for "dark mode" styling
'!$AWS_DARK = true

!define AWSPuml aws-icons-for-plantuml/dist
!include AWSPuml/AWSCommon.puml
!include AWSPuml/AWSSimplified.puml
!include AWSPuml/Compute/EC2.puml
!include AWSPuml/Compute/EC2Instance.puml
!include AWSPuml/Compute/Lambda.puml
!include AWSPuml/Containers/ElasticKubernetesService.puml
!include AWSPuml/Database/RDS.puml
!include AWSPuml/Groups/AWSCloud.puml
!include AWSPuml/Groups/Region.puml
!include AWSPuml/Groups/VPC.puml
!include AWSPuml/Groups/AvailabilityZone.puml
!include AWSPuml/Groups/PublicSubnet.puml
!include AWSPuml/Groups/PrivateSubnet.puml
!include AWSPuml/NetworkingContentDelivery/VPCNATGateway.puml
!include AWSPuml/NetworkingContentDelivery/VPCInternetGateway.puml
!include AWSPuml/NetworkingContentDelivery/VPCPeeringConnection.puml
!include AWSPuml/NetworkingContentDelivery/ElasticLoadBalancingClassicLoadBalancer.puml
!include AWSPuml/NetworkingContentDelivery/ElasticLoadBalancing.puml
!include AWSPuml/NetworkingContentDelivery/VPCElasticNetworkInterface.puml
!include AWSPuml/NetworkingContentDelivery/VPCInternetGateway.puml
!include AWSPuml/NetworkingContentDelivery/VPCEndpoints.puml
!include AWSPuml/NetworkingContentDelivery/VPCVPNGateway.puml
!include AWSPuml/NetworkingContentDelivery/VPCNetworkAccessControlList.puml

hide stereotype
'skinparam linetype ortho 
skinparam wrapWidth 300
{render_topology(topology, conf)}

{render_topology_connectivity(topology) if 'connectivity' in conf['render'] else ""}

{render_layout(topology, conf)}
@enduml
"""
    return puml


def configure():
    conf = {}
    current_account_id = (global_sts_client.get_caller_identity())['Account']
    default_region = global_args.region
    
    accounts:dict = dict()

    '''
    This needs to be re-worked to support account -> region -> vpc nesting as well as 'NOT' operations.
    E.g. !account or !vpc.
    This will impact cache key generation (probably easier to find something cache build a md5 sum given a dict)
    '''
    for account in (global_args.account if global_args.account is not None else []):
        account_details = dict()
        for kv in account.split(','):
            k,v = kv.split('=')
            if k not in ['id','alias','role','vpcs','regions']:
                logger.error(f'unknown account configuration key {k}')
                exit(-1)
            if v in ['vpcs','regions']:
                account_details[k] = [v.split(';')]
            else:
                account_details[k]=v

        if 'id' not in account_details:
            logger.error(f'id not specified for account {account_details}',)
            exit(-1)
        
        # ensure regions are set
        if ('regions' not in account_details or
                account_details['region'] is None or
                len(account_details['region']) == 0):

            conf['regions'] = [default_region]


        # ensure vpcs are set
        if ('vpcs' not in account_details or
                account_details['vpcs'] is None):

            conf['vpcs'] = []

        accounts[account_details['id']] = account_details

    if current_account_id not in accounts:
        accounts[current_account_id] = { 
            'id' : current_account_id,
            'vpcs'       : global_args.vpc,
            'regions'    : [global_args.region]
        }


    conf['accounts']           = accounts
    conf['outfile']            = global_args.outfile
    conf['cache']              = global_args.cache
    conf['current_account_id'] = current_account_id

    if global_args.render is None or len(global_args.render) == 0:
        conf['render'] = [ 'vpc-elements' ]
    else:
        conf['render'] = global_args.render

    md5 = hashlib.md5()
    for account_id in (sorted(accounts.keys())):
        for region in (sorted(accounts[account_id]['regions'])):
            for vpc in (sorted(accounts[account_id]['vpcs'])):
                md5.update(f'{account}{region}{vpc}')

    conf['cache_key'] = f'{current_account_id}.{md5.hexdigest()}'

    print(conf)

    return conf


if __name__ == '__main__':

    conf = configure()

    outfile = conf['outfile'] if 'outfile' in conf else None

    if outfile is not None:
        if os.path.isfile(outfile):
            confirm = input(f'file {outfile} exists. Overwrite? [Y/y] ')
            if confirm.lower() not in ('y', 'yes'):
                logger.warning("not overwrting - exiting")
                exit(-1)

    topology = expand_topology(get_topology(conf))

    puml = render_puml(topology, conf)

    if outfile is None:
        print(puml)
    else:
        with open(conf['outfile'], "w") as file:
            file.write(puml)