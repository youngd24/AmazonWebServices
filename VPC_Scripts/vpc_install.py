#!/usr/bin/env python
###############################################################################
# 
# vpc_install.py
#
# Script to deploy and configure a Booth research VPC in AWS
#
###############################################################################
#
# What it does:
#
# - Connect to both the core and subsidiary VPC's
# - Prepare the CloudFormation template based on our YAML
###############################################################################
#
# TODO: Document more
#
###############################################################################


################################################################################
# Foreign imports, apply border tax as you see fit
################################################################################
import boto3
import getopt
import sys
import logging
import subprocess
from configparser import ConfigParser
from botocore.exceptions import ClientError


################################################################################
# Temporary, will get moved to an object/method soon
################################################################################
def NFSAccess():
    session = boto3.Session(profile_name=cfg.profile)
    ec2 = session.client('ec2')

    response = ec2.describe_vpcs()
    vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

    try:
        response = ec2.create_security_group(GroupName='NFS Access',
                                             Description='Intra-VPC NFS access to EFS',
                                             VpcId=vpc_id)
        security_group_id = response['GroupId']
        print('Security Group Created %s in vpc %s.' % (security_group_id, vpc_id))

        data = ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {'IpProtocol': 'tcp',
                'FromPort': 2049,
                'ToPort': 2049,
                'IpRanges': [{'CidrIp': '10.227.50.0/24'}]
                }
            ])
        print('Ingress Successfully Set %s' % data)

    except ClientError as e:
        print(e)


def processYAMLTemplate():

    # We MUST get the requested VPC inbound in cfg
    if not cfg.requested_vpc:
        logging.info("processYAMLTemplate(): Requested VPC not specified, exiting")
        sys.exit(2)

    # Read the file into an array called yIn
    with open(cfg.yamlcf) as f:
        yIn = f.read().splitlines()

    # Replace the XXX with the ID of the VPC
    yOut = [s.replace('XXX', cfg.requested_vpc) for s in yIn]

    # Write the new text out to a new yaml template
    outfile = "cf_vpc" + cfg.requested_vpc + ".yaml"
    cf_json = open(outfile, "w")
    for line in yOut:
        cf_json.write("%s\n" % line)
    cf_json.close()

    # Convert this new YAML to JSON and dump it to a file
    # yaml2json will strip YAML comments and YAML specific parts like ---
    # TODO: convert this to a native Python conversion method at some point so it doesn't require an OS piece
    command = "yaml2json " + outfile + " > cf_vpc" + cfg.requested_vpc + ".json"
    cmd = SystemCommand()
    cmd.runCommand(command)



###############################################################################
# CLASS NAME  : SystemCommand
# DESCRIPTION : Generic system command wrapper class
# TODO        :
###############################################################################
class SystemCommand(object):

    ###########################################################################
    # Class properties
    ###########################################################################
    command = None

    ###########################################################################
    # NAME        : runCommand
    # DESCRIPTION : Try to run a given command
    # ARGUMENT(S) : object(self)
    #             : scalar(command)
    # RETURN      : list(result)
    # TODO        : Add a return code from the process pipe
    # TODO        : Add the ability to accept arguments to the command
    ###########################################################################
    def runCommand(self, command):
        logging.info("SystemCommand::runCommand(): Entering")
        result = []

        try:
            logging.info("SystemCommand::runCommand(): Running command => %s", command)
            child = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)
            for line in child.stdout.readlines():
                result.append(line)

            # Return what *should* be a populated list here
            return(result)
        except:
            logging.info("error running command \'%s\', "
                         "exception (%s): %s", command, sys.exc_info()[0], sys.exc_info()[1])

            # Return what should be an empty list here, check len(result) in the caller
            # to check this.
            return(result)


    ###########################################################################
    # NAME        : Default constructor
    # DESCRIPTION : Default constructor
    # ARGUMENT(S) : object(self)
    # RETURN      : None
    # TODO        :
    ###########################################################################
    def __init__(self):
        logging.info("SystemCommand::init(): Entering")


###############################################################################
# CLASS NAME  :
# DESCRIPTION :
# TODO        :
###############################################################################
class VpcPeer(object):

    ###########################################################################
    # Class properties
    ###########################################################################
    peeringRequest      = None      # A request to establish a peer
    requestDirection    = None      # inbound or outbound
    awsAccountId        = None      # The AWS account on this peer
    vpcId               = None      # The ID of the VPC attached to


    ###########################################################################
    # NAME        :
    # DESCRIPTION :
    # ARGUMENT(S) :
    # RETURN      :
    # TODO        :
    ###########################################################################
    def createPeerLink(self):
        logging.info("VpcPeer::createPeerLink(): Entering")


    ###########################################################################
    # NAME        :
    # DESCRIPTION :
    # ARGUMENT(S) :
    # RETURN      :
    # TODO        :
    ###########################################################################
    def acceptPeerLink(self):
            logging.info("VpcPeer::acceptPeerLink(): Entering")

    ###########################################################################
    # NAME        : Default constructor
    # DESCRIPTION : Default constructor
    # ARGUMENT(S) : object(self)
    # RETURN      : None
    # TODO        :
    ###########################################################################
    def __init__(self):
        logging.info("VpcPeer::init(): Entering")


###############################################################################
# CLASS NAME  :
# DESCRIPTION :
# TODO        :
###############################################################################
class AWSKeyPair(object):

    ###########################################################################
    # Class properties
    ###########################################################################
    ec2client = None


    ###########################################################################
    # NAME        :
    # DESCRIPTION :
    # ARGUMENT(S) :
    # RETURN      :
    # TODO        :
    ###########################################################################
    def createKeyPair(self, awsKeyName):
        logging.info("AWSKeyPair::createKeyPair(): Entering")


    ###########################################################################
    # NAME        :
    # DESCRIPTION :
    # ARGUMENT(S) :
    # RETURN      :
    # TODO        :
    ###########################################################################
    def __init__(self, ec2client):
        logging.info("AWSKeyPair::init(): Entering")
        self.ec2client = ec2client


###############################################################################
# CLASS NAME  : Config
# DESCRIPTION : General configuration object
# TODO        :
###############################################################################
class Config(object):

    ###########################################################################
    # Class properties
    ###########################################################################
    verbose = None

    ###########################################################################
    # NAME        : Default constructor
    # DESCRIPTION : Default constructor
    # ARGUMENT(S) : object(self)
    # RETURN      : None
    # TODO        :
    ###########################################################################
    def __init__(self):
        logging.info("Config::init(): Entering")
        self.verbose = False


###############################################################################
# CLASS NAME  : EC2
# DESCRIPTION : An EC2 object that's a bit higher level than boto3's
# TODO        :
###############################################################################
class EC2(object):

    ###########################################################################
    # Class properties
    ###########################################################################
    profile                 = None    # The AWS credentials file profile
    awsaccountid            = None    # Numeric AWS account ID
    session                 = None    # Boto3 EC2 session
    client                  = None
    aws_access_key_id       = None    # AWS key used to authenticate
    aws_secret_access_key   = None    # AWS secret used to authenticate


    ###########################################################################
    # NAME        : getEC2Session
    # DESCRIPTION : Create a boto3 EC2 session based on a creds profile
    # ARGUMENT(S) : (object(self)
    # RETURN      : True|False
    # TODO        :
    ###########################################################################
    def getEC2Session(self):
        logging.info("EC2::getEC2Session(): Entering")
        self.session = boto3.Session(profile_name=self.profile)
        self.client = self.session.client('ec2')
        return self.client

    ###########################################################################
    # NAME        : describe_vpcs
    # DESCRIPTION : Wrapper around the boto3 describe_vpcs
    # ARGUMENT(S) : object(self)
    # RETURN      : string(response)
    # TODO        :
    ###########################################################################
    def describe_vpcs(self, *args, **kwargs):
        logging.info("EC2::describe_vpcs: Entering")

        #args -- tuple of anonymous arguments
        #kwargs -- dictionary of named arguments
        if kwargs.get('strName'):
            strName = kwargs.get('strName')
            logging.info("VPC::describe_vpcs(): Searching for VPC named \'%s\'", strName)
            response = self.client.describe_vpcs(
                Filters=[{'Name': 'tag:Name', 'Values': [strName]}]
            )
            return(response)
        else:
            logging.info("VPC::describe_vpcs(): No search name given, returning all VPC\'s ")
            response = self.client.describe_vpcs()
            return(response)


    ###########################################################################
    # NAME        : getAWSAccessInfo
    # DESCRIPTION : Retrieve the AWS config info from the credentials file
    #             : (~/.aws/credentials)
    # ARGUMENT(S) : object(self)
    # RETURN      : None
    # TODO        :
    ###########################################################################
    def getAWSCreds(self):
        logging.info("EC2::getAWSCreds(): Entering")

        # ConfigParser to use against the aws credentials file
        parser = ConfigParser()
        parser.read(cfg.awscredsfile)

        # Get the AWS key/secret associated with this cred profile
        self.aws_access_key_id = parser.get(self.profile, 'aws_access_key_id')
        self.aws_secret_access_key = parser.get(self.profile, 'aws_secret_access_key')
        parser = None

    ###########################################################################
    # NAME        : getAWSAccountID
    # DESCRIPTION : Find the AWS account ID (number) based on a key/secret
    # ARGUMENT(S) : object(self)
    # RETURN      : None
    # TODO        :
    ###########################################################################
    def getAWSAccountId(self):
        logging.info("EC2::getAWSAccountId(): Entering")
        sts = boto3.client(
            "sts",
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
        )
        user_arn = sts.get_caller_identity()["Arn"]
        self.awsaccountid =  user_arn.split(":")[4]
        logging.info("EC2::getAWSAccountId(): Got AWS account ID: %s", self.awsaccountid)
        sts = None

    ###########################################################################
    # NAME        : Default constructor
    # DESCRIPTION : Default constructor
    # ARGUMENT(S) : object(self)
    #             : credsprofile - AWS credentials profile (as in default)
    # RETURN      : None
    # TODO        :
    ###########################################################################
    def __init__(self, credsprofile):
        logging.info("EC2::init(): Entering")
        self.profile = credsprofile

        # Initialize the object based on this class
        try:
            # Get the AWS credentials from the aws config file
            self.getAWSCreds()

            # Get the numeric AWS account ID for this EC2 profile/session
            self.getAWSAccountId()

            # Get a Boto3 EC2 session
            self.client = self.getEC2Session()

        except ClientError as e:
            logging.info("EC2::init(): exception: %s", e)


###############################################################################
# CLASS NAME  : VPC
# DESCRIPTION : A VPC object that's a bit higher level than boto3's and works
#             : a bit differently
# TODO        :
###############################################################################
class VPC(object):

    ###########################################################################
    # Class properties
    ###########################################################################
    ec2client       = None      # The boto3 ec2 client we will use
    name            = None      # The name of the VPC as it appears in AWS
    vpcid           = None      # The ID of the VPC from AWS
    cidrBlock       = None      # The CIDR block on the VPC
    dhcpOptionsId   = None      # DHCP options on the VPC
    isDefault       = None      # Is it the default VPC for the account?
    state           = None      # State, active or inactive


    ###########################################################################
    # NAME        : get()
    # DESCRIPTION : Get the VPC data from AWS
    # ARGUMENT(S) : self
    #             : name: the text string of the VPC name
    # RETURN      : True|False
    # TODO        :
    ###########################################################################
    def get(self, strName):
        logging.info("VPC::get(): Entering")
        logging.info("VPC::get(): Looking for VPC named \'%s\'", strName)

        # Get the VPC response based on the name given
        response = self.ec2client.describe_vpcs(strName=strName)
        logging.info("VPC::get(): Got response: %s", response)

        # Parse it
        for vpc in response["Vpcs"]:
            self.vpcid          = vpc["VpcId"]
            self.cidrBlock      = vpc["CidrBlock"]
            self.dhcpOptionsId  = vpc["DhcpOptionsId"]
            self.state          = vpc["State"]
            self.isDefault      = vpc["IsDefault"]

        # Log it
        logging.debug("VPC::get(): vpcid         => %s", self.vpcid)
        logging.debug("VPC::get(): cidrBlock     => %s", self.cidrBlock)
        logging.debug("VPC::get(): dhcpOptionsId => %s", self.dhcpOptionsId)
        logging.debug("VPC::get(): state         => %s", self.state)
        logging.debug("VPC::get(): isDefault     => %s", self.isDefault)

        return(True)

    ###########################################################################
    # NAME        : Default constructor
    # DESCRIPTION : Default constructor
    # ARGUMENT(S) : self
    #             : ec2client: the client connection to use for this class
    # RETURN      : None
    # TODO        :
    ###########################################################################
    def __init__(self, ec2client):
        logging.info("VPC::init(): Entering")
        logging.info("VPC::init(): ec2client.profile %s", ec2client.profile)
        try:
            self.ec2client = ec2client
        except ClientError as e:
            logging.info("VPC::init(): exception: %s", e)



################################################################################
#
################################################################################
def usage():
    print(
    '''Usage:
       -i|--interactive      : Interactive mode
       -v|--verbose          : Verbose
       -r|--request_vpc <id> : The VPC you want to create, as in 16 or 50, etc
    ''')


################################################################################
# M m M a A a I i I n N n

################################################################################
if __name__ == "__main__":

    # Configure logging, default to INFO level
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=logging.INFO)

    # woo hoo!
    logging.info('main(): Startup...')

    ############################################################################
    # CONFIGURATION
    ############################################################################
    # Create our main configuration object and give it some values to use later
    cfg = Config()
    cfg.appConfigFile = "app.config"

    # Parsed command line option config defaults
    cfg.verbose         = False
    cfg.interactve      = False
    cfg.requested_vpc   = None

    # Parse the app config file
    configParser = ConfigParser()
    configParser.read(cfg.appConfigFile)

    # Get the configuration values from the file
    cfg.awscredsfile    = configParser.get('main','awsCredentialsFile')
    cfg.yamlcf          = configParser.get('main', 'yamlcf')
    cfg.RSAKey          = configParser.get('KeyPair','RSAKey')
    cfg.AWSKeyName      = configParser.get('KeyPair','AWSKeyName')

    # Some very debuggy output
    logging.info("main(): Using cfg.appConfigFile %s",  cfg.appConfigFile)
    logging.info("main(): Using cfg.awscredsfile %s",   cfg.awscredsfile)
    logging.info("main(): Using cfg.yamlcf %s",         cfg.yamlcf)
    logging.info("main(): Using cfg.RSAKey \'%s\'",     cfg.RSAKey)
    logging.info("main(): Using cfg.AWSKeyName \'%s\'", cfg.AWSKeyName)


    ############################################################################
    # COMMAND LINE ARGUMENTS
    ############################################################################
    # Parse command line args *after* parsing the config file so they take presedence
    try:
        opts, args = getopt.getopt(sys.argv[1:], "vir:p", ["verbose",
                                                           "interactive",
                                                           "request_vpc=",
                                                           "--process-yaml"]
                                   )
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    for o, a in opts:

        # verbose
        if o in  ("-v", "--verbose"):
            cfg.verbose = True
            logging.info("main(): Comamnd line option verbose requested")

        # interactive
        elif o in ("-i", "--interactive"):
            cfg.interactve = True
            logging.info("main(): Command line option interactive requested")

        # Request VPC (the one we will create/configure)
        elif o in ("-r", "--request_vpc"):
            cfg.requested_vpc = a
            logging.info("main(): Command line option request_vpc requested with value => %s", a)

        elif o in ("-p", "--process-yaml"):
            logging.info("main(): Processing YAML template to JSON for VPC")
            processYAMLTemplate()
            sys.exit(0)

        # All other options
        else:
            assert False, "unhandled option"


    if not cfg.requested_vpc:
        logging.info("main(): You MUST specify the request_vpc to create")
        usage()
        sys.exit(2)

    ############################################################################
    # REAL WORK
    ############################################################################

    # Create the necessary EC2 clients
    # Main "core" IT account
    try:
        coreEC2client = EC2('itaccount')
        logging.info("main(): coreEC2client:")
        logging.info("main(): => coreEC2client.profile: %s", coreEC2client.profile)
        logging.info("main(): => coreEC2client.session: %s", coreEC2client.session)
        logging.info("main(): => coreEC2client.aws_access_key_id: %s", coreEC2client.aws_access_key_id)
        logging.info("main(): => coreEC2client.aws_secret_access_key: %s", coreEC2client.aws_secret_access_key)
        logging.info("main(): => coreEC2client.awsaccountid: %s", coreEC2client.awsaccountid)
    except:
        logging.info("Error connecting to EC2 using profile %s, "
                     "exception (%s): %s", 'itaccount', sys.exc_info()[0], sys.exc_info()[1])
        sys.exit(2)


    # Our test account, this is an example of a faculty research account
    try:
        testEC2client = EC2("vpc" + cfg.requested_vpc)
        logging.info("main(): testEC2client:")
        logging.info("main(): => testEC2client.profile: %s", testEC2client.profile)
        logging.info("main(): => testEC2client.session: %s", testEC2client.session)
        logging.info("main(): => testEC2client.aws_access_key_id: %s", testEC2client.aws_access_key_id)
        logging.info("main(): => testEC2client.aws_secret_access_key: %s", testEC2client.aws_secret_access_key)
        logging.info("main(): => testEC2client.awsaccountid: %s", testEC2client.awsaccountid)
    except:
        logging.info("Error connecting to EC2 using profile %s, "
                 "exception (%s): %s", 'testaccount', sys.exc_info()[0], sys.exc_info()[1])
        sys.exit(2)

    # Get the core VPC object to work with
    # These are based on the Name tag in AWS and is text
    coreVPC = VPC(coreEC2client)
    coreVPC.get("Booth Core VPC")

    # Get the test VPC object to work with
    testVPC = VPC(testEC2client)
    testVPC.get("Research VPC " + cfg.requested_vpc)

    # Check to see if the research VPC has been configured already
    # if the tag BoothPostInstall is set to Completed then we're done and should exit
    ### TODD: implement this


    ###
    # Coonvert the YAML CloudFormation template to the "real" one ready to use
    # The intermediaty YAML produced will be named cf_vpcXX.yaml (XX=VPC ID)
    # The final JSON prodced will be named cf_vpcXX.json (XX=VPC ID)
    # It's this final file that will be uploaded to S3 for CloudFormation to act on
    ###
    processYAMLTemplate()


    ###
    # Upload that new json template to our core S3 config template bucket
    # CloudFormation will look there to deploy it from within the subsidiary account
    ###


    # Import our standard systems RSA (SSH) key into the account
    # This comes from the .pub file on disk somewhere
    # You should have the corresponding .pem file with it
    infile = open(cfg.RSAKey, "r")
    inkey = infile.readline()
    infile.close()
    cmd = SystemCommand()
    res = cmd.runCommand("aws ec2 --profile " + testEC2client.profile +
                         " import-key-pair --key-name " + cfg.AWSKeyName +
                         " --public-key-material \"" + inkey + "\"")
    if len(res) > 0:
        logging.info("main(): Got result => %s", res)
    else:
        logging.info("main(): Result from command was empty, something might have happened, check logs")