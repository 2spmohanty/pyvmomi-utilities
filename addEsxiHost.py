__author__ = 'smrutim'

from optparse import OptionParser
import multiprocessing
import requests
import xml.etree.ElementTree as ElementTree
import time
import logging
from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect
import atexit
import getpass
import logging
import re
import ssl
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger("Add Hosts")
logger.setLevel(logging.DEBUG)
# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# create formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# add formatter to ch
ch.setFormatter(formatter)
# add ch to logger
logger.addHandler(ch)

options = None
si = None
invmap = {}
clustermap = {}
dcList = []
clusterList = []

def parseConfigFile(filename):
    eTree = ElementTree.parse(filename)
    clustermap = {}
    vc = eTree.find("vc")
    VC_Userid = vc.attrib['username']
    VC_Password = vc.attrib['password']
    VC_IP = vc.attrib['name']
    root = eTree.getroot()
    for e in root:
        for dataCenter in e.findall('datacenter'):
            dcList.append(dataCenter.attrib['name'])
            invmap[dataCenter.attrib['name']] = clustermap
            for cluster in dataCenter.findall('cluster'):
                clustermap[cluster.attrib['name']] = cluster.find('iplist').text
                clusterList.append(cluster.attrib['name'])
            clustermap = {}
    return(VC_IP, VC_Userid, VC_Password, clusterList)

def defineOptions():
    parser = OptionParser()
    parser.add_option("--configfile", help = "The XML config file to use")
    (options, args) = parser.parse_args()
    return options

def Login(host, user, pwd, port=443):
    context = ssl._create_unverified_context()
    si = SmartConnect(host=host,user=user,pwd=pwd,port=port,sslContext=context)
    atexit.register(Disconnect, si)
    return si

def CreateCluster(datacenter=None,clusterName=None):
    if datacenter == None:
        logger.error("You have to specify datacenter object")
    elif not (isinstance(datacenter, vim.Datacenter)):
        logger.error(str(datacenter) + " is not a datacenter object")
    else:
        logger.info("datacenter name: " + datacenter.name)

    if clusterName is None:
        logger.error("Missing value for cluster.")
    if datacenter is None:
        logger.error("Missing value for datacenter.")

    if len(clusterName.strip()) == 0:
        logger.error("Cannot create cluster with empty String name")

    cluster = ""
    try:
        clusterSpec = vim.cluster.ConfigSpecEx()
        host_folder = datacenter.hostFolder
        cluster = host_folder.CreateClusterEx(name=clusterName, spec=clusterSpec)

    except vim.fault.DuplicateName:
        logger.warning("Cluster '%s' already exists, not creating" % clusterName)
    except Exception, e:
        logger.error("Unable to create a Cluster by Name : " + clusterName)
        raise
    logger.info("Cluster '%s' has been created" % clusterName)
    return cluster


def AddHost(user, pwd, dcList, ClusterList):
    for dc in dcList:

        for clus in ClusterList:
            if invmap.has_key(dc.name):
                if invmap[dc.name].has_key(clus):
                    logger.info("Creating cluster %s under datacenter %s" %(clus,dc.name))
                    cluster = CreateCluster(dc,clus)

                    ipList = invmap[dc.name][clus].split(',')
                    for ip in ipList:
                        ssltp = None
                        try:
                            dc.QueryConnectionInfo(ip, 443, user, pwd)
                        except vim.fault.NoHost:
                            logger.warning("Host %s not found." %str(ip))
                            continue
                        except vim.fault.SSLVerifyFault,svf:
                            logger.warning("AddHost: auto-accepting host %s SSL certificate" %str(ip))
                            ssltp = svf.thumbprint

                        cspec = vim.host.ConnectSpec(force = True,hostName = ip,userName = user,
                                                     password = pwd,sslThumbprint = ssltp)

                        try:
                            if cluster != None:
                                t = cluster.AddHost(cspec, True, None, None)
                            else:
                                t = dc.hostFolder.AddStandaloneHost(cspec, None, True, None)

                            logger.info("Add hostSystems is done.")

                        except vim.fault.DuplicateName, f:
                            logger.warning("Host %s already exists." %f.object.name)
                        except Exception, e:
                            logger.error("Host Addition failed due to "+str(e))
                            raise
                    time.sleep(15)

def main():
    global si
    clustermap = {}
    configfile = ""
    p_dcList = []
    dc_map  = {}
    opts = defineOptions()

    if not opts.configfile:
        configfile = ""
    else:
        configfile = opts.configfile

    if configfile != "":
        VC_IP, VC_Userid, VC_Password, ClusterList = parseConfigFile(configfile)

    si = Login(VC_IP, VC_Userid, VC_Password,port=443)

    rootFolder = si.content.rootFolder
    p_dcList = rootFolder.childEntity

    for dc in dcList:
        dc_map[dc] = 0

    for p_dc in p_dcList:
        for dc in dcList:
            if p_dc.name == dc:
                dc_map[dc] = 1

    for dc in dcList:
        if dc_map[dc] != 1 :
            rootFolder.CreateDatacenter(dc)
            logger.info("Datacenter "+dc+ " created")

    p_dcList = rootFolder.childEntity

    logger.info("Starting to Add Hosts.")

    AddHost("root","ca$hc0w", p_dcList, ClusterList)



# Start program
if __name__ == "__main__":
    main()

