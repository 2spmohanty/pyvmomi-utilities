__author__ = 'smrutim'
import argparse
import getpass
from DatacenterOps import Login, GetAllStandAloneHostsnCluster,GetAllDatacenter
from CustomLogger import generate_logger


def get_args():
    """
    Supports the command-line arguments listed below.
    """

    parser = argparse.ArgumentParser(description="Get DC, Clusters, Hosts and VM in JSON.")
    parser.add_argument('-H', '--host', nargs=1, required=True, help='The vCenter to connect to',
                        dest='host', type=str)
    parser.add_argument('-p', '--password', nargs=1, required=False,
                        help='The password with which to connect to the VC. If not specified, the user is prompted at runtime for a password',
                        dest='password', type=str)
    parser.add_argument('-u', '--user', nargs=1, required=True, help='The username with which to connect to the host',
                        dest='username', type=str)
    args = parser.parse_args()
    return args






inventory_map="""
{DC : {
    DC_NAME : %[DC_NAME]s,
    STANDALONE_HOST : %[HOST_ARRAY]s,
    CLUSTER:
    [  {
             CLUSTER_NAME : %(CLUSTERNAME)s,
             HOST         : [
               {
               HOST_NAME : %(HOSTNAME)s,
               VM_ARRAY : %(VM_ARRAY)s
               }
             
             ]    
        
        }
    ]

}

"""


final_json = """
{
 "datacenters" : [
 
                    %(ALL_DC_INFO)s
 
 ]   
   
}

"""

dc_json = """
    {
    
     "dcname"          :  "%(DC_NAME)s",
     "clusters"        : [
     
                         %(ALL_CLUSTERS)s
     
     
     ],
     
     "standalonehosts" : [
     
                         %(ALL_STANDALONE_HOSTS)s
     
     ]
     
     
    }

"""

cluster_json = """
{
   "clustername"        :   "%(CLUSTER_NAME)s" ,
   "clusterhosts"       :   [
                                %(ALL_HOSTS)s
   ]
}

"""

host_json = """
{
 "hostname"     :   "%(HOST_NAME)s",
 "connection"   :   "%(CONNECTION_STATE)s",
 "datastores"   :   %(DS)s,
 "network"      :   %(NW)s,
 "maintenance"  :   "%(MAINTAIN)s",
 "cpu"          :   %(CPU)s, 
 "mem"          :   %(MEM)s,
 "hostvms"      :   [
                        %(ALL_VMs)s
 ]
}
"""

vm_json = """
{
   "vmname" : "%(VM_NAME)s",
   "power"  : "%(POWER_STATE)s"
}
"""

standalone_host_json = """

   %(ALL_HOST)s


"""


test_json = """
[
    %(TEST_DATA)s
]
"""

def getInv(datacenters,logger):
    if datacenters is None:
        pass
    else:
        final_json_output = ""
        dc_json_final = ""
        for dc in datacenters:
            dcName = dc.name
            logger.info ("Getting Objects for " + dcName)
            allStandAloneHost, allClusterObjList = GetAllStandAloneHostsnCluster(dc)
            # Add Null test for Hosts & Cluster

            standalone_host = ""


            if allStandAloneHost:

                for h in allStandAloneHost:
                    hosts = h.host
                    host_json_final = ""

                    for esx in hosts:
                        #print (" ---------- STANDALONE HOST ----------- " + esx.name)
                        host_connection_state = esx.runtime.connectionState
                        host_maintenance = esx.runtime.inMaintenanceMode
                        host_resource_cpu = esx.summary.quickStats.overallCpuUsage
                        host_resource_mem = esx.summary.quickStats.overallMemoryUsage
                        host_datastores = [dsmor.name for dsmor in esx.datastore ]
                        host_network = [nmor.name for nmor in esx.network]
                        host_name = esx.name
                        vms = esx.vm
                        vm_json_final = ""
                        for vmitem in vms:
                            #print ("----------- VM ----------- " + vmitem.name)
                            vm_name = vmitem.name
                            power_state = vmitem.runtime.powerState
                            vm_json_final = vm_json_final + "," + vm_json%{'VM_NAME': vm_name, 'POWER_STATE' : power_state }
                            vm_json_final = vm_json_final.strip(',')
                        host_json_final = host_json_final + "," + host_json%{'HOST_NAME' : host_name, 'ALL_VMs' : vm_json_final,
                                                                             'CONNECTION_STATE' : host_connection_state, 'MAINTAIN' : host_maintenance ,
                                                                             'CPU' : host_resource_cpu, 'MEM' : host_resource_mem , 'DS' : host_datastores, 'NW' : host_network   }
                        host_json_final = host_json_final.strip(',').replace("'",'"')

                    standalone_host = standalone_host + "," + host_json_final


            cluster_json_final = ""

            for cluster in allClusterObjList:
                host_json_final = ""
                #print ("----------- CLUSTER -------- " + cluster.name)
                hostsincluster = cluster.host
                for host in hostsincluster:
                    #print ("-----------HOST IN CLUSTER----------- " + host.name)
                    host_name = host.name
                    host_connection_state = host.runtime.connectionState
                    host_maintenance = host.runtime.inMaintenanceMode
                    host_resource_cpu = host.summary.quickStats.overallCpuUsage
                    host_resource_mem = host.summary.quickStats.overallMemoryUsage
                    host_datastores = [dsmor.name for dsmor in host.datastore]
                    host_network = [nmor.name for nmor in host.network]
                    vmsinhost = host.vm
                    vm_json_final = ""
                    for vmitem in vmsinhost:
                        #print ("----------- VM ----------- " + vmitem.name)
                        vm_name = vmitem.name
                        power_state = vmitem.runtime.powerState
                        vm_json_final = vm_json_final + "," + vm_json % {'VM_NAME': vm_name, 'POWER_STATE' : power_state}
                        vm_json_final = vm_json_final.strip(',')
                    host_json_final = host_json_final + "," + host_json%{'HOST_NAME' : host_name, 'ALL_VMs' : vm_json_final,
                                                                             'CONNECTION_STATE' : host_connection_state, 'MAINTAIN' : host_maintenance ,
                                                                             'CPU' : host_resource_cpu, 'MEM' : host_resource_mem, 'DS' : host_datastores, 'NW' : host_network  }

                cluster_json_final = cluster_json_final + "," + cluster_json % {'CLUSTER_NAME' : cluster.name , 'ALL_HOSTS' : host_json_final.strip(',').replace("'",'"')}
            #print (str(test_json%{'TEST_DATA':cluster_json_final.strip(',')}))

            dc_json_final = dc_json_final + "," + dc_json % {'DC_NAME' : dcName,
                                                             'ALL_CLUSTERS' : str(test_json%{'TEST_DATA':cluster_json_final.strip(',')}) ,
                                                             'ALL_STANDALONE_HOSTS' : str(test_json%{'TEST_DATA':standalone_host.strip(',')}) }

        final_json_output = final_json% { 'ALL_DC_INFO' : dc_json_final.strip(',') }

        print ("################# INVENTORY MAP JSON ##################")

        print (str(final_json_output))



def main():
    args = get_args()

    host = args.host[0]

    password = None
    if args.password:
        password = args.password[0]

    username = args.username[0]

    logger = generate_logger()

    # Getting user password
    if password is None:
        logger.debug('No command line password received, requesting password from user')
        password = getpass.getpass(prompt='Enter password for vCenter %s for user %s: ' % (host, username))

    try:
        logger.info("Connecting to VC "+host)
        si = Login(host, username, password, port=443)
        logger.info("Connected to VC. Getting Inventory Objects.")
        datacenters = GetAllDatacenter(si)
        getInv(datacenters,logger)
    except Exception as e:
        logger.info("Caught Exception while running program "+str(e))






# Start program
if __name__ == "__main__":
    main()



