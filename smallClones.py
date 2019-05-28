__author__ = 'smrutim'
import argparse
import atexit
import getpass
import logging
import re
import ssl
import datetime
from time import sleep
from pyVim.connect import SmartConnect, Disconnect,SmartStubAdapter,VimSessionOrientedStub
import pyVmomi
from pyVmomi import vim, vmodl
from multiprocessing.dummy import Pool as ThreadPool

def get_args():
    """
    Supports the command-line arguments listed below.
    """

    parser = argparse.ArgumentParser(description="Deploy a template into multiple VM's. You can get information returned with the name of the virtual machine created and it's main ip address IPv4 format. You can specify which folder and/or resource pool the clone should be placed in. Verbose and debug output can is send to stdout aswell as saved to a log file. And it can all be done in a number of parallel threads you specify. ).")
    parser.add_argument('-b', '--basename', nargs=1, required=False, help='Basename of the newly deployed VMs',
                        dest='basename', type=str)
    parser.add_argument('-z', '--domain', nargs=1, required=False, help='Domain of the newly deployed VMs For e.g: eng.vmware.com',
                        dest='domain', type=str)
    parser.add_argument('-c', '--count', nargs=1, required=False, help='Starting count, the name of the first VM deployed will be <basename>-<count>, the second will be <basename>-<count+1> (default = 1)', dest='count', type=int, default=[1])
    parser.add_argument('-d', '--debug', required=False, help='Enable debug output', dest='debug', action='store_true')
    parser.add_argument('--datacenter', nargs=1, required=False, help='The datacenter in which the new VMs should reside (default = same datacenter as source virtual machine', dest='datacenter', type=str)
    parser.add_argument('--cluster', required=False,
                        help='The cluster which should not be used.Pass values delimited with a comma(,)',dest='cluster', type=str)
    parser.add_argument('--datastore', required=False, help='The datastore list in which the new VMs should reside '
                                                            '(default = same datastore as source virtual machine).Pass values delimited with a comma(,)', dest='datastore', type=str)
    parser.add_argument('--folder', nargs=1, required=False,
                        help='The folder in which the new VMs should reside'
                             ' (default = same folder as source virtual machine)', dest='folder', type=str)
    parser.add_argument('-H', '--host', nargs=1, required=True, help='The vCenter or ESXi host to connect to', dest='host', type=str)
    parser.add_argument('-i', '--print-ips', required=False, help='Enable IP output', dest='ips', action='store_true')
    parser.add_argument('-l', '--log-file', nargs=1, required=False, help='File to log to (default = stdout)', dest='logfile', type=str)
    parser.add_argument('-n', '--number', nargs=1, required=False, help='Amount of VMs to deploy (default = 1)', dest='amount', type=int, default=[1])
    parser.add_argument('-o', '--port', nargs=1, required=False, help='Server port to connect to (default = 443)', dest='port', type=int, default=[443])
    parser.add_argument('-p', '--password', nargs=1, required=False, help='The password with which to connect to the host. If not specified, the user is prompted at runtime for a password', dest='password', type=str)
    parser.add_argument('-P', '--disable-power-on', required=False, help='Disable power on of cloned VMs', dest='nopoweron', action='store_true')
    parser.add_argument('--resource-pool', nargs=1, required=False, help='The resource pool in which the new VMs should reside, (default = Resources, the root resource pool)', dest='resource_pool', type=str)
    parser.add_argument('-S', '--disable-SSL-certificate-verification', required=False, help='Disable SSL certificate verification on connect', dest='nosslcheck', action='store_true')
    parser.add_argument('-t', '--template', nargs=1, required=True, help='Template to deploy', dest='template', type=str)
    parser.add_argument('--container', nargs=1, required=False, help='The cluster where the template resides. Giving this options '
                                                                     'expedite the process of cloning.', dest='template_container',
                        type=str)
    parser.add_argument('-T', '--threads', nargs=1, required=False, help='Amount of threads to use. Choose the amount of threads with the speed of your datastore in mind, each thread starts the creation of a virtual machine. (default = 1)', dest='threads', type=int, default=[1])
    parser.add_argument('-u', '--user', nargs=1, required=True, help='The username with which to connect to the host', dest='username', type=str)
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    parser.add_argument('-w', '--wait-max', nargs=1, required=False, help='Maximum amount of seconds to wait when gathering information (default = 120)', dest='maxwait', type=int, default=[120])
    args = parser.parse_args()
    return args

def find_obj(si, logger, name, vimtype, threaded=False):
    """
    Find an object in vSphere by it's name and return it
    """

    content = si.content
    obj_view = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    obj_list = obj_view.view

    for obj in obj_list:
        if threaded:
            logger.debug('THREAD %s - Checking Object "%s"' % (name, obj.name))
        else:
            logger.debug('Checking object "%s"' % obj.name)
        if obj.name == name:
            if threaded:
                logger.debug('THREAD %s - Found object %s' % (name, obj.name))
            else:
                logger.debug('Found object %s' % obj.name)
            return obj
    return None

def get_container_view(service_instance, obj_type, container=None):
    """
    Get a vSphere Container View reference to all objects of type 'obj_type'
    It is up to the caller to take care of destroying the View when no longer
    needed.
    Args:
        obj_type (list): A list of managed object types
    Returns:
        A container view ref to the discovered managed objects
    """
    if not container:
        container = service_instance.content.rootFolder

    view_ref = service_instance.content.viewManager.CreateContainerView(
        container=container,
        type=obj_type,
        recursive=True
    )
    return view_ref

def collect_properties(service_instance, view_ref, obj_type, path_set=None,
                       include_mors=False,desired_vm=None):
    """
    Collect properties for managed objects from a view ref
    Returns:
        A list of properties for the managed objects
    """

    collector = service_instance.content.propertyCollector

    # Create object specification to define the starting point of
    # inventory navigation
    obj_spec = pyVmomi.vmodl.query.PropertyCollector.ObjectSpec()
    obj_spec.obj = view_ref
    obj_spec.skip = True

    # Create a traversal specification to identify the path for collection
    traversal_spec = pyVmomi.vmodl.query.PropertyCollector.TraversalSpec()
    traversal_spec.name = 'traverseEntities'
    traversal_spec.path = 'view'
    traversal_spec.skip = False
    traversal_spec.type = view_ref.__class__
    obj_spec.selectSet = [traversal_spec]

    # Identify the properties to the retrieved
    property_spec = pyVmomi.vmodl.query.PropertyCollector.PropertySpec()
    property_spec.type = obj_type

    if not path_set:
        property_spec.all = True

    property_spec.pathSet = path_set

    # Add the object and property specification to the
    # property filter specification
    filter_spec = pyVmomi.vmodl.query.PropertyCollector.FilterSpec()
    filter_spec.objectSet = [obj_spec]
    filter_spec.propSet = [property_spec]

    # Retrieve properties
    props = collector.RetrieveContents([filter_spec])

    properties = {}
    try:
        for obj in props:
            for prop in obj.propSet:

                if prop.val == desired_vm:
                    properties['name'] = prop.val
                    properties['obj'] = obj.obj
                    return properties
                else:
                    pass
    except Exception, e:
        print "The exception inside collector_properties " + str(e)
    return properties


def vm_clone_handler_wrapper(args):
    """
    Wrapping arround vm_clone_handler
    """
    return vm_clone_handler(*args)


def vm_clone_handler(host, port,username, password,logger, vm_name, datacenter_name, cluster_actual_name, hostMor, resource_pool_name, folder_name, ds,
                     maxwait, power_on, print_ips, template, template_vm, mac_ip_pool, mac_ip_pool_results):
    """
    Will handle the thread handling to clone a virtual machine and run post processing
    """

    run_loop = True
    vm = None

    #Debug
    #logger.info("THREAD %s - Login Parameter %s %s %s %s " %(vm_name,host, port,username, password))

    si = loginToVc(host, port, username, password,logger)


    logger.debug('THREAD %s - started' % vm_name)
    logger.info('THREAD %s - Trying to clone %s to new virtual machine' % (vm_name, template))

    # Find the correct Datacenter
    datacenter = None
    if datacenter_name:
        logger.debug('THREAD %s - Finding datacenter %s' % (vm_name, datacenter_name))
        datacenter = find_obj(si, logger, datacenter_name, [vim.Datacenter], False)
        if datacenter is None:
            logger.critical('THREAD %s - Unable to find datacenter %s' % (vm_name, datacenter_name))
            return 1
        logger.info('THREAD %s - Datacenter %s found' % (vm_name, datacenter_name))

    # Find the correct Cluster
    cluster = None
    if cluster_actual_name:
        logger.debug('THREAD %s - Finding cluster %s' % (vm_name, cluster_actual_name))
        cluster = find_obj(si, logger, cluster_actual_name, [vim.ClusterComputeResource], False)
        if cluster is None:
            logger.critical('THREAD %s - Unable to find cluster %s' % (vm_name, cluster_actual_name))
            return 1
        logger.info('THREAD %s - Cluster %s found' % (vm_name, cluster_actual_name))

    # Find the correct Resource Pool
    resource_pool = None
    if resource_pool_name:
        logger.debug('THREAD %s - Finding resource pool %s' % (vm_name, resource_pool_name))
        resource_pool = find_obj(si, logger, resource_pool_name, [vim.ResourcePool], False)
        if resource_pool is None:
            logger.critical('THREAD %s - Unable to find resource pool %s' % (vm_name, resource_pool_name))
            return 1
        logger.info('THREAD %s - Resource pool %s found' % (vm_name, resource_pool_name))
    elif cluster:
        logger.info('THREAD %s - No resource pool specified, but a cluster is. Using its root resource pool.' % vm_name)
        resource_pool = cluster.resourcePool
        logger.info('THREAD %s - resource pool %s' % (vm_name,resource_pool))
    else:
        logger.info('THREAD %s - No resource pool specified. Using the default resource pool.' % vm_name)
        resource_pool = find_obj(si, logger, 'Resources', [vim.ResourcePool], False)

    # Find the correct folder
    folder = None
    if folder_name:
        logger.debug('THREAD %s - Finding folder %s' % (vm_name, folder_name))
        folder = find_obj(si, logger, folder_name, [vim.Folder], False)
        if folder is None:
            logger.critical('THREAD %s - Unable to find folder %s' % (vm_name, folder_name))
            return 1
        logger.info('THREAD %s - Folder %s found' % (vm_name, folder_name))
    elif datacenter:
        logger.info('THREAD %s - Setting folder to datacenter root folder as a datacenter has been defined' % vm_name)
        folder = datacenter.vmFolder
    else:
        logger.info('THREAD %s - Setting folder to template folder as default' % vm_name)
        folder = template_vm.parent

    # Find the correct datastore
    datastore = ds
    datastoreName=ds.info.name

    #Debug
    #logger.info("Coming after DS INFO NAME " + ds)

    if datastore is None:
        logger.critical('THREAD %s - Unable to find datastore %s' % (vm_name, datastoreName))
        return 1
    logger.info('THREAD %s - Datastore %s found' % (vm_name,datastoreName))

    # Creating necessary specs
    logger.debug('THREAD %s - Creating relocate spec' % vm_name)
    relocate_spec = vim.vm.RelocateSpec()
    if resource_pool:
        logger.debug('THREAD %s - Resource pool found, using' % vm_name)
        relocate_spec.pool = resource_pool
    if datastore:
        logger.info('THREAD %s - DS on which clone will be created %s . MOR: %s' % (vm_name,datastoreName, str(datastore)))
        relocate_spec.datastore = datastore

    if hostMor:
        logger.info('THREAD %s - Host on which clone will be created %s . MOR:%s' %(vm_name,hostMor.name,hostMor))
        relocate_spec.host = hostMor

    try:
        logger.debug('THREAD %s - Creating clone spec' % vm_name)
        clone_spec = vim.vm.CloneSpec(powerOn=False, template=False, location=relocate_spec)
        logger.debug('THREAD %s - Creating clone task' % vm_name)
        task = template_vm.Clone(name=vm_name, folder=folder, spec=clone_spec)
        logger.info('THREAD %s - Cloning task created' % vm_name)
        logger.info('THREAD %s - Checking task for completion. This might take a while' % vm_name)

        while run_loop:
            info = task.info
            logger.debug('THREAD %s - Checking clone task' % vm_name)
            if info.state == vim.TaskInfo.State.success:
                logger.info('THREAD %s - Cloned and running' % vm_name)
                vm = info.result
                run_loop = False
                break
            elif info.state == vim.TaskInfo.State.running:
                logger.debug('THREAD %s - Cloning task is at %s percent' % (vm_name, info.progress))
            elif info.state == vim.TaskInfo.State.queued:
                logger.debug('THREAD %s - Cloning task is queued' % vm_name)
            elif info.state == vim.TaskInfo.State.error:
                errormsg=None
                try:
                    errormsg = info.error
                except Exception, e:
                    logger.error('THREAD %s - Cloning task has quit with unknown error: %s'%(vm_name,str(e)))
                if errormsg:
                    logger.info('THREAD %s - Cloning task has quit with error: %s' % (vm_name, errormsg))
                else:
                    logger.info('THREAD %s - Cloning task has quit with cancelation' % vm_name)
                run_loop = False
                break


            logger.debug('THREAD %s - Sleeping 10 seconds for new check' % vm_name)
            sleep(10)

    except Exception, e:
        logger.info('THREAD %s - Cloning task failed with error %s' % (vm_name,str(e)))

    if vm and power_on:
        logger.info('THREAD %s - Powering on VM. This might take a couple of seconds' % vm_name)
        power_on_task = vm.PowerOn()
        logger.debug('THREAD %s - Waiting fo VM to power on' % vm_name)
        run_loop = True
        while run_loop:
            info = power_on_task.info
            if info.state == vim.TaskInfo.State.success:
                run_loop = False
                break
            elif info.state == vim.TaskInfo.State.error:
                if info.error:
                    logger.info('THREAD %s - Power on has quit with error: %s' % (vm_name, info.error))
                else:
                    logger.info('THREAD %s - Power on has quit with cancelation' % vm_name)
                run_loop = False
                break
            sleep(5)

    if vm and power_on and print_ips:
        logger.debug('THREAD %s - Printing ip ' % vm_name)
        mac_ip_pool_results.append(mac_ip_pool.apply_async(vm_mac_ip_handler, (logger, vm,maxwait,power_on, print_ips)))
    elif vm and print_ips:
        logger.error('THREAD %s - Power on is disabled, printing of IP is not possible' % vm_name)

    Disconnect(si)
    return vm

def find_mac_ip(logger, vm, maxwait, ipv6=False, threaded=False):
    """
    Find the external mac and IP of a virtual machine and return it
    """

    mac = None
    ip = None
    waitcount = 0

    while waitcount < maxwait:
        if threaded:
            logger.debug('THREAD %s - Waited for %s seconds, gathering net information' % (vm.config.name, waitcount))
        else:
            logger.debug('Waited for %s seconds, gathering net information for virtual machine %s' % (waitcount, vm.config.name))
        net_info = vm.guest.net

        for cur_net in net_info:
            if cur_net.macAddress:
                if threaded:
                    logger.debug('THREAD %s - Mac address %s found' % (vm.config.name, cur_net.macAddress))
                else:
                    logger.debug('Mac address %s found for virtual machine %s' % (cur_net.macAddress, vm.config.name))
                mac = cur_net.macAddress
            if cur_net.ipConfig:
                if cur_net.ipConfig.ipAddress:
                    for cur_ip in cur_net.ipConfig.ipAddress:
                        if threaded:
                            logger.debug('THREAD %s - Checking ip address %s' % (vm.config.name, cur_ip.ipAddress))
                        else:
                            logger.debug('Checking ip address %s for virtual machine %s' % (cur_ip.ipAddress, vm.config.name))
                        if ipv6 and re.match('\d{1,4}\:.*', cur_ip.ipAddress) and not re.match('fe83\:.*', cur_ip.ipAddress):
                            ip = cur_ip.ipAddress
                        elif not ipv6 and re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', cur_ip.ipAddress) and cur_ip.ipAddress != '127.0.0.1':
                            ip = cur_ip.ipAddress
                        if ip:
                            if threaded:
                                logger.info('THREAD %s - Mac %s and ip %s found' % (vm.config.name, mac, ip))
                            else:
                                logger.info('Mac %s and ip %s found for virtual machine %s' % (mac, ip, vm.config.name))
                            return [mac, ip]

        if threaded:
            logger.debug('THREAD %s - No IP found, waiting 5 seconds and retrying' % vm.config.name)
        else:
            logger.debug('No IP found for virtual machine %s, waiting 5 seconds and retrying' % vm.config.name)
        waitcount += 5
        sleep(5)
    if mac:
        if threaded:
            logger.info('THREAD %s - Found mac address %s, No ip address found' % (vm.config.name, mac))
        else:
            logger.info('Found mac address %s, No ip address found for virtual machine %s' % (mac, vm.config.name))
        return [mac, '']
    if threaded:
        logger.info('THREAD %s - Unable to find mac address or ip address' % vm.config.name)
    else:
        logger.info('Unable to find mac address or ip address for virtual machine %s' % vm.config.name)
    return None


def vm_mac_ip_handler(logger, vm, ipv6, maxwait, post_script, power_on, print_ips, print_macs, custom_mac):
    """
    Gather mac, ip and run post-script for a cloned virtual machine
    """

    mac_ip = None
    if print_macs or print_ips:
        logger.info('THREAD %s - Gathering mac and ip' % vm.config.name)
        mac_ip = find_mac_ip(logger, vm, maxwait, ipv6, True)
        if mac_ip and print_macs and print_ips:
            logger.info('THREAD %s - Printing mac and ip information: %s %s %s' % (vm.config.name, vm.config.name, mac_ip[0], mac_ip[1]))
            print('%s %s %s' % (vm.config.name, mac_ip[0], mac_ip[1]))
        elif mac_ip and print_macs:
            logger.info('THREAD %s - Printing mac information: %s %s' % (vm.config.name, vm.config.name, mac_ip[0]))
            print('%s %s' % (vm.config.name, mac_ip[0]))
        elif mac_ip and print_ips:
            logger.info('THREAD %s - Printing ip information: %s %s' % (vm.config.name, vm.config.name, mac_ip[1]))
            print('%s %s' % (vm.config.name, mac_ip[1]))
        elif print_macs or print_ips:
            logger.error('THREAD %s - Unable to find mac or ip information within %s seconds' % (vm.config.name, maxwait))

def loginToVc(host,port,username,password,logger):
    si = None
    try:
        context=ssl._create_unverified_context()
        #smart_stub = SmartStubAdapter(host=host, port=int(port), sslContext=context, connectionPoolTimeout=1800)
        #session_stub = VimSessionOrientedStub(smart_stub,VimSessionOrientedStub.makeUserLoginMethod(username, password))
        #si = vim.ServiceInstance('ServiceInstance', session_stub)
        #atexit.register(Disconnect, si)
        si = SmartConnect(host=host, user=username, pwd=password, port=int(port), sslContext=context)
        return si
    except IOError as e:
        pass

    if not si:
        logger.error('Could not connect to host %s with user %s and specified password' % (host, username))
        return 1

    logger.debug('Registering disconnect at exit')
    atexit.register(Disconnect, si)


def main():
    """
    Clone a VM or template into multiple VMs with logical names with numbers and allow for post-processing
    """

    # Handling arguments
    args = get_args()
    csvfile=None

    amount = args.amount[0]

    basename = None
    if args.basename:
        basename = args.basename[0]

    domain = None
    if args.domain:
        domain = args.domain[0]

    count = args.count[0]

    debug = args.debug

    cluster_name = []
    if args.cluster:
        cluster_name = [item for item in args.cluster.split(',')]

    datacenter_name = None
    if args.datacenter:
        datacenter_name = args.datacenter[0]

    datastore_name = []
    if args.datastore:
        datastore_name =  [item for item in args.datastore.split(',')]

    folder_name = None
    if args.folder:
        folder_name = args.folder[0]

    host = args.host[0]
    print_ips = args.ips

    log_file = None
    if args.logfile:
        log_file = args.logfile[0]

    port = args.port[0]

    password = None
    if args.password:
        password = args.password[0]

    power_on = not args.nopoweron

    resource_pool_name = None
    if args.resource_pool:
        resource_pool_name = args.resource_pool[0]


    nosslcheck = args.nosslcheck
    template = args.template[0]

    container_cluster=None
    if args.template_container:
        container_cluster=args.template_container[0]

    threads = args.threads[0]
    username = args.username[0]
    verbose = args.verbose
    maxwait = args.maxwait[0]

    # Logging settings

    def generate_logger(log_level=None,log_file=None):
        import logging
        #    PROJECT_DIR="/home/vmlib/spm/nsx"
        fh=None
        FORMAT = "%(asctime)s %(levelname)s %(message)s"
        logger = logging.getLogger(__name__)
        logger.setLevel(log_level)
        # Reset the logger.handlers if it already exists.
        if logger.handlers:
            logger.handlers = []
        formatter = logging.Formatter(FORMAT)
        if log_file:
            fh = logging.FileHandler(log_file)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        return logger

    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    if log_file=='nolog':
        logger = generate_logger(log_level,log_file=None)
    else:
        log_file = log_file
        if not log_file:
            currentTime = datetime.datetime.now().strftime("%d%m%Y%H%M%S")
            log_file = host+"_Clones_" + currentTime+".log"
        logger = generate_logger(log_level,log_file=log_file)

    # Disabling SSL verification if set
    ssl_context = None
    context = ssl._create_unverified_context()

    # Getting user password
    if password is None:
        logger.debug('No command line password received, requesting password from user')
        password = getpass.getpass(prompt='Enter password for vCenter %s for user %s: ' % (host, username))

    try:

        si=loginToVc(host,port,username,password,logger)


        def GetAllClusters(datacenter):
            if datacenter == None:
                logger.error("You have to specify datacenter object")
                return []
            elif not (isinstance(datacenter, vim.Datacenter)):
                logger.error(str(datacenter) + " is not a datacenter object")
                return []
            else:
                logger.info("Datacenter name given: " + datacenter.name)

            hostFolder = datacenter.hostFolder
            allClusterObjList = []
            crs = hostFolder.childEntity
            logger.debug("crs: " + str(crs))

            def WalkFolder(folder, allClusterObjList):
                childEntities = folder.childEntity
                for i in range(len(childEntities)):
                    WalkManagedEntity(childEntities[i], allClusterObjList)

            def WalkManagedEntity(entity, allClusterObjList):
                if isinstance(entity, vim.Folder):
                    WalkFolder(entity, allClusterObjList)
                elif isinstance(entity, vim.ClusterComputeResource):
                    allClusterObjList.append(entity)

            if crs == None:
                return []
            for cr in crs:
                WalkManagedEntity(cr, allClusterObjList)

            return allClusterObjList

        def GetAllClusterNames(datacenter):
            nameList = []
            logger.info("datacenter: " + str(datacenter))
            clusters = GetAllClusters(datacenter)
            logger.debug("clusters: " + str(clusters))
            for entity in clusters:
                nameList.append(entity.name)

            logger.debug("nameList: " + str(nameList))
            return nameList

        def GetClusters(datacenter, clusterNames=[]):
            """
            Return list of cluster objects from given cluster name.

            @param datacenter: datacenter object
            @type datacenter: Vim.Datacenter
            @param clusterNames: cluster name list
            @type clusterNames: string[]
            """
            foundCr = []
            clusterListObj = GetAllClusters(datacenter)
            logger.debug("'%s' has %d clusters." % (datacenter.name, len(clusterListObj)))
            if len(clusterNames) == 0:
                # equivalent to GetAllClusters()
                if len(clusterListObj) == 0:
                    logger.warning("No Cluster found in %s" % (datacenter.name))
                    return []
                else:
                    return clusterListObj
            else:
                foundCr = [c for c in clusterListObj if c.name in clusterNames]

            if len(foundCr) == 0:
                logger.warning("Cluster '%s' not found in '%s'" % (
                    str(clusterNames), datacenter.name))

            return foundCr

        def GetHostsInClusters(datacenter, clusterNames=[], connectionState=None):
            """
            Return list of host objects from given cluster names.

            @param datacenter: datacenter object
            @type datacenter: Vim.Datacenter
            @param clusterNames: cluster name list
            @type clusterNames: string[]
            @param connectionState: host connection state ("connected", "disconnected", "notResponding"), None means all states.
            @typr connectionState: string
            """

            if len(clusterNames) == 0:
                clusterObjs = GetAllClusters(datacenter)
            else:
                clusterObjs = GetClusters(datacenter, clusterNames)

            hostObjs = []
            if connectionState == None:
                hostObjs = [h for cl in clusterObjs for h in cl.host]
            else:
                hostObjs = [h for cl in clusterObjs for h in cl.host if h.runtime.connectionState == connectionState and not h.runtime.inMaintenanceMode]

            return hostObjs

        dcMor = None

        if datacenter_name:
            logger.info('THREAD %s - Finding datacenter %s' % ("MAIN", datacenter_name))
            dcMor = find_obj(si, logger, datacenter_name, [vim.Datacenter], False)
            if dcMor is None:
                logger.debug('THREAD %s - Unable to find datacenter %s' % ("MAIN", datacenter_name))
                return 1
            logger.info('THREAD %s - Datacenter %s found' % ("MAIN", datacenter_name))

        # Minimize the traversal of Datastore to specific Datacenter. DS Mor can be different for different DC in a VC
        ds_mor_list=[]
        datastoresMors = dcMor.datastore
        for datastore in datastoresMors:
            if datastore.info.name in datastore_name:
                ds_mor_list.append(datastore)
            else:
                pass

        #Debug
        #logger.info("The datastore list is "+str(ds_mor_list))

        # Find the correct VM
        template_vm= None #Mor for Template
        clusterMorList=GetClusters(dcMor,[container_cluster])
        desiredClusterMor=None
        for item in clusterMorList:
            desiredClusterMor = item

        if desiredClusterMor is None:
            logger.warning('Traversing the whole VC to locate the template. This might take time.')


        #Try the Property collector

        if template and desiredClusterMor:
            logger.debug('Finding template %s via property collector.' % template)
            vm_properties = ["name"]
            view = get_container_view(si, obj_type=[vim.VirtualMachine],container=desiredClusterMor)
            vm_data = collect_properties(si, view_ref=view,
                                         obj_type=vim.VirtualMachine,
                                         path_set=vm_properties,
                                         include_mors=True,desired_vm=template)
            if vm_data['name'] == template:
                logger.info('Template %s found' % template)
                template_vm = vm_data['obj']
            else:
                logger.info('Finding template %s failed via fast method.' % template)

        #Debug
        #logger.info("Coming after Property Collector Method")

        if template_vm is None:

            logger.debug('Finding template %s via walking down the inventory. This '
                         'might take time. '% template)
            template_vm = find_obj(si, logger, template, [vim.VirtualMachine], False)

        if template_vm is None:
            logger.error('Unable to find template %s' % template)
            return 1
        logger.info('Template %s found' % template)

        # Pool handling
        clusterList = GetAllClusterNames(dcMor)

        desiredCluster = [cl for cl in clusterList if cl not in cluster_name]

        logger.info("The Desired Cluster are " + str(desiredCluster))

        #numberofDatastore=len(datastore_name)
        numberofDatastore = len(ds_mor_list)
        dsCount=0

        hostMorList = GetHostsInClusters(dcMor, desiredCluster, 'connected')
        totalEligibleHost = len(hostMorList)
        logger.info('Total Hosts on which VMs will be created ' + str(totalEligibleHost))
        vmCountPerHost = amount / totalEligibleHost
        remainingVms = amount % totalEligibleHost

        for cluster in desiredCluster:
            logger.debug('Setting up pools and threads')
            pool = ThreadPool(threads)
            mac_ip_pool = ThreadPool(threads)
            mac_ip_pool_results = []
            vm_specs = []
            logger.debug('Pools created with %s threads' % threads)
            logger.debug('Creating thread specifications')

            clusterHostMorList = GetHostsInClusters(dcMor, [cluster], 'connected')

            for clusterHostMor in clusterHostMorList:
                if str(clusterHostMor.name) == "sc2-hs1-d2204.eng.vmware.com":
                    continue
                for a in range(1,vmCountPerHost+1):
                    vm_name = basename + str(count)
                    if domain:
                        vm_name = vm_name + "." + domain
                    count += 1
                    ds = ds_mor_list[dsCount]
                    # Debug
                    logger.info("The Datastore send to spec is " + str(ds.info.name))
                    #logger.info("THREAD %s - Initiating Pool for Host %s " % (vm_name, clusterHostMor.name))

                    vm_specs.append((host,port,username, password,logger, vm_name, datacenter_name, cluster, clusterHostMor,
                                     resource_pool_name, folder_name, ds,maxwait, power_on, print_ips, template,
                                     template_vm, mac_ip_pool, mac_ip_pool_results))

                    dsCount = dsCount + 1
                    if dsCount == numberofDatastore:
                        dsCount = 0

                if remainingVms:
                    vm_name = basename + str(count)
                    if domain:
                        vm_name = vm_name + "." + domain
                    count += 1
                    ds = ds_mor_list[dsCount]

                    vm_specs.append((host, port, username, password, logger, vm_name, datacenter_name, cluster, clusterHostMor,
                                     resource_pool_name, folder_name, ds, maxwait, power_on, print_ips, template,
                                     template_vm, mac_ip_pool, mac_ip_pool_results))

                    dsCount = dsCount + 1
                    if dsCount == numberofDatastore:
                        dsCount = 0
                    remainingVms = remainingVms - 1


            logger.debug('Running virtual machine clone pool')
            pool.map(vm_clone_handler_wrapper, vm_specs)


            logger.debug('Closing virtual machine clone pool')
            pool.close()
            pool.join()

            logger.debug('Waiting for all mac, ip and post-script processes')
            for running_task in mac_ip_pool_results:
                running_task.wait()

            logger.debug('Closing mac, ip and post-script processes')
            mac_ip_pool.close()
            mac_ip_pool.join()

    except vmodl.MethodFault as e:
        logger.error('Caught vmodl fault'
                     ' ' + str(e))

    except Exception as e:
        logger.error('Caught exception: ' + str(e))



    logger.info('Finished all tasks')
    if log_file != 'nolog':
        logger.info('The output is logged to '+ log_file)

    return 0


# Start program
if __name__ == "__main__":
    main()


