#!/usr/bin/env python
"""
This module registers virtual machines that
exist on a datastore, but are not part of the inventory.
"""

from pyVim.connect import SmartConnect
from pyVim.connect import Disconnect
from pyVmomi import vmodl
from pyVmomi import vim
import argparse
import atexit
import urllib2
import urlparse
import base64
import ssl
import logging
import datetime
import getpass
from time import sleep
from multiprocessing.dummy import Pool as ThreadPool
import sys


VMX_PATH = []
DS_VM = {}
INV_VM = []
REGISTER_VMX=[]


def updatevmx_path():
    """
    function to set the VMX_PATH global variable to null
    """
    global VMX_PATH
    VMX_PATH = []


def url_fix(s, charset='utf-8'):
    """
    function to fix any URLs that have spaces in them
    urllib for som ve reason doesn't like spaces
    function found on internet
    """
    if isinstance(s, unicode):
        s = s.encode(charset, 'ignore')
    scheme, netloc, path, qs, anchor = urlparse.urlsplit(s)
    path = urllib2.quote(path, '/%')
    qs = urllib2.quote(qs, ':&=')
    return urlparse.urlunsplit((scheme, netloc, path, qs, anchor))


def get_args():
    """
    Supports the command-line arguments listed below.
    function to parse through args for connecting to ESXi host or
    vCenter server function taken from getallvms.py script
    from pyvmomi github repo
    """
    parser = argparse.ArgumentParser(
        description='Process args for retrieving all the Virtual Machines')
    parser.add_argument(
        '-s', '--host', required=True, action='store',
        help='Remote host to connect to')
    parser.add_argument('-o', '--port', nargs=1, required=False, help='Server port to connect to (default = 443)',
                        dest='port', type=int, default=[443])
    parser.add_argument('-u', '--user', nargs=1, required=True, help='The username with which to connect to the host',
                        dest='username', type=str)
    parser.add_argument('-p', '--password', nargs=1, required=False,
                        help='The password with which to connect to the host. If not specified, the user is prompted at runtime for a password',
                        dest='password', type=str)
    parser.add_argument('--datastore', required=True,
                        help='The datastore list to look into.Pass values delimited with a comma(,)',
                        dest='datastore', type=str)
    parser.add_argument('--datacenter', nargs=1, required=True,
                        help='The datacenter in which to look for VMs and registration',
                        dest='datacenter', type=str)
    parser.add_argument('--cluster', required=False,
                        help='The cluster which should not be used.Pass values delimited with a comma(,)',
                        dest='cluster', type=str)
    parser.add_argument('-T', '--threads', nargs=1, required=False,
                        help='Amount of threads to use. Choose the amount of threads with the speed of your datastore in mind, '
                             'each thread starts the creation of a virtual machine. (default = 1)',
                        dest='threads', type=int, default=[1])
    parser.add_argument('--pattern', required=True,
                        help='The VM regular expression pattern. Pass values delimited with a comma(,)',
                        dest='pattern', type=str)
    parser.add_argument('-P', '--disable-power-on', required=False, help='Disable power on of Registered VMs',
                        dest='nopoweron', action='store_true')
    parser.add_argument('-w', '--wait-max', nargs=1, required=False,
                        help='Maximum amount of seconds to wait when gathering information (default = 120)',
                        dest='maxwait', type=int, default=[120])
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose',
                        action='store_true')
    parser.add_argument('-d', '--debug', required=False, help='Enable debug output', dest='debug', action='store_true')
    parser.add_argument('-l', '--log-file', nargs=1, required=False, help='File to log to (default = stdout)',
                        dest='logfile', type=str)

    args = parser.parse_args()
    return args


def find_vmx(dsbrowser, dsname, datacenter, fulldsname):
    """
    function to search for VMX files on any datastore that is passed to it
    """
    args = get_args()
    search = vim.HostDatastoreBrowserSearchSpec()
    search.matchPattern = "*.vmx"
    search_ds = dsbrowser.SearchDatastoreSubFolders_Task(dsname, search)
    while search_ds.info.state != "success":
        pass
    # results = search_ds.info.result
    # print results

    for rs in search_ds.info.result:
        dsfolder = rs.folderPath
        for f in rs.file:
            try:
                dsfile = f.path
                vmfold = dsfolder.split("]")
                vmfold = vmfold[1]
                vmfold = vmfold[1:]
                vmxurl = "https://%s/folder/%s%s?dcPath=%s&dsName=%s" % \
                         (args.host, vmfold, dsfile, datacenter, fulldsname)
                VMX_PATH.append(vmxurl)
            except Exception, e:
                print "Caught exception : " + str(e)
                return -1


def examine_vmx(dsname,expectedPattern,username,password):
    """
    function to download any vmx file passed to it via the datastore browser
    and find the 'vc.uuid' and 'displayName'
    """
    args = get_args()

    try:
        for file_vmx in VMX_PATH:
            # print file_vmx

            username = username
            password = password
            gcontext = ssl._create_unverified_context()
            request = urllib2.Request(url_fix(file_vmx))
            base64string = base64.encodestring(
                '%s:%s' % (username, password)).replace('\n', '')
            request.add_header("Authorization", "Basic %s" % base64string)
            result = urllib2.urlopen(request,context=gcontext)
            vmxfile = result.readlines()
            mylist = []
            for a in vmxfile:
                mylist.append(a)
            for b in mylist:
                if b.startswith("displayName"):
                    dn = b
                if b.startswith("vc.uuid"):
                    vcid = b
            uuid = vcid.replace('"', "")
            uuid = uuid.replace("vc.uuid = ", "")
            uuid = uuid.strip("\n")
            uuid = uuid.replace(" ", "")
            uuid = uuid.replace("-", "")
            newdn = dn.replace('"', "")
            newdn = newdn.replace("displayName = ", "")
            newdn = newdn.strip("\n")
            if any(item in newdn for item in expectedPattern) :
                #Debug
                #print newdn
                vmfold = file_vmx.split("folder/")
                vmfold = vmfold[1].split("/")
                vmfold = vmfold[0]
                dspath = "[%s]/%s" % (dsname, vmfold)
                tempds_vm = dspath+"/"+newdn+".vmx"
                DS_VM[uuid] = tempds_vm
            else:
                pass

    except Exception, e:
        print "Caught exception : " + str(e)


def getvm_info(vm, depth=1):
    """
    Print information for a particular virtual machine or recurse
    into a folder with depth protection
    from the getallvms.py script from pyvmomi from github repo
    """
    maxdepth = 10

    # if this is a group it will have children. if it does,
    # recurse into them and then return

    if hasattr(vm, 'childEntity'):
        if depth > maxdepth:
            return
        vmlist = vm.childEntity
        for c in vmlist:
            getvm_info(c, depth+1)
        return
    if hasattr(vm, 'CloneVApp_Task'):
        vmlist = vm.vm
        for c in vmlist:
            getvm_info(c)
        return

    try:
        uuid = vm.config.instanceUuid
        uuid = uuid.replace("-", "")
        INV_VM.append(uuid)
    except Exception, e:
        print "Caught exception : " + str(e)
        return -1


def find_match(uuid,logger):
    """
    function takes vc.uuid from the vmx file and the instance uuid from
    the inventory VM and looks for match if no match is found
    it is printed out.
    """
    global REGISTER_VMX
    a = 0
    for temp in INV_VM:
        if uuid == temp:
            a = a+1
    if a < 1:
        REGISTER_VMX.append(DS_VM[uuid])
        logger.info(DS_VM[uuid] + " will be registered to the inventory")

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

def _create_char_spinner():
    """Creates a generator yielding a char based spinner.
    """
    while True:
        for c in '|/-\\':
            yield c





_spinner = _create_char_spinner()

def spinner(logger,label):
    """Prints label with a spinner.
    When called repeatedly from inside a loop this prints
    a one line CLI spinner.
    """
    logger.info('THREAD %s - Answering VM question in progress' % label)
    sys.stdout.write("\r\t%s %s \r\t   \n" % (label, _spinner.next()))
    sys.stdout.flush()


def vm_question_handler_wrapper(args):
    """
    Wrapping arround vm_question_handler
    """
    return spinner(*args)

def vm_register_handler(logger, vmxFile, datacenter, cluster, clusterHostMor,power_on):
    """
    Will handle the thread handling to register a virtual machine
    """
    run_loop = True
    vm = None
    vm_name = vmxFile.split('/')[1]
    logger.debug('THREAD %s - started' % vm_name)
    logger.info('THREAD %s - Trying to register %s to inventory' % (vm_name, vm_name))

    clusterMor = cluster
    if clusterMor is None:
        logger.critical('THREAD %s - Unable to find cluster %s' % (vm_name, cluster))
        return 1

    logger.info('THREAD %s - Cluster %s found' % (vm_name, cluster.name))

    resource_pool = None
    logger.info('THREAD %s - Using %s root resource pool.' % (vm_name, cluster.name))
    resource_pool = clusterMor.resourcePool

    logger.info('THREAD %s - Setting folder to datacenter root folder' % vm_name)
    folder = datacenter.vmFolder

    try:
        logger.debug('THREAD %s - Creating Register task' % vm_name)
        logger.info("THREAD %s - Register VM Spec : vmxFile - %s ,"
                    "hostMor - %s, pool - %s " %(vm_name,vmxFile,clusterHostMor,resource_pool))
        task = folder.RegisterVM_Task(vmxFile,vm_name, asTemplate=False, host=clusterHostMor,pool=resource_pool)
        while run_loop:
            info = task.info
            logger.debug('THREAD %s - Checking register task' % vm_name)
            if info.state == vim.TaskInfo.State.success:
                logger.info('THREAD %s - Register VM Successful' % vm_name)
                vm = info.result
                run_loop = False
                break
            elif info.state == vim.TaskInfo.State.running:
                logger.debug('THREAD %s - Register task is at %s percent' % (vm_name, info.progress))
            elif info.state == vim.TaskInfo.State.queued:
                logger.debug('THREAD %s - Register task is queued' % vm_name)
            elif info.state == vim.TaskInfo.State.error:
                if info.error.fault:
                    logger.info(
                        'THREAD %s - Register task has quit with error: %s' % (vm_name, info.error.fault.faultMessage))
                else:
                    logger.info('THREAD %s - Register task has quit with cancelation' % vm_name)
                run_loop = False
                break
            logger.debug('THREAD %s - Sleeping 5 seconds for new check' % vm_name)
            sleep(5)
    except vmodl.MethodFault, e:
        logger.error('THREAD %s -  Caught vmodl fault : %s' %(vm_name,str(e)))
    except Exception, e:
        logger.error('THREAD %s - Caught exception: %s'%(vm_name,str(e)))

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
                if info.error.fault:
                    logger.info(
                        'THREAD %s - Power on has quit with error: %s' % (vm_name, info.error.fault.faultMessage))
                else:
                    logger.info('THREAD %s - Power on has quit with cancelation' % vm_name)
                run_loop = False
                break
            else:
                if vm.runtime.question is not None:
                    question_id = vm.runtime.question.id
                    answer_id="2"
                    vm.AnswerVM(question_id, answer_id)

                spinner(logger,vm_name)

            sleep(5)

def vm_register_handler_wrapper(args):
    """
    Wrapping arround vm_clone_handler
    """
    return vm_register_handler(*args)





def main():
    """
    function runs all of the other functions. Some parts of this function
    are taken from the getallvms.py script from the pyvmomi gihub repo
    """
    args = get_args()
    host=args.host
    datastoreList = []
    if args.datastore:
        datastoreList = [item for item in args.datastore.split(',')]

    datacenter_name = None
    if args.datacenter:
        datacenter_name = args.datacenter   [0]

    cluster_name = []
    if args.cluster:
        cluster_name = [item for item in args.cluster.split(',')]

    maxwait = args.maxwait[0]
    debug = args.debug
    verbose = args.verbose
    threads = args.threads[0]
    userPattern = []
    if args.pattern:
        userPattern = [item for item in args.pattern.split(',')]

    log_file = None
    if args.logfile:
        log_file = args.logfile[0]

    password = None
    if args.password:
        password = args.password[0]

    username = args.username[0]
    port = args.port[0]
    power_on = not args.nopoweron

    # Logging settings

    def generate_logger(fileName, log_level):
        import logging
        #    PROJECT_DIR="/home/vmlib/spm/nsx"
        LOG_FILENAME = fileName
        FORMAT = "%(asctime)s %(levelname)s %(message)s"
        logger = logging.getLogger(__name__)
        logger.setLevel(log_level)
        # Reset the logger.handlers if it already exists.
        if logger.handlers:
            logger.handlers = []
        fh = logging.FileHandler(LOG_FILENAME)
        ch = logging.StreamHandler()
        formatter = logging.Formatter(FORMAT)
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(ch)
        return logger



    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    if log_file:
        logger = generate_logger(log_file, log_level)
    else:
        currentTime = datetime.datetime.now().strftime("%d%m%Y%H%M%S")
        log_file = host + "_Register_" + currentTime + ".log"
        logger = generate_logger(log_file, log_level)

    # Getting user password

    if password is None:
        logger.debug('No command line password received, requesting password from user')
        password = getpass.getpass(prompt='Enter password for vCenter %s for user %s: ' % (host, username))



    try:
        si = None

        context = ssl._create_unverified_context()

        try:
            si = SmartConnect(host=host, user=username, pwd=password, port=int(port), sslContext=context)
        except IOError, e:
            pass

        if not si:
            logger.error('Could not connect to host %s with user %s and specified password' % (host, username))
            return -1

        atexit.register(Disconnect, si)

        #Finding Datacenter and Desired Datastore

        datacenter = None

        if datacenter_name:
            logger.debug('THREAD %s - Finding datacenter %s' % ("MAIN", datacenter_name))
            datacenter = find_obj(si, logger, datacenter_name, [vim.Datacenter], False)
            if datacenter is None:
                logger.critical('THREAD %s - Unable to find datacenter %s' % ("MAIN", datacenter_name))
                return 1
            logger.info('THREAD %s - Datacenter %s found' % ("MAIN", datacenter_name))


        datastores = datacenter.datastore
        vmfolder = datacenter.vmFolder
        vmlist = vmfolder.childEntity
        dsvmkey = []

        # each datastore found on ESXi host or vCenter is passed
        # to the find_vmx and examine_vmx functions to find all
        # VMX files and search them


        for ds in datastores:
            if ds.info.name in datastoreList:
                logger.info("Processing Datastore "+ds.info.name)
                find_vmx(ds.browser, "[%s]" % ds.summary.name, datacenter.name,ds.summary.name)
                examine_vmx(ds.summary.name,userPattern,username,password)
                updatevmx_path()
            else:
                pass

        # each VM found in the inventory is passed to the getvm_info
        # function to get it's instanceuuid

        #Debug
        #print "Coming Here 1"

        for vm in vmlist:
            getvm_info(vm)

        # Debug
        #print "Coming Here 2"

        # each key from the DS_VM hashtable is added to a separate
        # list for comparison later

        for a in DS_VM.keys():
            dsvmkey.append(a)

        # Debug
        #print "Coming Here 3"

        # each uuid in the dsvmkey list is passed to the find_match
        # function to look for a match
        """
        logger.info("THREAD MAIN - The following virtual machine(s) do not exist in the " \
              "inventory, but exist on a datastore " \
              ":")
        """

        for match in dsvmkey:
            find_match(match,logger)

        orphanedVmCount=0

        if REGISTER_VMX:
            orphanedVmCount = len(REGISTER_VMX)
        else:
            logger.error("THREAD MAIN - No VMX found to be registered.")
            return 1
        #Debug
        #print str(REGISTER_VMX)

        def GetAllClusters(datacenter):
            if datacenter == None:
                logger.error("You have to specify datacenter object")
                return []
            elif not (isinstance(datacenter, vim.Datacenter)):
                logger.error(str(datacenter) + " is not a datacenter object")
                return []
            else:
                logger.info("datacenter name: " + datacenter.name)

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
            @type clusterNames: ClusterObjectMor[]
            @param connectionState: host connection state ("connected", "disconnected", "notResponding"), None means all states.
            @typr connectionState: string
            """

            if len(clusterNames) == 0:
                clusterObjs = GetAllClusters(datacenter)
            else:
                clusterObjs = clusterNames

            hostObjs = []
            if connectionState == None:
                hostObjs = [h for cl in clusterObjs for h in cl.host]
            else:
                hostObjs = [h for cl in clusterObjs for h in cl.host if h.runtime.connectionState == connectionState and not h.runtime.inMaintenanceMode]

            return hostObjs

        #Pool handling
        #clusterList = GetAllClusterNames(datacenter)
        #desiredCluster = [cl for cl in clusterList if cl not in cluster_name]
        clusterList = GetAllClusters(datacenter)
        desiredCluster = [cl for cl in clusterList if cl.name not in cluster_name]

        hostMorList = GetHostsInClusters(datacenter, desiredCluster, 'connected')
        totalEligibleHost = len(hostMorList)
        logger.info('THREAD MAIN - Total Hosts on which VMs will be registered ' + str(totalEligibleHost))
        vmCountPerHost = orphanedVmCount / totalEligibleHost
        remainingVms = orphanedVmCount % totalEligibleHost
        vmxCount = 0

        for cluster in desiredCluster:
            logger.debug('Setting up pools and threads')
            pool = ThreadPool(threads)
            vm_specs = []
            logger.debug('Pools created with %s threads' % threads)
            logger.debug('Creating thread specifications')
            clusterHostMorList = GetHostsInClusters(datacenter, [cluster], 'connected')

            for clusterHostMor in clusterHostMorList:
                for i in range(1,vmCountPerHost+1):
                    vmxFile = REGISTER_VMX[vmxCount]

                    vm_specs.append((logger,vmxFile,datacenter,cluster,clusterHostMor,power_on))
                    vmxCount = vmxCount+1

                if remainingVms:
                    vmxFile = REGISTER_VMX[vmxCount]

                    vm_specs.append((logger, vmxFile, datacenter, cluster, clusterHostMor,power_on))
                    vmxCount = vmxCount+1
                    remainingVms = remainingVms - 1

            logger.debug('Running virtual machine register pool')
            pool.map(vm_register_handler_wrapper, vm_specs)

            logger.debug('Closing virtual machine register pool')
            pool.close()
            pool.join()

    except vmodl.MethodFault, e:
        logger.critical('Caught vmodl fault : ' + e.msg)

    except Exception, e:
        logger.critical('Caught exception: %s' % str(e))


    logger.info('Finished all tasks')
    logger.info('The output is logged to ' + log_file)
    return 0

# Start program
if __name__ == "__main__":
    main()
