from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect
import atexit
import ssl



def Login(host, user, pwd, port=443):
    context = ssl._create_unverified_context()
    si = SmartConnect(host=host,user=user,pwd=pwd,port=port,sslContext=context)
    atexit.register(Disconnect, si)
    return si



def GetAllDatacenter(si=None):
    content = si.RetrieveContent()
    datacenters = [entity for entity in content.rootFolder.childEntity if hasattr(entity, 'vmFolder')]
    return datacenters


def GetAllStandAloneHostsnCluster(datacenter):
    if datacenter == None:
        print("You have to specify datacenter object")
        return []
    elif not (isinstance(datacenter, vim.Datacenter)):
        print(str(datacenter) + " is not a datacenter object")
        return []
    else:
        print("datacenter name: " + datacenter.name)

    hostFolder = datacenter.hostFolder
    allClusterObjList = []
    allStandAloneHost = []

    crs = hostFolder.childEntity
    #print("crs: " + str(crs))

    def WalkFolder(folder, allClusterObjList):
        childEntities = folder.childEntity
        for i in range(len(childEntities)):
            WalkManagedEntity(childEntities[i], allClusterObjList)

    def WalkManagedEntity(entity, allClusterObjList):
        if isinstance(entity, vim.Folder):
            WalkFolder(entity, allClusterObjList)
        elif isinstance(entity, vim.ClusterComputeResource):
            allClusterObjList.append(entity)
        elif isinstance(entity, vim.ComputeResource):
            allStandAloneHost.append(entity)

    if crs == None:
        return []
    for cr in crs:
        WalkManagedEntity(cr, allClusterObjList)

    return allStandAloneHost , allClusterObjList





