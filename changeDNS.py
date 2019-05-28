__author__ = 'smrutim'

from bisect import insort
import multiprocessing
import argparse
import paramiko
import time
import sys
import datetime
import csv



synchObj=multiprocessing.Manager()

#Synchronized Object to Hold Results

inv_list=synchObj.list([])
errored_dict=synchObj.dict()
success_dict=synchObj.dict()

def changeDS(information,):
    global inv_list
    global errored_dict
    global success_dict
    lineinfo=information.split(':')
    vmAddress=lineinfo[0]
    dnsname=lineinfo[1]


    insort(inv_list, vmAddress)
    user="root"
    password="ca$hc0w"
    ssh=paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(vmAddress,username=user,password=password)
        print "Working on: "+ vmAddress

        try:
            convertCmd = "esxcli system hostname set --host="+dnsname
            stdin, stdout, stderr = ssh.exec_command(convertCmd)
            while not stdout.channel.exit_status_ready():
                time.sleep(2)
            success_dict[vmAddress]= "DNS Change successful to "+dnsname

        except Exception, e2:
            print "The error while changing DNS of "+vmAddress+ " "+ str(e2)
            errored_dict[vmAddress]= str(e2)
            
    except Exception,e1:

        print "The error while connecting " + vmAddress + ": " +str(e1)
        errored_dict[vmAddress]= str(e1)

    finally:
        ssh.close()






if __name__ == '__main__':


    parser=argparse.ArgumentParser()
    parser.add_argument("ifile",help="Filename containing IP addresses",type=str,)
    user="root"
    password="ca$hc0w"
    args, unknown = parser.parse_known_args()

    if args.ifile:

        with open(args.ifile, 'rb') as f:
            lines = [line.rstrip('\n\r') for line in f]
#            print "IP are" + str(lines)

        jobs = []

        for ipAddInfo in lines:
            proc = multiprocessing.Semaphore(multiprocessing.cpu_count())
            proc = multiprocessing.Process(target=changeDS, args=(str(ipAddInfo),))
            jobs.append(proc)
            proc.start()

        for job in jobs:
            job.join()

    else:
        print "Please provide a valid file input with -ifile option"
        sys.exit(0)



    for iplist in inv_list:
        if iplist in success_dict:
            print iplist +" "+success_dict[iplist]

        elif iplist in errored_dict:
            print iplist +" "+errored_dict[iplist]

        else:
            print "Could not obtain status for "+iplist



