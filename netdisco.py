import sys,getopt,psutil,re,nmap

#sys module is used to get arguments from command line 

#getopt module is used to parse arguments passed through command line

#psutil module is used to get network details of current system

#re module is used to find ipaddres and netmask of selected interface



def help():
    print("\n\nnetdisco -i <interface>\n\n")
    print("-i  :specify interface")
    print("-h  :show help")
    print("\n\nExample:\n    netdisco -i wlan0\n    netdisco -i Wi-Fi")

def scanWnmap(ipaddr):
    nm=nmap.PortScanner()
    mn=nm.scan(hosts=ipaddr,arguments='-n -PA -PS -PE -sP ')
    hosts = [(i, nm[i]['status']['state']) for i in nm.all_hosts()]

    #print("\n")
   # print("Total No. of hosts:", mn['nmap']['scanstats']['totalhosts'])
   # print("No. of hosts up:", mn['nmap']['scanstats']['uphosts'])
   # print("No. of hosts down:", mn['nmap']['scanstats']['downhosts'])
    #print("\n")
    
    #print("Alive Hosts\tStatus\t\tMAC Address\t\t\tMAC Vendor")
    for alive_host, status in hosts:
        if(status.lower()=='up'):
            print('{0}\t{1}\t\t{2}\t\t{3}'.format(alive_host,status,
                                                  "".join([macaddr for macaddr,macven in mn['scan'][alive_host]['vendor'].items()]),
                                                  "".join([macven for macaddr,macven in mn['scan'][alive_host]['vendor'].items()])))

def mainNet(interface):
    try:
        psu=str(psutil.net_if_addrs()[interface][:2])
    except:
        print("\n\nNo such interface available")
        exit()
   # print(psu)
    ip_addr,netmask,broad=re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',psu)

    del psu,broad

    print("\n\nSystem Details:")
    print("\nip addr: ",ip_addr)
    print("netmask: ",netmask)
    ip_addr=ip_addr.split('.')
    netmask=netmask.split('.')

    ipaddr=''
    #wildcard=''#if netmask is 255.255.255.0 then wildcard will be 0.0.0.255
    binnetmask=''
    length=len(netmask)

    for i in range(length):
        ipaddr+=str(int(ip_addr[i]) & int(netmask[i]))
        #wildcard+=str(int(netmask[i]) ^ 255))
        binnetmask+=bin(int(netmask[i]))
        if(i<length-1):
            ipaddr+='.'

    binnetmask=binnetmask.count('1')

    del i,ip_addr,netmask,length

    print("\nScanning..."+"\""+ipaddr+'/'+str(binnetmask)+"\"\n")
    print("Alive Hosts\tStatus\t\tMAC Address\t\t\tMAC Vendor")
    if binnetmask>=24:
        ipaddr+='/'+str(binnetmask)
        scanWnmap(ipaddr)
    else:
        ipaddr+='/'+'24'
        i=2**(8-binnetmask%8)
        while i!=-1:
            #print(ipaddr)
            scanWnmap(ipaddr)
            ipaddr=ipaddr.split('.')
            ipaddr[2]=str(int(ipaddr[2])+1)
            ipaddr=".".join(ipaddr)
            i=i-1
        



#execution starts from here
#getting all arguments except file name

cmdargv=sys.argv[1:]

#print(cmdargv)

try:
    options,argvs=getopt.getopt(cmdargv,'hi:',['help'])
except:
    help()
    exit()
    
interface=None
for opt,arg in options:
    #print(opt,arg)
    if(opt=='-h'):
        help()
        exit()
    elif(opt=='-i'):
        interface=arg
        mainNet(interface)
    else:
        help()
        
#print(options)
#print(argvs)
