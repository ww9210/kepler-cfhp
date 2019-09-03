#!/usr/bin/python
import sys
import re
import pickle
usage='parse_map.py <map file>'

mapname='System.map-4.15.0-13-generic'
mapname='centos.map.txt'
mapname='map.fedora.txt'
mapname='map.arch.txt'
mapname='System.map-4.15.0-2-amd64'
mapname='System.map-3.10.0-862.el7.x86_64'
mapname='System.map-4.16.0-1-default'
mapname='System.map-4.10.0-38-generic'
mapname='System.map-hardened'
mapname='System.map-4.15.0-20-generic'
mapname='System.map'



def undefine_all_func():
    for segea in Segments():
        #for funcea in Functions(segea, SegEnd(segea)):
        for funcea in range(segea, SegEnd(segea)):
            MakeUnkn(funcea,1)
            idc.MakeName(funcea,'')

def parse_file(filename):
    output_res=[]
    lines = file(filename,'r').readlines()
    for line in lines:
        if line == '':
            pass
        regex=r'([a-fA-F0-9]{16})\ ([TtrRdDAWBbV]{1})\ ([a-zA-Z0-9_\.]{1,})'
        res=re.match(regex,line)
        #print res
        if res==None:
            print line
            continue
        addr=res.group(1)
        t = res.group(2)
        name=res.group(3)
        if t in ['T','t']:
            #print addr, t, name
            output_res.append([int(addr,16),name])
    return output_res

def main():
    #if len(sys.argv)!=2:
        #print usage
    #filename = sys.argv[1]
    filename = mapname
    res = parse_file(filename)
    for entry in res:
        addr=entry[0]
        name=entry[1]
        idc.MakeCode(addr)
        idc.MakeFunction(addr)
        #idc.MakeName(addr,name,idc.SN_NOWARN)
        idc.MakeName(addr,name)
        #idc.LocByName('_copy_from_user')
        #print hex(_)

if __name__ == '__main__':
    main()
    pass
