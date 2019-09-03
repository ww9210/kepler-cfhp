from idautils import *
from idaapi import *
import pickle
#from ipc import *
def get_func_stack_frame_size():
	for segea in Segments():
	  	print '%x-%x'%(SegStart(segea),SegEnd(segea))
		for funcea in Functions(segea,SegEnd(segea)):
			functionName = GetFunctionName(funcea)
			print functionName
			#TODO
			pass

def get_func_code_refs_to(func_ea):
    """Returns a set with the code references to this function"""
    code_refs = set()

    for ref in CodeRefsTo(func_ea, 0): #callers
    	#print ref
        func_ida = get_func(ref)
        name = get_func_name(ref)
       	#func_start = func_ida.startEA
       	#pfn=get_frame(func_start) 
       	frame_size = get_frame_size(func_ida)	
        #print func_ida

        if not func_ida:
            #print "BUG?: coderef came from no function! %X->%X"%(ref, addr) 
            continue

        #if func_ida.startEA not in functions:
        #    print "BUG?: function %X not in our set (r=%X)!"%(func_ida.startEA, ref) 
        #    continue

        #code_refs.add((ref, func_ida.startEA, name))
        code_refs.add((ref, func_ida.startEA, name,frame_size))

    return code_refs 
'''
for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        functionName = GetFunctionName(funcea)
        for (startea, endea) in Chunks(funcea):
            for head in Heads(startea, endea):
                print functionName, ":", "0x%08x"%(head), ":", GetDisasm(head)
'''
#get_func_code_refs_to(0xFFFFFFFF81375100)#copy_from_user
xref_copy_to_user=get_func_code_refs_to(0xFFFFFFFF81375160)#copy_to_user
the_filename="res.txt"
with open(the_filename, 'wb') as f:
    pickle.dump(xref_copy_to_user, f)
#for _ in xref_copy_to_user:
	#print _
