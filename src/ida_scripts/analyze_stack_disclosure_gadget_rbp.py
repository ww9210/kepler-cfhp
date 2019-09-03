from idautils import *
from idaapi import *
from capstone import *
import pickle
md = None
isdebug = True
isdebug = False

#============================================================
interested_mnem=['mov', 'lea']
interested_opnd=['rdi','edi','rsi','esi','rdx','edx','dh','dl']
all_regs=['rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15','rbp','rsp'\
,'eax','ebx','ecx','edx','esi','edi','r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d','ebp','esp']
#============================================================

#==========types of lea instruction, enumeration=============
LEA_MEM_TO_REG=21
#============================================================
#==========types of mov instruction, enumeration=============
MOV_MEM_TO_REG=11
MOV_REG_TO_MEM=12
MOV_IMM_TO_REG=13
MOV_IMM_TO_MEM=14
MOV_REG_TO_REG=15
#============================================================

def dbg(content):
	if isdebug:
		print '[+]', content

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
        code_refs.add((ref, func_ida, name, frame_size))

    return code_refs 

	
def analyze_add(head):
	return None
	
def analyze_imul(head):
	return None
	
def analyze_and(head):
	return None
	
def analyze_sub(head):
	return None
	
def analyze_not(head):
	return None
	
def analyze_sbb(head):
	return None
	
def analyze_shl(head):
	return None

def analyze_pop(head):
	return None

def analyze_shr(head):	
	return None

def analyze_sar(head):	
	return None

def analyze_cmp(head):
	return None

def analyze_xor(head):
	return None

def analyze_or(head):
	return None

def analyze_test(head):
	return None

def analyze_push(head):
	return None

def analyze_lea(head):
	result = {}
	print('===== analyzing lea instruction =====')
	inst_bytes = idc.GetManyBytes(head, ItemSize(head))
	capstone_disasm = md.disasm(inst_bytes,head)
	inst = capstone_disasm.next() #only one instruction here
	print(inst_bytes.encode('hex'))
	num_of_opnds = len(inst.operands)
	assert(num_of_opnds==2)
	src = inst.operands[1]
	dst = inst.operands[0]
	print(inst.mnemonic+' '+inst.op_str)
	print('src type: '+str(src.type))
	print('dst type: '+str(dst.type))
	assert(dst.type==1 and src.type==3) #dst must be register
	dstreg=dst.reg
	src_base = inst.reg_name(src.mem.base)
	src_disp = src.mem.disp
	src_index = src.mem.index
	src_index_reg = ''
	if src_index != 0:
		src_index_reg = inst.reg_name(src_index)
	src_scale = src.mem.scale
	src_segment = src.mem.segment
	print(src_base+str(src_disp)+src_index_reg+str(src_scale)+ str(src_segment))
	result['type']=LEA_MEM_TO_REG
	result['addr']=head
	result['dst']=inst.reg_name(dstreg)
	result['src']={'base':src_base,'disp':src_disp,'index_reg':src_index_reg\
							,'scale':src_scale, 'segment':src_segment}
	print('===== end of analyzing a lea instruction =====')

	return result

def analyze_mov(head):
	result = {}
	dbg('===== analyzing mov instruction =====')
	inst_bytes = idc.GetManyBytes(head, ItemSize(head))
	capstone_disasm = md.disasm(inst_bytes,head)
	inst = capstone_disasm.next() #only one instruction here
	opndstr = inst.op_str
	dbg(inst.mnemonic + ' ' + opndstr)
	dbg(inst.bytes)
	dbg(inst_bytes.encode('hex'))
	num_of_opnds = len(inst.operands)
	assert(num_of_opnds==2)
	src = inst.operands[1]
	dst = inst.operands[0]
	#type 1: reg 2.immediate 3.mem
	dbg('src type: '+str(src.type))
	dbg('dst type: '+str(dst.type))
	if dst.type == 1:#dst is reg
		dstreg = dst.reg
		result['dst'] = inst.reg_name(dstreg)
		if src.type == 1:
			dbg('src is Register')
			dbg(inst.reg_name(src.reg)+'->'+inst.reg_name(dstreg))
			result['type'] = MOV_REG_TO_REG
			result['addr'] = head
			result['src'] = inst.reg_name(src.reg)
		elif src.type == 2: #src is immediate
			dbg('src isImmediate')
			dbg(str(src.imm)+'->'+inst.reg_name(dstreg))
			result['type']=MOV_IMM_TO_REG
			result['addr'] = head
			result['src']=src.imm
		elif src.type==3:
			dbg('src isMemory')
			src_base = inst.reg_name(src.mem.base)
			src_disp = src.mem.disp
			src_index = src.mem.index
			src_index_reg = ''
			if src_index != 0:
				src_index_reg = inst.reg_name(src_index)
			src_scale = src.mem.scale
			src_segment = src.mem.segment
			dbg(src_base+str(src_disp)+src_index_reg+str(src_scale)+ str(src_segment))
			#print src.mem,'->',dstreg
			result['type']=MOV_MEM_TO_REG
			result['addr'] = head
			result['src']={'base':src_base,'disp':src_disp,'index_reg':src_index_reg\
							,'scale':src_scale, 'segment':src_segment}
			#resutl['src'] = tmp_dict

	elif dst.type == 2:#dst is immediate
		assert(0)
	elif dst.type == 3:#dst is memory, do not care for now
		assert(src.type!=3) #src type could not be memory
		if dst.mem.base:
			base_reg = inst.reg_name(dst.mem.base)
			dbg('writing to memory '+'base reg: '+base_reg+' offset: '+str(dst.mem.disp))
		if src.type==1: #src is reg
			result['type']=MOV_REG_TO_MEM
			result['addr'] = head
		if src.type==2:
			result['type']=MOV_IMM_TO_MEM
			result['addr'] = head

		print(src)


	dbg('===== end of analyzing a mov instruction =====')
	return result

def analyze_inst(mnem,head):
	return {\
		'mov':analyze_mov, \
		'movsxd':analyze_mov, \
		'cmovns':analyze_mov, \
		'cmovnb':analyze_mov, \
		'movzx':analyze_mov, \
		'movzxd':analyze_mov, \
		'cmovg':analyze_mov, \
		'movsx':analyze_mov, \
		'cmova':analyze_mov, \
		'cmovle':analyze_mov, \
		'cmovbe':analyze_mov, \
		'cmovb':analyze_mov, \
		'cmovz':analyze_mov, \
		'lea':analyze_lea, \
		'add':analyze_add, \
		'imul':analyze_imul, \
		'sub':analyze_sub, \
		'and':analyze_and, \
		'not':analyze_not, \
		'sbb':analyze_sbb, \
		'xor':analyze_xor, \
		'or':analyze_or, \
		'shl':analyze_shl, \
		'shr':analyze_shr, \
		'sar':analyze_sar, \
		'cmp':analyze_cmp, \
		'test':analyze_test, \
		'pop':analyze_pop,\
		'push':analyze_push,\
	}[mnem](head)

def get_data_flow_sig(callsite,func):
	global md
	fc = idaapi.FlowChart(func)
	signature=[]
	reversed_instruction=[]
	seen_end=False
	for block in fc:
		if block.startEA <= callsite and block.endEA > callsite:
			for head in Heads(block.startEA, block.endEA):
				disasm = GetDisasm(head)
				if '_copy_to_user' not in disasm or \
						('call' not in disasm and 'jmp' not in disasm):
						inst_bytes = idc.GetManyBytes(head, ItemSize(head))
						reversed_instruction = [[head,inst_bytes]] + reversed_instruction
				else:
					seen_end=True
					break
			if seen_end:
				break

	for inst in reversed_instruction:
		dbg(GetDisasm(inst[0]))

	for entry in reversed_instruction:
		head=entry[0]
		disasm = GetDisasm(head)
		mnem = GetMnem(head)
		opnd0 = GetOpnd(head, 0)
		#opnd1 = GetOpnd(head, 1)
		dbg(disasm)
		dbg(mnem)
		dbg(hex(head))
		#print GetOpnd(head, 0), GetOpnd(head, 1), GetOpnd(head, 2)
		if mnem in interested_mnem or opnd0 in interested_opnd:
			tmp = analyze_inst(mnem,head)
			if tmp != None:
				signature.append(tmp)

	#assert 0 #should not reach here
	return signature,reversed_instruction

def isPush(inst):
	if inst[:4]=='push':
		return True
	else:
		return False

def isSubRsp(head):
	#if inst[:3]=='sub':
	if GetMnem(head)=='sub' and GetOperandValue(head,0) == 4:  # rsp
		return True
	return False	

def getCanaryLocation(head):
	#print GetOperandValue(head,0)
	#print GetOperandValue(head,1)
	#print GetOperandValue(head,2)
	#print GetOperandValue(head,3)
	return  GetOperandValue(head,0)

def getCanaryLocation_rbp(head):
	return  (-GetOperandValue(head,0))&0xffffffff

def isLoadStackCanary(disasm,head):
	if 'mov' in disasm and 'gs' in disasm:
		if GetOperandValue(head,1) == 40:
			print disasm
			return True
	return False

def isSaveStackCanary(disasm):
	if 'mov' in disasm and 'rsp' in disasm:
		print disasm
		return 1
	if 'mov' in disasm and 'rbp' in disasm:
		print disasm
		return 2
	return False 

def get_num_saved_registers(func):
	'''
	check whether stack canary exists and get parameter related to the stack frame
	returns: num_saved_registers, canary_location, canary_type
	'''
	stack_size=0
	seen_stack_canary = 0
	num_saved_registers = 0
	canary_location = -1
	canary_type = ''
	print hex(func.startEA)
	for (startea,endea) in Chunks(func.startEA):
	#for head in Heads(func.startEA, func.endEA):
		for head in Heads(startea, endea):
			disasm=GetDisasm(head)
			if isPush(disasm):
				num_saved_registers+=1
				print disasm
			if isSubRsp(head):
				print disasm
				stack_size=GetOperandValue(head,1)
				# TODO
			if seen_stack_canary==0:
				if isLoadStackCanary(disasm,head):
					seen_stack_canary = 1
					continue
			if seen_stack_canary==1:
				res = isSaveStackCanary(disasm)
				assert res!=False
				if res==1:# rsp canary
					canary_type = 'rsp'
					canary_location = getCanaryLocation(head)	
				if res==2:#rbp canary
					canary_type = 'rbp'
					canary_location = getCanaryLocation_rbp(head)
				seen_stack_canary = 2
				return num_saved_registers, canary_location, canary_type, stack_size

	return num_saved_registers, canary_location, canary_type, stack_size

def analyze_one_xref(ea):
	print '-'*79
	call_site = ea[0]
	func = ea[1]
	frame_size = ea[2]
	num_saved_registers, canary_location, canary_type, stack_size= get_num_saved_registers(func)
	data_flow_sig, reversed_instruction = get_data_flow_sig(call_site, func)
	print num_saved_registers, canary_location, canary_type\
			, get_func_name(call_site), data_flow_sig, reversed_instruction, stack_size
	return num_saved_registers, canary_location, canary_type\
			, get_func_name(call_site), data_flow_sig, reversed_instruction, stack_size

def main():
	global md
	output=[]
	info = idaapi.get_inf_structure()
	proc = info.procName
	if info.is_64bit():
		if proc == "metapc":
			md = Cs(CS_ARCH_X86, CS_MODE_64)
			md.detail = True
		else:
			assert(0)
	else:
		assert(0)
	stack_disclosure_gadgets = set()
	copy_to_user_addr=idc.LocByName('_copy_to_user')
	xref_copy_to_user=get_func_code_refs_to(copy_to_user_addr)#copy_to_user
	#xref_copy_to_user=get_func_code_refs_to(0xFFFFFFFF81375160)#copy_to_user
	#xref_copy_to_user=get_func_code_refs_to(0xFFFFFFFF81154E80)#copy_to_user
	#xref_copy_to_user=get_func_code_refs_to(0xffffffff81496f70)#copy_to_user
	for ea in xref_copy_to_user:
		num_saved_registers, canary_location, canary_type, func_name\
			, data_flow_sig, reversed_instruction, stack_size = analyze_one_xref(ea)
		output.append([num_saved_registers, canary_location, canary_type, func_name, data_flow_sig, reversed_instruction,stack_size])
	#dump to result	
	num_of_disclosure_gadget=0
	for _ in output:
		if _[2]!='':  # has canary
			num_of_disclosure_gadget+=1

	print 'there are %d disclosure gadget'%(num_of_disclosure_gadget)
	the_filename="res_disclosure.txt"
	with open(the_filename, 'wb') as f:
   		pickle.dump(output, f)

if __name__=='__main__':
	main()