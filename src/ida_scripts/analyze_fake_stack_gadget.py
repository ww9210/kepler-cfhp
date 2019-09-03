from idautils import *
from idaapi import *
from capstone import *
import pickle
isdebug=False
md=None
def is_xor(mnem):
	if 'xor' == mnem:
		return True
	return False
def fix_reg_name_alias(regname):
	reg_name_dict={\
		'rdi':'rdi'
		,'edi':'rdi'
		,'di':'rdi'
		,'rsi':'rsi'
		,'esi':'rsi'
		,'si' :'rsi'
		,'rdx':'rdx'
		,'edx':'rdx'
		,'dx':'rdx'
		,'dl':'rdx'
		,'dh':'rdx'
		,'rcx':'rcx'
		,'ecx':'rcx'
		,'cx':'rcx'
		,'cl':'rcx'
		,'ch':'rcx'
		,'rax':'rax'
		,'eax':'rax'
		,'ax':'rax'
		,'al':'rax'
		,'ah':'rax'
		,'rbx':'rbx'
		,'ebx':'rbx'
		,'bx':'rbx'
		,'bl':'rbx'
		,'bh':'rbx'
		,'r8':'r8'
		,'r8d':'r8'
		,'r9':'r9'
		,'r9d':'r9'
		,'r10':'r10'
		,'r10d':'r10'
		,'r11':'r11'
		,'r11d':'r11'
		,'r12':'r12'
		,'r12d':'r12'
		,'r13':'r13'
		,'r13d':'r13'
		,'r14':'r14'
		,'r14d':'r14'
		,'r15':'r15'
		,'r15d':'r15'
		,'rbp':'rbp'
		,'ebp':'rbp'
	}
	if regname in reg_name_dict:
		return reg_name_dict[regname]
	else:
		return regname

def dbg(content):
	if isdebug:
		print '[+]', content

def isSubRsp(head):
	#if inst[:3]=='sub':
	if GetMnem(head)=='sub' and GetOperandValue(head,0) == 4:  # rsp
		return True
	return False
def isPush(inst):
	if inst[:4]=='push':
		return True
	else:
		return False

def isLoadStackCanary(disasm,head):
	if 'mov' in disasm and 'gs:' in disasm:
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

def getCanaryLocation(head):
	return GetOperandValue(head, 0)

def getCanaryLocation_rbp(head):
	return (-GetOperandValue(head, 0)) & 0xffffffff

def check_one_function(func):
	#check one function to see if it is fake stack prologue function
	canary_type=None
	canary_location=None
	seen_stack_canary=False
	has_canary=False
	has_indirect_call=False
	num_saved_registers=0
	inprologue=True
	fc = idaapi.FlowChart(get_func(func))
	for block in fc:
		for head in Heads(block.startEA, block.endEA):
			disasm=GetDisasm(head)
			if isPush(disasm) and inprologue:
				num_saved_registers+=1
				#print disasm
			if seen_stack_canary==0:
				if isLoadStackCanary(disasm,head):
					seen_stack_canary = 1
					has_canary=True
					continue
			if seen_stack_canary==1:
				res = isSaveStackCanary(disasm)
				if res==False:
					print GetFunctionName(func)
					assert 0
				if res==1:# rsp canary
					canary_type = 'rsp'
					canary_location = getCanaryLocation(head)	
				if res==2:# rbp canary
					canary_type = 'rbp'
					canary_location = getCanaryLocation_rbp(head)
				seen_stack_canary = 2
			if 'call' in GetMnem(head):
				#inst_bytes = idc.GetManyBytes(head, ItemSize(head))
				if ItemSize(head)<=3:
					has_indirect_call=True
		inprologue=False
		break #remove this to be more permissive
	return has_canary, has_indirect_call, num_saved_registers, canary_type, canary_location

def isIndirectCall(head):
	isIndirect = False
	if ItemSize(head) <= 3:
		isIndirect = True
		return isIndirect
	disasm = GetDisasm(head)
	if '_indirect_thunk' in disasm:
		isIndirect = True
	return isIndirect

def analyze_mov_or_lea(head, interested_reg_value, tracked_register):
	inst_bytes = idc.GetManyBytes(head, ItemSize(head))
	capstone_disasm = md.disasm(inst_bytes,head)
	try:
		inst = capstone_disasm.next()  # only one instruction here
	except:
		print 'fail disassembly'
		return
	opndstr = inst.op_str
	num_of_opnds = len(inst.operands)
	if num_of_opnds!=2:
		print hex(head),inst.mnemonic,opndstr
		#assert(0)
		return
	src = inst.operands[1]
	dst = inst.operands[0]
	dbg(inst.mnemonic+' '+inst.op_str)
	dbg('src type: '+str(src.type))
	dbg('dst type: '+str(dst.type))
	if dst.type == 1:#dst is reg
		dstreg = inst.reg_name(dst.reg)
		dstreg = fix_reg_name_alias(dstreg)
		if dstreg not in interested_reg_value:
			return
		if src.type == 1:#src is reg
			srcreg = inst.reg_name(src.reg)
			srcreg = fix_reg_name_alias(srcreg)
			if srcreg in interested_reg_value:
				interested_reg_value[dstreg]=interested_reg_value[srcreg]
			else:
				interested_reg_value[dstreg]=None
		elif src.type == 2:#src is imm
			interested_reg_value[dstreg]=None
		elif src.type == 3:
			src_base = inst.reg_name(src.mem.base)
			src_disp = src.mem.disp
			src_index = src.mem.index
			src_index_reg = ''
			if src_index != 0:
				src_index_reg = inst.reg_name(src_index)
			src_scale = src.mem.scale
			src_segment = src.mem.segment
			dbg(src_base+str(src_disp)+src_index_reg+str(src_scale)+ str(src_segment))
			dbg(hex(head))
			src_base = fix_reg_name_alias(src_base)
			if src_base in interested_reg_value:
				interested_reg_value[dstreg]=interested_reg_value[src_base]
			else:
				interested_reg_value[dstreg]=None
			#print src.mem,'->',dstreg

	elif dst.type == 2:#dst is immediate
		assert(0)
	elif dst.type == 3:#dst is memory, give up
		return
	return	

def analyze_xor(head,interested_reg_value):
	inst_bytes = idc.GetManyBytes(head, ItemSize(head))
	capstone_disasm = md.disasm(inst_bytes,head)
	inst = capstone_disasm.next() #only one instruction here
	opndstr = inst.op_str
	num_of_opnds = len(inst.operands)
	assert(num_of_opnds==2)
	src = inst.operands[1]
	dst = inst.operands[0]
	dbg(inst.mnemonic+' '+inst.op_str)
	if src.type == 1 and dst.type == 1:
		if dst.reg == src.reg:
			dstreg = inst.reg_name(dst.reg)
			dstreg = fix_reg_name_alias(dstreg)
			if dstreg in interested_reg_value:
				interested_reg_value[dstreg]=None

	return

def is_mov_or_lea(mnem):
	if 'mov' in mnem:
		return True
	if 'lea' in mnem and 'leave' not in mnem:
		return True
	return False

def get_indirect_call_target_register(head):
	target_reg=None
	disasm=GetDisasm(head)
	if '_indirect_thunk' in disasm:
		tmp= disasm.split('_')[-1]
		if tmp=='start':
			tmp='rax'
		return tmp
	inst_bytes = idc.GetManyBytes(head, ItemSize(head))
	capstone_disasm = md.disasm(inst_bytes, head)
	inst=None
	try:
		inst = capstone_disasm.next() #only one instruction here
	except:
		return target_reg

	opndstr = inst.op_str
	num_of_opnds = len(inst.operands)
	#assert(num_of_opnds==1)
	if(num_of_opnds!=1):
		print hex(head)
		print disasm
		assert(0)	
	
	dst = inst.operands[0]
	if dst.type == 1: #dst is reg
		dstreg=inst.reg_name(dst.reg)
		target_reg=dstreg
	elif dst.type == 2:
		assert(0)
	elif dst.type == 3:
		dstreg = inst.reg_name(dst.mem.base)
		target_reg=dstreg
	return target_reg

def is_parameter_blooming(interested_reg_value,tracked_register,target_reg=None,permissive=True):
	bloom_num = 0
	if target_reg!=None and target_reg not in interested_reg_value:
		print target_reg
		#assert 0
		return False
	if target_reg!=None and interested_reg_value[target_reg] not in tracked_register:
		return False
	for reg in interested_reg_value:
		if interested_reg_value[reg] in tracked_register:
			bloom_num += 1
	if permissive:
		return True
	else:
		if bloom_num >= len(tracked_register)+2:
			return True
		else:
			return False


def check_one_function_v2(func, only_check_first_block=True):
	# check one function to see if it is fake stack prologue function
	tracked_register = ['rdi', 'rsi','rdx']
	interested_reg_value = {'rdi': 'rdi'
		, 'rsi': 'rsi'
		, 'rdx': 'rdx'
		, 'rcx': 'rcx'
		, 'r8': 'r8'
		, 'r9': 'r9'
		, 'r10': 'r10'
		, 'r11': 'r11'
		, 'r12': 'r12'
		, 'r13': 'r13'
		, 'r14': 'r14'
		, 'r15': 'r15'
		, 'rax': 'rax'
		, 'rbx': 'rbx'
		, 'rbp': 'rbp'
		# ,'rsp':'rsp'\
	}
	canary_type = None
	canary_location = None
	seen_stack_canary = 0
	seencall = False
	has_canary = False
	has_indirect_call = False
	num_saved_registers = 0
	stack_size = 0
	inprologue = True
	fc = idaapi.FlowChart(get_func(func))
	for block in fc:
		for head in Heads(block.startEA, block.endEA):
			if inprologue:
				disasm=GetDisasm(head)
				mnem = GetMnem(head)
				if is_mov_or_lea(mnem):
					analyze_mov_or_lea(head,interested_reg_value,tracked_register)
				elif is_xor(mnem):
					analyze_xor(head,interested_reg_value)

				if isPush(disasm) and inprologue:
					num_saved_registers += 1
					# print disasm
				if isSubRsp(head) and inprologue:
					stack_size = GetOperandValue(head, 1)
				if seen_stack_canary == 0:
					if isLoadStackCanary(disasm, head):
						seen_stack_canary = 1
						has_canary = True
						continue
				if seen_stack_canary == 1:
					res = isSaveStackCanary(disasm)
					if res is False:
						print GetFunctionName(func)
						assert 0
					if res == 1:  # rsp canary
						canary_type = 'rsp'
						canary_location = getCanaryLocation(head)	
					if res == 2:  # rbp canary
						canary_type = 'rbp'
						canary_location = getCanaryLocation_rbp(head)
					seen_stack_canary = 2
			if 'call' in GetMnem(head) and 'vmcall' != GetMnem(head):
				if '__fentry__' not in GetDisasm(head) and '__stack_chk_fail' not in GetDisasm(head):
					seencall = True
				else:
					continue
				if isIndirectCall(head):
					has_indirect_call = True
					target_reg = get_indirect_call_target_register(head)
					if is_parameter_blooming(interested_reg_value, tracked_register, target_reg):
						has_indirect_call = True
				break
		inprologue = False
		if seencall:
			break  # comment this to be more permissive
			pass
		if only_check_first_block:
			break
	return has_canary, has_indirect_call, num_saved_registers, canary_type, canary_location,stack_size

def check_one_function_v4(func):  # this is the most permissive version
	#check one function to see if it is fake stack prologue function
	tracked_register=['rdi','rsi','rdx']
	interested_reg_value={'rdi':'rdi'\
		,'rsi':'rsi'\
		,'rdx':'rdx'\
		,'rcx':'rcx'\
		,'r8':'r8'\
		,'r9':'r9'\
		,'r10':'r10'\
		,'r11':'r11'\
		,'r12':'r12'\
		,'r13':'r13'\
		,'r14':'r14'\
		,'r15':'r15'\
		,'rax':'rax'\
		,'rbx':'rbx'\
		,'rbp':'rbp'\
		#,'rsp':'rsp'\
	}
	canary_type = None
	canary_location = None
	seen_stack_canary = 0
	seencall = False
	has_canary = False
	has_indirect_call = False
	num_saved_registers = 0
	stack_size = 0
	inprologue = True  # indicating we are analyzing first basic block of this function
	fc = idaapi.FlowChart(get_func(func))
	for block in fc:
		for head in Heads(block.startEA, block.endEA):
			if inprologue:
				disasm = GetDisasm(head)
				mnem = GetMnem(head)
				if is_mov_or_lea(mnem):
					analyze_mov_or_lea(head,interested_reg_value,tracked_register)
				elif is_xor(mnem):
					analyze_xor(head,interested_reg_value)


				if isPush(disasm) and inprologue:
					num_saved_registers += 1
					#print disasm
				if isSubRsp(head) and inprologue:
					stack_size = GetOperandValue(head,1)
				if seen_stack_canary == 0:
					if isLoadStackCanary(disasm,head):
						seen_stack_canary = 1
						has_canary = True
						continue
				if seen_stack_canary == 1:
					res = isSaveStackCanary(disasm)
					if res is False:
						print GetFunctionName(func)
						assert 0
					if res == 1:  # rsp canary
						canary_type = 'rsp'
						canary_location = getCanaryLocation(head)	
					if res == 2:  # rbp canary
						canary_type = 'rbp'
						canary_location = getCanaryLocation_rbp(head)
					seen_stack_canary = 2
			if 'call' in GetMnem(head) and 'vmcall' != GetMnem(head):
				if '__fentry__' not in GetDisasm(head) and '__stack_chk_fail' not in GetDisasm(head):
					seencall = True
				else:
					continue #  what a nasty bug...
				if isIndirectCall(head):
					has_indirect_call = True
					target_reg = get_indirect_call_target_register(head)
					if is_parameter_blooming(interested_reg_value, tracked_register, target_reg):
						has_indirect_call = True
				break
		inprologue = False
		if seencall:
			#break#comment this to be more permissive
			pass
		#break #remove this to be more permissive
	return has_canary, has_indirect_call, num_saved_registers, canary_type, canary_location,stack_size


def check_one_function_v3(func):
	# this version is most rigrous and produce least candidates
	#check one function to see if it is fake stack prologue function
	tracked_register=['rdi','rsi','rdx']
	interested_reg_value={'rdi':'rdi'\
		,'rsi':'rsi'\
		,'rdx':'rdx'\
		,'rcx':'rcx'\
		,'r8':'r8'\
		,'r9':'r9'\
		,'r10':'r10'\
		,'r11':'r11'\
		,'r12':'r12'\
		,'r13':'r13'\
		,'r14':'r14'\
		,'r15':'r15'\
		,'rax':'rax'\
		,'rbx':'rbx'\
		,'rbp':'rbp'\
		#,'rsp':'rsp'\
	}
	canary_type=None
	canary_location=None
	seen_stack_canary=0
	seencall=False
	has_canary=False
	has_indirect_call=False
	num_saved_registers=0
	stack_size=0
	inprologue=True
	fc = idaapi.FlowChart(get_func(func))
	for block in fc:
		for head in Heads(block.startEA, block.endEA):
			if inprologue:
				disasm=GetDisasm(head)
				mnem = GetMnem(head)
				if is_mov_or_lea(mnem):
					analyze_mov_or_lea(head,interested_reg_value,tracked_register)
				elif is_xor(mnem):
					analyze_xor(head,interested_reg_value)


				if isPush(disasm) and inprologue:
					num_saved_registers+=1
					#print disasm
				if isSubRsp(head) and inprologue:
					stack_size=GetOperandValue(head,1)
				if seen_stack_canary==0:
					if isLoadStackCanary(disasm,head):
						seen_stack_canary = 1
						has_canary=True
						continue
				if seen_stack_canary==1:
					res = isSaveStackCanary(disasm)
					if res==False:
						print GetFunctionName(func)
						assert 0
					if res==1:# rsp canary
						canary_type = 'rsp'
						canary_location = getCanaryLocation(head)	
					if res==2:#rbp canary
						canary_type = 'rbp'
						canary_location = getCanaryLocation_rbp(head)
					seen_stack_canary = 2
			if 'call' in GetMnem(head) and 'vmcall' != GetMnem(head):
				if '__fentry__' not in GetDisasm(head) and '__stack_chk_fail' not in GetDisasm(head):
					seencall=True
				else:
					continue
				if isIndirectCall(head):
					target_reg=get_indirect_call_target_register(head)
					if is_parameter_blooming(interested_reg_value, tracked_register, target_reg):
						has_indirect_call=True
				break
		inprologue=False
		if seencall:
			break#comment this to be more permissive
			pass
		break #remove this to be more permissive
	return has_canary, has_indirect_call, num_saved_registers, canary_type, canary_location, stack_size


def main(only_check_first_block=True):
	# capstone setup
	global md
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.detail = True
	#output list
	output=[]
	rsp_gadget=0
	rbp_gadget=0
	num_analyzed_function=0
	num_indirect_function_without_stack_canary=0
	for segea in Segments():
		for funcea in Functions(segea, SegEnd(segea)):
			num_analyzed_function += 1
			#has_canary, has_indirect_call, num_saved_registers, canary_type\
				#,canary_location = check_one_function(funcea)
			#has_canary, has_indirect_call, num_saved_registers, canary_type\
				#,canary_location, stack_size = check_one_function_v2(funcea)
			#has_canary, has_indirect_call, num_saved_registers, canary_type\
				#,canary_location = check_one_function_v3(funcea)
			has_canary, has_indirect_call, num_saved_registers, canary_type\
				,canary_location, stack_size = check_one_function_v2(funcea, only_check_first_block=only_check_first_block)
			if has_canary and has_indirect_call:
				funcname = GetFunctionName(funcea)
				output.append([has_canary, has_indirect_call, num_saved_registers, canary_type
								,canary_location, funcname, funcea, stack_size])
				print funcname
			if not has_canary and has_indirect_call:
				num_indirect_function_without_stack_canary+=1
			if canary_type == 'rsp':
				rsp_gadget += 1
			elif canary_type == 'rbp':
				rbp_gadget += 1

	for candidate in output:
		print candidate[5]

	print 'analyzed %d functions' % num_analyzed_function
	print 'there are', len(output), 'candidates'
	print 'there are %d functions has indirect call but does not have canary' % (num_indirect_function_without_stack_canary)
	print '%d function uses rsp canary; %d function uses rbp canary' % (rsp_gadget, rbp_gadget)

	if only_check_first_block:
		the_filename="res_fake_stack.txt"
		with open(the_filename, 'wb') as f:
			pickle.dump(output, f)
	else:
		the_filename="res_fake_stack_extended.txt"
		with open(the_filename, 'wb') as f:
			pickle.dump(output, f)

if __name__=='__main__':
	main()
	main(only_check_first_block=False)
