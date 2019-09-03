from idautils import *
from idaapi import *
from capstone import *
import pickle
import traceback
isdebug=True
isdebug=False

md=None

def dbg(content):
	if isdebug:
		print '[+]', content

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

def is_indirect_call(head):
	isIndirect=False
	disasm=GetDisasm(head)
	if 'vm' in disasm:
		return False
	if ItemSize(head)<=3:
		isIndirect=True
		return isIndirect
	if '_indirect_thunk' in disasm:
		isIndirect=True
	return isIndirect

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
	
def get_indirect_jmp_target_register(head):
	target_reg=None
	disasm=GetDisasm(head)
	if '_indirect_thunk' in disasm:
		tmp= disasm.split('_')[-1]
		if tmp=='start':
			tmp='rax'
		return tmp
	inst_bytes = idc.GetManyBytes(head, ItemSize(head))
	capstone_disasm = md.disasm(inst_bytes, head)
	inst = capstone_disasm.next()
	opndstr = inst.op_str
	num_of_opnds = len(inst.operands)
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
		target_reg = dstreg
	return target_reg

def is_indirect_jump(head):
	isIndirect=False
	inst_bytes = idc.GetManyBytes(head, ItemSize(head))
	if inst_bytes[0]=='\xff' and len(inst_bytes)<=3:
		isIndirect=True
	return isIndirect
	#capstone_disasm = md.disasm(inst_bytes,head)
	#inst = capstone_disasm.next() #only one instruction here

def is_mov_or_lea(mnem):
	if 'mov' in mnem:
		return True
	if 'lea' in mnem and 'leave' not in mnem:
		return True
	return False

def is_call(mnem):
	if 'call' in mnem and mnem != 'vmcall':
		return True
	return False

def is_jump(mnem):
	if 'jmp' in mnem:
		return True
	return False

def is_xor(mnem):
	if 'xor' == mnem:
		return True
	return False

def analyze_mov_or_lea(head, interested_reg_value, tracked_register):
	inst_bytes = idc.GetManyBytes(head, ItemSize(head))
	capstone_disasm = md.disasm(inst_bytes,head)
	try:
		inst = capstone_disasm.next() #only one instruction here
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
	#print hex(head), ItemSize(head)
	inst_bytes = idc.GetManyBytes(head, ItemSize(head))
	capstone_disasm = md.disasm(inst_bytes,head)
	try:
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
	except:
		print 'wtf simgr error'
		traceback.print_exc()
	return 

def is_parameter_blooming(interested_reg_value,tracked_register,target_reg=None):
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
	if bloom_num >= len(tracked_register)+2:
		return True
	else:
		return False


def is_blooming_gadget_type_rdi(funcea):
	'''
	input: function address
	output: whether the function would be used to bloom 
	algorithm: for each call site 
	'''	
	tracked_register=['rdi']
	bloom_site=None
	func=get_func(funcea)
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

	fc = idaapi.FlowChart(func)
	seen_call=False
	#iterate over the instructions and update the register states
	for block in fc:
		for head in Heads(block.startEA, block.endEA):
			mnem = GetMnem(head)	
			#print mnem
			if is_mov_or_lea(mnem):
				analyze_mov_or_lea(head,interested_reg_value,tracked_register)
			elif is_xor(mnem):
				analyze_xor(head,interested_reg_value)
			elif is_call(mnem):
				if '__fentry__' not in GetDisasm(head) and '__stack_chk_fail' not in GetDisasm(head):
					seen_call=True
				if is_indirect_call(head):
					target_reg=get_indirect_call_target_register(head)
					if is_parameter_blooming(interested_reg_value,tracked_register,target_reg):
						return [True, head, interested_reg_value]
			elif is_jump(mnem):
				if is_indirect_jump(head):
					seen_call=True
					target_reg=get_indirect_jmp_target_register(head)
					if is_parameter_blooming(interested_reg_value,tracked_register,target_reg):
						return [True, head, interested_reg_value]
		if seen_call:
			break



	return False

def main():
	global md
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.detail = True
	num_analyzed_function = 0
	bloom_gadget=[]
	for segea in Segments():
		for funcea in Functions(segea, SegEnd(segea)):
			num_analyzed_function+=1
			res = is_blooming_gadget_type_rdi(funcea)
			if res != False:
				call_site = res[1]
				reg_state = res[2]
				mnem = GetDisasm(funcea)
				func_name = get_func_name(funcea)
				print '='*80
				print hex(funcea)
				print func_name
				print hex(call_site)
				#print reg_state
				for key in reg_state:
					if reg_state[key]=='rdi':
						print key,
				print ''
				bloom_gadget.append([funcea, func_name, call_site, reg_state])

	print 'there are %d blooming gadget'%(len(bloom_gadget))
	the_filename="bloom_gadget.txt"
	with open(the_filename, 'wb') as f:
   		pickle.dump(bloom_gadget, f)

if __name__ == '__main__':
	main()