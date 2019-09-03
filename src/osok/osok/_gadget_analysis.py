from pwn import *
import pickle
from IPython import embed

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


class GadgetAnalysisMixin:
    def get_prologue_disclosure_pairs(self):
        """
        get paired prologue and disclosure gadget
        :return:
        """
        """
        fake stack gadget:
        has_canary, has_indirect_call, num_saved_registers, canary_type ,canary_location, funcname, funcea, stack_size]
        
        disclosure gadget:
        num_saved_registers, canary_location, canary_type, func_name, data_flow_sig, reversed_instruction, stack_size
        """
        fake_stack_gadgets = self.fake_stack_gadgets
        disclosure_gadgets = self.disclosure_gadgets
        res = []
        for fake_stack_gadget in fake_stack_gadgets:
            for disclosure_gadget in disclosure_gadgets:
                # have the same number of saved of registers
                if fake_stack_gadget[2] == disclosure_gadget[0]:
                    # has the same canary type and not none
                    if fake_stack_gadget[3] == disclosure_gadget[2] and fake_stack_gadget[3] != '':
                        # if fake_stack_gadget[3] == 'rsp' and fake_stack_gadget[4] < disclosure_gadget[1] \
                                #and (fake_stack_gadget[4] - disclosure_gadget[1]) == -8:
                        if fake_stack_gadget[3].decode('utf-8') == 'rsp' and fake_stack_gadget[4] == disclosure_gadget[1] - 8 \
                                and fake_stack_gadget[2] == disclosure_gadget[0]:
                                res.append([fake_stack_gadget, disclosure_gadget])
                        if self.consider_rbp_disclosure_prologue_pair:  # consider rbp disclosure prologue pair
                            if fake_stack_gadget[3].decode('utf-8') == 'rbp' and fake_stack_gadget[4] == disclosure_gadget[1]:
                                if fake_stack_gadget[7] + 8 == disclosure_gadget[6]:
                                    res.append([fake_stack_gadget, disclosure_gadget])
                                # res.append([fake_stack_gadget,disclosure_gadget])
        print('there are %d pairs of gadgets:' % (len(res)))
        if len(res) == 0:
            embed()
        return res


    def analyze_disclosure_gadget_data_flow_signature(self, disclosure_gadget):
        interested_opnd = ['rdi', 'edi', 'rsi', 'esi', 'rdx', 'edx']
        data_flow_sig = disclosure_gadget[4]
        reversed_instructions = disclosure_gadget[5]
        hotmap = [0, 0, 0]
        sub_gadget_entry = [0, 0, 0]
        cnt = 1
        for sig in data_flow_sig:
            if sig['type'] == MOV_MEM_TO_REG or sig['type'] == MOV_IMM_TO_REG or sig['type'] == MOV_REG_TO_REG:
                if sig['dst'] in interested_opnd:
                    if sig['dst'] in ['rdi', 'edi']:
                        if not hotmap[0]:
                            sub_gadget_entry[0] = sig['addr']
                            hotmap[0] = cnt
                            cnt += 1
                    elif sig['dst'] in ['rsi', 'esi']:
                        if not hotmap[1]:
                            sub_gadget_entry[1] = sig['addr']
                            hotmap[1] = cnt
                            cnt += 1
                    elif sig['dst'] in ['rdx', 'edx', 'dh', 'dl']:
                        if not hotmap[2]:
                            sub_gadget_entry[2] = sig['addr']
                            hotmap[2] = cnt
                            cnt += 1
                    # print(sig)

            if sig['type'] == LEA_MEM_TO_REG:
                if sig['dst'] in interested_opnd:
                    if sig['dst'] in ['rsi', 'esi']:
                        if not hotmap[1]:
                            sub_gadget_entry[1] = sig['addr']
                            hotmap[1] = cnt
                            cnt += 1
                    if sig['dst'] in ['rdi', 'edi']:
                        if not hotmap[0]:
                            sub_gadget_entry[0] = sig['addr']
                            hotmap[0] = cnt
                            cnt += 1
        return hotmap, sub_gadget_entry


    def analyze_disclosure_gadget(self, disclosure_gadget):
        saved_registers = disclosure_gadget[0]
        canary_offset = disclosure_gadget[1]
        canary_type = disclosure_gadget[2]
        func_name = disclosure_gadget[3]
        data_flow_sig = disclosure_gadget[4]
        reversed_instructions = disclosure_gadget[5]
        # for instruction in reversed_instructions:
        # head = instruction[0]
        # raw_bytes = instruction[1]
        # capstone_disasm = self.md.disasm(raw_bytes, head)
        # inst = capstone_disasm.next()#only one instruction here
        # mnem = inst.mnemonic
        # op_str = inst.op_str
        hotmap, sub_gadget_entry = self.analyze_disclosure_gadget_data_flow_signature(disclosure_gadget)
        return hotmap, sub_gadget_entry


    def load_gadgets(self):
        disclosure_gadget_path = self._gadget_path + '/res_disclosure.txt'
        fake_stack_gadget_path = self._gadget_path + '/res_fake_stack.txt'
        smash_gadget_path = self._gadget_path + '/res_smash.txt'
        bloom_gadget_path = self._gadget_path + '/bloom_gadget.txt'
        fork_gadget_path = self._gadget_path + '/fork_gadget.txt'
        relay_gadget_path = self._gadget_path + '/relay_gadget.txt'

        self.disclosure_gadgets = pickle.load(open(disclosure_gadget_path, 'rb'), encoding='bytes')
        self.fake_stack_gadgets = pickle.load(open(fake_stack_gadget_path, 'rb'), encoding='bytes')
        self.smash_gadgets = pickle.load(open(smash_gadget_path, 'rb'), encoding='bytes')
        self.bloom_gadgets = pickle.load(open(bloom_gadget_path, 'rb'), encoding='bytes')
        self.fork_gadgets = pickle.load(open(fork_gadget_path, 'rb'), encoding='bytes')
        try:
            self.relay_gadgets = pickle.load(open(relay_gadget_path, 'rb'), encoding='bytes')
        except:
            print('no relay gadget, pass')
