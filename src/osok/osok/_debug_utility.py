"""
filename: _debug_utility.py
author: ww9210
"""
import angr
import colorama
import socket
import errno
import traceback
import time
from IPython import embed


class DebugUtilityMixin:
    def dump_stack(self, state, size_in_qword=10):
        """
        dump current stack content from rsp
        :param state: the state to dump
        :param size_in_qword: length to dump in qword
        :return: None
        """
        try:
            current_rsp = state.se.eval(state.regs.rsp)
            addr_to_print = current_rsp
            for i in range(size_in_qword):
                value = state.se.eval(state.memory.load(addr_to_print, 8).reversed)
                print hex(value)
                addr_to_print += 8
        except all as e:
            print e
            traceback.print_exc()
            embed()

        return

    def debug_state(self, state, save_memory=True):
        b = self.b
        print '*** debugging info of state:', state, '***'
        try:
            if not save_memory:
                irsb = b.factory.block(state.addr).vex
                cap = b.factory.block(state.addr).capstone
                irsb.pp()
                cap.pp()
            self.dump_reg(state)
        except angr.errors.SimEngineError as e:
            print e.args, e.message
            print 'angr.errors.SimEngineError'
            pass
        return

    def dump_reg(self, state):
        print 'rax:', state.regs.rax, 'r8', state.regs.r8
        print 'rbx:', state.regs.rbx, 'r9', state.regs.r9
        print 'rcx:', state.regs.rcx, 'r10', state.regs.r10
        print 'rdx:', state.regs.rdx, 'r11', state.regs.r11
        print 'rsi:', state.regs.rsi, 'r12', state.regs.r12
        print 'rdi:', state.regs.rdi, 'r13', state.regs.r13
        print 'rsp:', state.regs.rsp, 'r14', state.regs.r14
        print 'rbp:', state.regs.rbp, 'r15', state.regs.r15
        print 'gs:', state.regs.gs
        return

    def debug_simgr(self, simgr, save_memory=True):
        print 'there are %d active states of this simgr:' % len(simgr.active)
        if not save_memory:
            for i, state in enumerate(simgr.stashes['active']):
                print "%dth state:" % i, state
                self.debug_state(state, save_memory)
        return

    def draw_progress_bar(self, cur, total_len, filename='progress_bar.txt'):
        percent = int(float(cur)/float(total_len) * 100)
        ts = int(time.time())
        bar = str(ts)+'\n'
        bar += str(cur) + '/' + str(total_len) + '\n'
        bar += percent * '=' + (100-percent)*'-' + '\n'
        if self.lock is not None:
            self.lock.acquire()
        with open(filename, 'a') as f:
            f.write(bar)
        if self.lock is not None:
            self.lock.release()
        return True

    def is_port_in_use(self, port_number):
        in_use = False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port_number))
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                print("Port %d is already in use" % port_number)
                in_use = True
            else:
                # something else raised the socket.error exception
                print(e)
                raise
        s.close()
        return in_use


