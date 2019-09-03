"""
filename: _symbolic_tracing.py
Author: Wei Wu (ww9210)
"""
import traceback
import angr
from IPython import embed


class SymbolicTracingMixin:
    def normalize_history_bbl_addrs(self, bbl_addrs, forking_gadget):
        """
        remove some false bbl addrs
        :param bbl_addrs: bbl_addrs of history
        :return: new list of bbl_addrs
        """
        first_fork_site = forking_gadget[2][0][1]
        second_fork_site = forking_gadget[2][1][1]

        # get last basic block of the trace
        last_bbl_addr = bbl_addrs[-1]

        if last_bbl_addr == first_fork_site:
            # check if this basic block contains indirect call
            jump_target_set = self.b.factory.block(first_fork_site).vex.constant_jump_targets
            if len(jump_target_set) > 0:
                # if is direct jump, append its target to our trace
                e = next(iter(jump_target_set))
                bbl_addrs.append(e)

        elif last_bbl_addr == second_fork_site:
            # check if this basic block contains indirect call
            jump_target_set = self.b.factory.block(second_fork_site).vex.constant_jump_targets
            if len(jump_target_set) > 0:
                # if is direct jump, append its target to our trace
                e = next(iter(jump_target_set))
                bbl_addrs.append(e)
        else:
            print('strange state')
            assert 0
        if bbl_addrs[0] is None:
            bbl_addrs = bbl_addrs[1:]
        good_bbl_addrs = []
        previous_block = None
        for i, addr in enumerate(bbl_addrs):
            if i == 0:
                good_bbl_addrs.append(addr)
            elif addr in previous_block.instruction_addrs:
                continue
            else:
                good_bbl_addrs.append(addr)
            try:
                block = self.b.factory.block(addr)
                previous_block = block
            except ValueError as e:
                print(e)
                embed()

        return list(good_bbl_addrs)

    def run_symbolic_tracing_to_first_fork_site(self, state, bloom_gadget, forking_gadget, history_bbl_addrs
                                                , first_constraint_func=None):
        """
        symbolic tracing to reach the first fork site, return a state prior to first forking for further exploration
        We normalize the path history to remove some duplicated entries.
        we also add *concretization strategy*, to concretize symbolic address to memory region under our control
        We use a state plugin to help symbolic tracing.
        :param state:
        :param bloom_gadget:
        :param forking_gadget:
        :param history_bbl_addrs:
        :param first_constraint_func:
        :return:
        """
        the_chosen_state = None
        bbl_addrs = list(history_bbl_addrs)
        print('[+] the raw trace is:',)
        for bbladdr in bbl_addrs:
            if bbladdr is None:
                continue
            else:
                print(hex(bbladdr),)
        print(' ')

        # normalize_history basic block address to fix stupid bugs
        bbl_addrs = self.normalize_history_bbl_addrs(bbl_addrs, forking_gadget)

        print('[+] run symbolic tracing to forking site using the following trace:',)
        for bbladdr in bbl_addrs:
            print(hex(bbladdr),)
        print(' ')

        if first_constraint_func is not None:
            bloom_entry, bloom_site = self.get_blooming_gadget_entry_and_site(bloom_gadget)
            print('apply first constraint func to bloom entry:', hex(bloom_entry))
            first_constraint_func(state, bloom_entry)

        # instrument memory read and writes
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=self.track_reads)
        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=self.track_writes)

        if self.use_controlled_data_concretization:
            self.add_concretization_strategy_controlled_data(state)

        bbl_idx = 0
        # find the correct start idx
        current_addr = state.addr
        print('[+] Initial address is %x' % current_addr)
        for i, visited_addr in enumerate(bbl_addrs):
            if visited_addr == current_addr:
                bbl_idx = i

        state.register_plugin('osoktracing', angr.state_plugins.OsokTracing(history_bbl_addrs=bbl_addrs
                                                                            , current_bbl_idx=bbl_idx))
        simgr = self.b.factory.simgr(state, save_unconstrained=True)
        max_loop_idx = len(bbl_addrs)
        while True:
            print('[+] ' + str(bbl_idx) + ' step()')
            try:
                print('[+] stepping...')

                if len(simgr.active) == 0:
                    print('[-] no active states left, wtf')

                simgr.stashes['deadended'] = []

                print('active(before)', simgr.active)

                # stepping
                simgr.step(stash='active')
                print('active(after)', simgr.active)
                print('simgr(after)', simgr)

                # update state idx
                bbl_idx += 1
                if bbl_idx == max_loop_idx:
                    print('tracing ended, return the unconstrained state...')
                    # import IPython; IPython.embed()
                    try:
                        #the_chosen_state = simgr.active[0].copy()
                        the_chosen_state = simgr.unconstrained[0].copy()
                    except IndexError as e:
                        print(e)
                        print('The unconstrained stash is empty, wtf')
                        the_chosen_state = None
                        # embed()
                    del simgr
                    return the_chosen_state

                for active_state in simgr.stashes['active']:
                    active_state.osoktracing.current_bbl_idx = bbl_idx
                try:
                    next_expected_bbl_addr = bbl_addrs[bbl_idx]
                    print('next_expected_bbl_addr is %x' % next_expected_bbl_addr)
                except IndexError as e:
                    print(e)
                    embed()
                    assert 0

                # moving unmatched state to dead-end stash
                simgr.move(from_stash='active', to_stash='deadended', filter_func=
                           lambda s: s.addr != s.osoktracing.history_bbl_addrs[s.osoktracing.current_bbl_idx])

                if simgr.unconstrained:  # found unconstrained state
                    print('there are %d unconstrained' % (len(simgr.unconstrained)))
                    for ucstate in simgr.unconstrained:
                        # add constraints to follow basic block indicated by the previous path
                        ucstate.add_constraints(ucstate.regs.rip == next_expected_bbl_addr)
                        if ucstate.satisfiable():
                            simgr.move(from_stash='unconstrained', to_stash='active', filter_func=
                                       lambda s: s == ucstate)
                        else:
                            print('unsatisfiable')
                            simgr.move(from_stash='unconstrained', to_stash='deadended',
                                       filter_func=lambda s: s == ucstate)
            except all as e:
                print(e)
                print('wtf simgr error')
                traceback.print_exc()
                input()
                del simgr
                return
