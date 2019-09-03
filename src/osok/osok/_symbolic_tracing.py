import traceback
import angr


class SymbolicTracingMixin:
    def normalize_history_bbl_addrs(self, bbl_addrs):
        """
        remove some false bbl addrs
        :param bbl_addrs: bbl_addrs of history
        :return: new list of bbl_addrs
        """
        good_bbl_addrs = []
        previous_block = None
        for i, addr in enumerate(bbl_addrs):
            if i == 0:
                good_bbl_addrs.append(addr)
            elif addr in previous_block.instruction_addrs:
                continue
            else:
                good_bbl_addrs.append(addr)
            block = self.b.factory.block(addr)
            previous_block = block

        return list(good_bbl_addrs)

    def run_symbolic_tracing_to_first_fork_site(self, state, bloom_gadget, forking_gadget, history_bbl_addrs\
                                                , first_constraint_func=None):
        """
        symbolic tracing to reach the first fork site, return a state prior to first forking for further exploiration
        :param state:
        :param bloom_gadget:
        :param forking_gadget:
        :param history_bbl_addrs:
        :param first_constraint_func:
        :return:
        """
        the_chosen_state = None
        bbl_addrs = list(history_bbl_addrs)
        #bbl_addrs = bbl_addrs[1:]
        # normalize_history basic block address to fix stupid bugs
        bbl_addrs = self.normalize_history_bbl_addrs(bbl_addrs)
        print 'run symbolic tracing to forking site using the following trace:',
        for bbladdr in bbl_addrs:
            print hex(bbladdr),
        print ' '

        if first_constraint_func is not None:
            bloom_entry, bloom_site = self.get_blooming_gadget_entry_and_site(bloom_gadget)
            print 'apply first constraint func to bloom entry:', hex(bloom_entry)
            first_constraint_func(state, bloom_entry)

        if self.use_controlled_data_concretization:
            self.add_concretization_strategy_controlled_data(state)

        state.register_plugin('osoktracing', angr.state_plugins.OsokTracing(history_bbl_addrs=bbl_addrs\
                                                                            , current_bbl_idx=0))
        simgr = self.b.factory.simgr(state, save_unconstrained=True)
        loop_idx = 0
        max_loop_idx = len(bbl_addrs)
        next_expected_bbl_addr = bbl_addrs[loop_idx]
        while True:
            print '[+] ' + str(loop_idx) + ' step()'
            try:
                print '[+] stepping...'
                if len(simgr.active) == 0:
                    print '[-] no active states left, wtf'
                    #import IPython; IPython.embed()
                simgr.stashes['deadended'] = []
                print 'active(before)', simgr.active
                simgr.step(stash='active')
                print 'active(after)', simgr.active
                print 'simgr(after)', simgr
                #import IPython; IPython.embed()
                #loop_idx += 1
                for active_state in simgr.stashes['active']:
                    active_state.osoktracing.current_bbl_idx = loop_idx
                next_expected_bbl_addr = bbl_addrs[loop_idx]
                print 'next_expected_bbl_addr %x' % (next_expected_bbl_addr)
                simgr.move(from_stash='active', to_stash='deadended', filter_func=\
                    lambda s: s.addr != s.osoktracing.history_bbl_addrs[s.osoktracing.current_bbl_idx])
                if simgr.unconstrained:  # found unconstrained state
                    print 'there are %d unconstrained' % (len(simgr.unconstrained))
                    for ucstate in simgr.unconstrained:
                        ucstate.add_constraints(ucstate.regs.rip == next_expected_bbl_addr)
                        if ucstate.satisfiable():
                            simgr.move(from_stash='unconstrained', to_stash='active', filter_func=\
                                   lambda s: s == ucstate)
                        else:
                            print 'unsatisfiable'
                            simgr.move(from_stash='unconstrained', to_stash='deadended',\
                                       filter_func=lambda s: s == ucstate)
                loop_idx += 1
                #import IPython; IPython.embed()
            except:
                print 'wtf simgr error'
                traceback.print_exc()
                raw_input()
                del simgr
                return
            #if loop_idx == max_loop_idx-1:
            if loop_idx == max_loop_idx:
                print'tracing ended...'
                #import IPython; IPython.embed()
                try:
                    the_chosen_state = simgr.active[0].copy()
                except:
                    traceback.print_exc()
                    #import IPython; IPython.embed()
                del simgr
                return the_chosen_state