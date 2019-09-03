import angr
import traceback
from IPython import embed
from .state_filters import *


class RelayGadgetMixin:
    def get_relay_gadget_entry_and_site(self, relay_gadget):
        return relay_gadget[0], relay_gadget[2]  # entry, site

    def run_relay_gadget(self, state, relay_gadget, first_constraint_func=None):
        res = False

        if self.use_controlled_data_concretization:  # use controlled_data_concretization
            # todo add relay specific symbolic region
            print('adding concretization strategy')
            self.add_concretization_strategy_controlled_data(state)

        relay_entry, relay_site = self.get_relay_gadget_entry_and_site(relay_gadget)

        # apply user-defined constraint
        if first_constraint_func is not None:
            first_constraint_func(state, relay_entry)
        #embed()

        # add instrumentation
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=self.track_reads)
        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=self.track_writes)
        self.dump_reg(state)


        # init simgr
        simgr = self.b.factory.simgr(state, save_unconstrained=True)
        self.debug_simgr(simgr)
        print(simgr.active)
        loop_idx = 0
        while True:
            print('[+] ' + str(loop_idx) + ' step()')
            try:
                # stepping
                simgr.step(stash='active')
                self.debug_simgr(simgr)
                print(simgr.active)
                simgr.move(from_stash='active', to_stash='deadended', filter_func=filter_bad_rip)
                loop_idx += 1
            except KeyboardInterrupt:
                raise
            except:
                print('wtf simgr error')
                traceback.print_exc()
                del simgr
                return

            # check whether we have unconstrained states
            if simgr.unconstrained:  # has unconstrained state
                for ucstate in simgr.unconstrained:
                    # angr do not know how to concretize return address even we have constraints over return address
                    if ucstate.history.jumpkind == 'Ijk_Ret':  # indirect call thunk pattern 1
                        # only call stub based indirect call will give us Ijk_ret
                        # eval with state constraints should generate exactly one ret_addr
                        tmp_ret_addr_list = ucstate.solver.eval_upto(ucstate.ip, 2, extra_constraints=ucstate.se.constraints)
                        if len(tmp_ret_addr_list) == 1:
                            print('we encounter an angr bug, fix it here..')  # this is workaround, consider fix angr
                            # fix jump_target
                            ucstate.history.jump_target = ucstate.ip
                            # fix ip address
                            ucstate.ip = tmp_ret_addr_list[0]
                            simgr.move(from_stash='unconstrained', to_stash='active', filter_func=filter_concrete)
                            print('moved Ijk_Ret')
                            continue
                        elif ucstate.history.jumpkinds[-2] == 'Ijk_Call':  # indirect call thunk patten 2
                            # indirect thunk pattern 3
                            if ucstate.solver.eval(ucstate.history.jump_targets[-2]) \
                                    - ucstate.solver.eval(ucstate.history.jump_targets[-3]) < 16:
                                interested_bb_addr = ucstate.solver.eval(ucstate.history.jump_targets[-4])
                                # relay site reached!
                                try:
                                    interested_bb_inst_addrs = self.b.factory.block(interested_bb_addr).instruction_addrs
                                except angr.errors.SimEngineError as e:
                                    print('angr.errors.SimEngineError ', e)
                                    embed()
                                    exit(0)
                                if relay_site in interested_bb_inst_addrs:
                                    rdi = ucstate.registers.load('rdi')
                                    if rdi.symbolic:
                                        ucstate.add_constraints(rdi != ucstate.regs.rip)
                                        if ucstate.satisfiable():
                                            self.relay_log_file.write(self.current_relay_gadget[1].decode('utf-8') + '\n')
                                            res = True
                                            continue
                                        else:
                                            # not satisfiable
                                            continue
                                    # rdi is not symbolic but points to controlled page in physmap
                                    elif self.controlled_memory_base <= self.sol.eval(rdi, 1)[0] < \
                                            self.controlled_memory_base + self.controlled_memory_size:
                                        self.relay_log_file.write(self.current_relay_gadget[1].decode('utf-8') + '\n')
                                        res = True
                                        continue
                                    else:
                                        print('remove state with out relaying effect')
                                        simgr.unconstrained.remove(ucstate)
                                        continue
                            else:
                                pass
                        else:
                            print('unhandeled Ijk_Ret')
                            embed()
                            continue

                    if relay_site in self.b.factory.block(ucstate.history.addr).instruction_addrs:
                        # check whether rdi is controllable(symbolic)
                        rdi = ucstate.registers.load('rdi')
                        if rdi.symbolic:
                            ucstate.add_constraints(rdi != ucstate.regs.rip)
                            if ucstate.satisfiable():
                                self.relay_log_file.write(self.current_relay_gadget[1]+'\n')
                                res = True
                        elif self.controlled_memory_base <= self.sol.eval(rdi, 1)[0] < \
                                self.controlled_memory_base + self.controlled_memory_size:
                            self.relay_log_file.write(self.current_relay_gadget[1]+'\n')
                            res = True
                        else:
                            simgr.unconstrained.remove(ucstate)
                            continue
                    else:  # unexpected relay site,
                        # maybe the function has multiple sites of indirect call, let's just ignore these states.
                        print('strange unconstrained state')
                        #embed()
                        print('unexpected unconstrained state, removing...')
                        simgr.unconstrained.remove(ucstate)
                # end of iteration over all unconstrained state
                if res is True:
                    print('found good relay site')
                    #embed()
                    break  # stop exploration

            if len(simgr.active) == 0:
                print('no active states left, wtf..')
                break

            if loop_idx > 8:
                break
            # end of handling unconstrained state

        del simgr
        return res

    def multiple_run_relay_gadgets(self):
        num_good_relay_gadget = 0
        total = len(self.relay_gadgets)
        for i, relay_gadget in enumerate(self.relay_gadgets):
            print('[+] ===== checking %d/%d th relay gadget... =====' % (i, total))
            self.current_relay_gadget = relay_gadget
            state = self.initial_state.copy()
            res = self.run_relay_gadget(state, relay_gadget, first_constraint_func=self.first_constraint_func)
            if res:
                num_good_relay_gadget += 1
            del state
        print('there are in total %d good relay gadget ' % num_good_relay_gadget)
        return

