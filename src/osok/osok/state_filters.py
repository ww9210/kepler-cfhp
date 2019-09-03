import traceback


def filter_bad_rip(somestate):
    """
    filter function used when moving exploitable states
    if the rip of the state is user space or is in some symbolic region, return True
    :param somestate:
    :return:
    """
    try:
        if somestate.regs.rip.symbolic:
            return False
        ip = somestate.solver.eval_upto(somestate.ip, 1)[0]
        if 0xffff880066800000 < ip < 0xffff880066900000:
            return True
        if ip < 0x7fffffffffff:
            return True
        return False
    except all as e:
        print e
        traceback.print_exc()
        import IPython; IPython.embed()


def filter_bloom_unreachable(somestate):
    if not somestate.osokplugin.reach_bloom_site:
        return True
    return False


def filter_fork_unreachable(somestate):
    if not somestate.osokplugin.firstly_reach_first_fork_site \
            and not somestate.osokplugin.firstly_reach_second_fork_site:
        return True
    return False
