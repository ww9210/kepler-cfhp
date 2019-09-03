def filter_bad_rip(somestate):
    """
    filter function used when moving exploitable states
    if the rip of the state is user space or is in some symbolic region, return True
    :param somestate:
    :return:
    """
    if somestate.regs.rip.symbolic:
        return False
    ip = sol.eval(somestate.ip, 1)[0]
    if ip in [0xffff880066800000, 0]:
        return True
    if ip < 0x7fffffffffff:
        return True
    return False


def filter_bloom_unreachable(somestate):
    if not somestate.osokplugin.reach_bloom_site:
        return True
    return False


def filter_fork_unreachable(somestate):
    if not somestate.osokplugin.firstly_reach_first_fork_site \
            and not somestate.osokplugin.firstly_reach_second_fork_site:
        return True
    return False