from . import ExplorationTechnique

class Slicecutor(ExplorationTechnique):
    def __init__(self, annotated_cfg):
        self._annotated_cfg = annotated_cfg

    def step_state(self, state, **kwargs):
        whitelist = self._annotated_cfg.get_whitelisted_statements(state.addr)
        last_stmt = self._annotated_cfg.get_last_statement_index(state.addr)
        if whitelist is not None: kwargs['whitelist'] = whitelist
        if last_stmt is not None: kwargs['last_stmt'] = last_stmt
        succ = self.project.factory.successors(state, **kwargs)

        if all(self.filter(s) is not None for s in succ.flat_successors):
            for target in self._annotated_cfg.get_targets(state.addr):
                successor = succ.successors[0].copy()
                successor.regs._ip = target
                succ.flat_successors.append(successor)

        return succ

    def filter(self, state):
        src_addr = state.history.addr
        dst_addr = state.addr

        try:
            if not self._annotated_cfg.should_take_exit(src_addr, dst_addr):
                return 'sliced'
        except AngrExitError:
            return 'mystery'
