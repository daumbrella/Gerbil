import angr
from angr.state_plugins.sim_action import SimAction, SimActionConstraint

class netbuf_next(angr.SimProcedure):
    def run(self):
        operations="<Operation {0} ({1})>".format("netbuf_next",self.state.regs.r0)
        sac = SimActionConstraint(self.state,operations)
        self.state.history.add_action(sac)
        self.state.regs.r0=-1
        self.state.regs.ip=self.state.regs.lr

