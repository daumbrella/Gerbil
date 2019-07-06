import angr
from angr.state_plugins.sim_action import SimAction, SimActionConstraint

class miio_jsmn_parse(angr.SimProcedure):
    def run(self):
        operations="<Operation {0} ({1}, {2}, {3})>".format("miio_jsmn_parse",self.state.regs.r0,self.state.regs.r1,self.state.regs.r2)
        self.state.regs.r0=0
        sac = SimActionConstraint(self.state,operations)
        self.state.history.add_action(sac)
        self.state.regs.ip=self.state.regs.lr

