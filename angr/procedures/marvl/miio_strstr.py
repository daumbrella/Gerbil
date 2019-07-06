import angr
from angr.state_plugins.sim_action import SimAction, SimActionConstraint

class miio_strstr(angr.SimProcedure):
    def run(self):
        operations="<Operation {0} ({1}, {2}, {3})>".format("miio_strstr",self.state.regs.r0,self.state.regs.r1,self.state.regs.r2)
        sac = SimActionConstraint(self.state,operations)
        r0=self.state.solver.BVS('strstr_r0',4*8)
        self.state.regs.r0=r0
        self.state.regs.ip=self.state.regs.lr
        return

