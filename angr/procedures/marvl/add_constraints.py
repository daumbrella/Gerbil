import angr
from angr.state_plugins.sim_action import SimAction, SimActionConstraint

class add_constraints(angr.SimProcedure):
    def run(self,func_name=None):
        operations="<Operation {0} ({1}, {2}, {3})>".format(func_name,self.state.regs.r0,self.state.regs.r1,self.state.regs.r2)
        sac = SimActionConstraint(self.state,operations)
        self.state.history.add_action(sac)
        self.state.regs.ip=self.state.regs.lr