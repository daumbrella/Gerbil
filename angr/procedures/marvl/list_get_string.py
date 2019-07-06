import angr
import string
from angr.state_plugins.sim_action import SimAction, SimActionConstraint

class list_get_string(angr.SimProcedure):
    def run(self):
        operations="<Operation> list_get_string"
        print operations



