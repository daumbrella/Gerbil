import angr
import string
from angr.state_plugins.sim_action import SimAction, SimActionConstraint

class get_list_index(angr.SimProcedure):
    def run(self):
        operations="<Operation> get_list_index"
        print operations


