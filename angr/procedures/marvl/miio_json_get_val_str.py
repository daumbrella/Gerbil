import angr
import string
from angr.state_plugins.sim_action import SimAction, SimActionConstraint

class miio_json_get_val_str(angr.SimProcedure):
    def run(self):
        operations="<Operation> miio_json_get_val_str"
        #print operations
