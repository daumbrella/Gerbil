import logging

from ..analyses.loopfinder import Loop
from ..knowledge_base import KnowledgeBase
from ..knowledge_plugins.functions import Function
from . import ExplorationTechnique
from .. import sim_options


l = logging.getLogger("angr.exploration_techniques.filter_contraints")


class FilterContraints(ExplorationTechnique):
    """
    This exploration technique is used to filter target "data" constraints.
    """

    def __init__(self, find=None, avoid=None,functions=None, find_stash='found', discard_stash=None,loops=None, avoid_stash='avoid',loop_limit=False, bound=1, bound_reached=None, cfg=None, num_find=1, avoid_priority=False):
        super(FilterContraints, self).__init__()
        self.find = self._condition_to_lambda(find)
        self.avoid = self._condition_to_lambda(avoid)
        self.find_stash = find_stash
        self.avoid_stash = avoid_stash
        self.cfg = cfg
        self.bound = bound
        self.bound_reached = bound_reached
        self.discard_stash = discard_stash
        self.functions = functions
        self.ok_blocks = set()
        self.num_find = num_find
        self.avoid_priority = avoid_priority
        self.loop_limit=loop_limit
        if self.loop_limit:
            self.loops = {}
            if type(loops) is Loop:
                loops = [loops]
            if type(loops) in (list, tuple) and all(type(l) is Loop for l in loops):
                for loop in loops:
                    self.loops[loop.entry_edges[0][0].addr] = loop
            elif loops is not None:
                raise TypeError('What type of loop is it?')

        find_addrs = getattr(self.find, "addrs", None)
        avoid_addrs = getattr(self.avoid, "addrs", None)

        # it is safe to use unicorn only if all addresses at which we should stop are statically known
        self._warn_unicorn = (find_addrs is None) or (avoid_addrs is None)

        # even if avoid or find addresses are not statically known, stop on those that we do know
        self._extra_stop_points = (find_addrs or set()) | (avoid_addrs or set())


        # TODO: This is a hack for while CFGFast doesn't handle procedure continuations
        '''from .. import analyses
        if isinstance(cfg, analyses.CFGFast):
            l.error("CFGFast is currently inappropriate for use with Explorer.")
            l.error("Usage of the CFG has been disabled for this explorer.")
            self.cfg = None

        if self.cfg is not None:
            avoid = avoid_addrs or set()

            # we need the find addresses to be determined statically
            if find_addrs is None:
                l.error("You must provide at least one 'find' address as a number, set, list, or tuple if you provide a CFG.")
                l.error("Usage of the CFG has been disabled for this explorer.")
                self.cfg = None
                return
            find = self.find.addrs

            for a in avoid:
                if cfg.get_any_node(a) is None:
                    l.warning("'Avoid' address %#x not present in CFG...", a)

            # not a queue but a stack... it's just a worklist!
            queue = []
            for f in find:
                nodes = cfg.get_all_nodes(f)
                if len(nodes) == 0:
                    l.warning("'Find' address %#x not present in CFG...", f)
                else:
                    queue.extend(nodes)

            seen_nodes = set()
            while len(queue) > 0:
                n = queue.pop()
                if id(n) in seen_nodes:
                    continue
                if n.addr in avoid:
                    continue
                self.ok_blocks.add(n.addr)
                seen_nodes.add(id(n))
                queue.extend(n.predecessors)

            if len(self.ok_blocks) == 0:
                l.error("No addresses could be validated by the provided CFG!")
                l.error("Usage of the CFG has been disabled for this explorer.")
                self.cfg = None
                return

            l.warning("Please be sure that the CFG you have passed in is complete.")
            l.warning("Providing an incomplete CFG can cause viable paths to be discarded!")'''

    def setup(self, simgr):
        if self.loop_limit:
            if not self.loops or self.functions is not None:
                loop_finder = self.project.analyses.LoopFinder(normalize=True, functions=self.functions)
                for loop in loop_finder.loops:
                    if len(loop.entry_edges)>0 and len(loop.entry_edges[0])>0:
                        entry = loop.entry_edges[0][0]
                        self.loops[entry.addr] = loop
        if not self.find_stash in simgr.stashes: simgr.stashes[self.find_stash] = []
        if not self.avoid_stash in simgr.stashes: simgr.stashes[self.avoid_stash] = []

    def step(self, simgr, stash=None, **kwargs):
        base_extra_stop_points = set(kwargs.get("extra_stop_points") or {})
        if self.loop_limit:
            simgr.step(stash=stash, extra_stop_points=base_extra_stop_points | self._extra_stop_points, **kwargs)
            #print "-----------------------------------------"
            #print simgr.stashes[stash]
            #print len(simgr.stashes[stash])
            for state in simgr.stashes[stash]:
                # Processing a currently running loop
                #print "current state is ",hex(state.addr)
                if state.loop_data.current_loop:
                    #print "current state is in the loop"
                    loop = state.loop_data.current_loop[-1][0]
                    header = loop.entry.addr
                    
                    if state.addr == header:
                        #print "the header find and count + 1  ",hex(state.addr)
                        state.loop_data.trip_counts[state.addr][-1] += 1

                    elif state.addr in state.loop_data.current_loop[-1][1]:
                        back_edge_src = loop.continue_edges[0][0].addr
                        back_edge_dst = loop.continue_edges[0][1].addr
                        block = self.project.factory.block(back_edge_src)
                        if back_edge_src != back_edge_dst and back_edge_dst in block.instruction_addrs:
                            state.loop_data.trip_counts[header][-1] -= 1
                        #print "pop this state loop  ",hex(state.addr)
                        state.loop_data.current_loop.pop()

                    if self.bound is not None:
                        #print "the header count ",state.loop_data.trip_counts[header][-1]
                        if state.loop_data.trip_counts[header][-1] >= self.bound:
                            if self.bound_reached is not None:
                                simgr = self.bound_reached(simgr)
                            else:
                                #print "loop seer remove the state  ",hex(state.addr)
                                simgr.stashes[stash].remove(state)
                                simgr.stashes[self.discard_stash].append(state)

                    l.debug("%s trip counts %s", state, state.loop_data.trip_counts)

                # Loop entry detected. This test is put here because in case of
                # nested loops, we want to handle the outer loop before proceeding
                # the inner loop.
                if state.addr in self.loops and not simgr._project.is_hooked(state.addr):
                    #print "add the state into the loops ",hex(state.addr)
                    loop = self.loops[state.addr]
                    header = loop.entry.addr
                    exits = [e[1].addr for e in loop.break_edges]

                    state.loop_data.trip_counts[header].append(0)
                    state.loop_data.current_loop.append((loop, exits))

            return simgr
        else:
            return simgr.step(stash=stash, extra_stop_points=base_extra_stop_points | self._extra_stop_points, **kwargs)

    def filter(self, state):
        if sim_options.UNICORN in state.options and self._warn_unicorn:
            self._warn_unicorn = False # show warning only once
            l.warning("Using unicorn with find or avoid conditions that are a lambda (not a number, set, tuple or list).")
            l.warning("Unicorn may step over states that match the condition (find or avoid) without stopping.")
        rFind = self.find(state)
        if rFind:
            if not state.history.reachable:
                return 'unsat'
            rAvoid = self.avoid(state)
            if rAvoid:
                # if there is a conflict
                if self.avoid_priority & ((type(rFind) is not set) | (type(rAvoid) is not set)):
                    # with avoid_priority and one of the conditions is not a set
                    return self.avoid_stash
            if type(rAvoid) is not set:
                # rAvoid is False or self.avoid_priority is False
                # Setting rAvoid to {} simplifies the rest of the code
                rAvoid = {}
            if type(rFind) is set:
                while state.addr not in rFind:

                    if state.addr in rAvoid:
                        return self.avoid_stash
                    state = self.project.factory.successors(state, num_inst=1).successors[0]


                if self.avoid_priority & (state.addr in rAvoid):
                    # Only occurs if the intersection of rAvoid and rFind is not empty
                    # Why would anyone want that?
                    return self.avoid_stash
            return (self.find_stash, state)
        if self.avoid(state): return self.avoid_stash
        '''if self.cfg is not None and self.cfg.get_any_node(state.addr) is not None:
            if state.addr not in self.ok_blocks: return self.avoid_stash'''
        return None

    def complete(self, simgr):
        return len(simgr.stashes[self.find_stash]) >= self.num_find

