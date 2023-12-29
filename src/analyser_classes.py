from copy import deepcopy
import json

class Node:
    
    def __init__(self, name: str, line: int):
        self.name = name 
        self.line = line
        self.initialise = True

    def get_name(self):
        return self.name
    
    def get_line(self):
        return self.line
    
    def set_line(self, line):
        self.line = line
    
    def do_not_initialise(self):
        self.initialise = False
        
    def should_initialise(self):
        return self.initialise
    
    def __repr__(self):
        return [self.name, self.line].__repr__()
    
    def __eq__(self, other):
        return self.name == other.name and self.line == other.line
    
    def __iter__(self):
        return iter([self.name, self.line])
    
    def __hash__(self) -> int:
        return hash((self.name, self.line))

class Pattern:
    
    def __init__(self, vuln_name: str, sources: 'set[Node]', sanitisers: 'set[Node]', sinks: 'set[Node]', implicit: bool):
        self.vuln_name = vuln_name
        self.sources = sources
        self.sanitisers = sanitisers
        self.sinks = sinks
        self.implicit = implicit
        
    def is_source(self, name):
        return name in self.sources
    
    def is_sanitiser(self, node):
        return node in self.sanitisers
    
    def is_sink(self, node):
        return node in self.sinks
    
    def get_vuln_name(self):
        return self.vuln_name
    
    def get_sources(self):
        return deepcopy(self.sources)
    
    def get_sanitisers(self):
        return deepcopy(self.sanitisers)
    
    def get_sinks(self):
        return deepcopy(self.sinks)

    def is_implicit(self):
        return self.implicit == "yes"
    
    def __repr__(self):
        return [self.vuln_name, self.sources, self.sanitisers, self.sinks, self.implicit].__repr__()
    
    @staticmethod
    def from_json(pattern):
        return Pattern(pattern["vulnerability"], pattern["sources"], pattern["sanitizers"], pattern["sinks"], pattern["implicit"])
    
class Label:
    
    """A Label is, in isolation, a pattern-agnostic information flow.
       To associate it with a pattern and restrict its sources and sanitisers,
       it must belong to a MultiLabel instance."""
    
    def __init__(self, source=None):
        # Is a set adequate? Maybe repeated elements are okay
        self.pairs = []
        if source is not None:
            self.add_pair([source, [[]]])
       
    def get_pairs(self):
        return deepcopy(self.pairs)
    
    def sanitise(self, sanitiser: Node):
        #print("SANITISING!!!!", self.pairs)
        for pair in self.pairs:
            for flow in pair[1]:
                if sanitiser not in flow:
                    flow.append(sanitiser)
        #print("SANITISED!!!!", self.pairs)
            
    def add_pair(self, other_pair):
        for pair in self.pairs:
            if pair[0] == other_pair[0]:
                for flow in other_pair[1]:
                    if flow not in pair[1]:
                        pair[1].append(flow)
                return
        self.pairs.append(other_pair)
        
    def get_copy(self):
        return deepcopy(self)
    
    def fix_lineno(self, lineno):
        for pair in self.pairs:
            source = pair[0]
            if source.get_line() == -1:
                source.set_line(lineno)
    
    def __eq__(self, other):
        if len(self.pairs) != len(other.pairs):
            return False

        for pair in self.pairs:
            if pair not in other.pairs:
                return False
        return True
        
    def __repr__(self):
        return self.pairs.__repr__()
    
    @staticmethod
    def create_empty():
        new_label = Label()
        new_label.pairs = []
        return new_label
       
    @staticmethod 
    def combine(label1, label2):
        new_label = label1.get_copy()
        label1_pairs = label1.get_pairs()
        label2_pairs = label2.get_pairs()
        #print("LABEL1", label1)
        #print("LABEL2", label2)
        for pair in label2_pairs:
            #print(pair, pair not in label1_pairs)
            new_label.add_pair(pair)
        return new_label

class MultiLabel:
    
    """A MultiLabel matches a set of labels and patterns
    using a cartesian product.
       In each pair, the labels' sources and sanitisers
    are restricted to those also present in the pattern."""
    
    def __init__(self, patterns, labels):
        self.label_map = dict()
        for pattern in patterns:
            for label in labels:
                new_label = Label.create_empty()
                for pair in label.get_pairs():
                    if pair[0].get_name() in pattern.get_sources():
                        new_label.add_pair([pair[0], [[s for s in flow if pattern.is_sanitiser(s.get_name())] for flow in pair[1]]])
                if len(new_label.pairs) > 0:
                    vuln_name = pattern.get_vuln_name()
                    if vuln_name in self.label_map:
                        self.label_map[vuln_name] = [new_label]
                    else:
                        self.label_map[vuln_name] = new_label
         
    def get_vulns(self):
        return set(self.label_map.keys())
        
    def get_label(self, vuln_name):
        return deepcopy(self.label_map[vuln_name])
    
    def get_labels(self):
        return set(self.label_map.values())
    
    def set_pattern_label(self, vuln_name, label):
        self.label_map[vuln_name] = label
    
    def get_label_map(self):
        return deepcopy(self.label_map)
    
    def get_copy(self):
        return deepcopy(self)
    
    def is_empty(self):
        return len(self.label_map) == 0
    
    def sanitise(self, policy, node: Node):
        for vuln_name in policy.get_vulns_by_sanitiser(node.get_name()):
            if vuln_name in self.label_map:
                self.label_map[vuln_name].sanitise(node)
                
    def fix_lineno(self, lineno):
        for vuln_name in self.label_map:
            self.label_map[vuln_name].fix_lineno(lineno)
    
    def __repr__(self):
        return self.label_map.__repr__()
    
    def __eq__(self, other):
        if len(self.label_map.keys()) != len(other.label_map.keys()):
            return False

        for vuln_name in self.label_map.keys():
            if vuln_name not in other.label_map.keys() or self.label_map[vuln_name] != other.label_map[vuln_name]:
                return False

        return True
    
    @staticmethod
    def create_empty():
        return MultiLabel([], None)
    
    @staticmethod
    def create_for_uninitialised_variable(policy, node: Node):
        new_multilabel = MultiLabel.create_empty()
        label = Label(node)
        for vuln_name in policy.get_vulns():
            new_multilabel.label_map[vuln_name] = label
        return new_multilabel

    @staticmethod
    def combine(multilabel1, multilabel2):
        #print("ML1", multilabel1)
        #print("ML2", multilabel2)
        new_multilabel = multilabel1.get_copy()
        multilabel1_vulns = multilabel1.get_vulns()
        multilabel2_vulns = multilabel2.get_vulns()
        for vuln_name in multilabel2_vulns:
            if vuln_name in multilabel1_vulns:
                new_multilabel.label_map[vuln_name] = Label.combine(multilabel1.get_label(vuln_name), multilabel2.get_label(vuln_name))
            else:
                new_multilabel.label_map[vuln_name] = multilabel2.get_label(vuln_name)
        #print("COMBINED", new_multilabel)
        return new_multilabel

    
class Policy:
    
    def __init__(self, patterns: 'list[Pattern]'):
        self.patterns = patterns
        
    def get_patterns(self):
        return self.patterns
    
    def get_pattern(self, vuln_name):
        return self.patterns[vuln_name]
    
    def get_patterns_by_source(self, source):
        return set(pattern for pattern in self.patterns if pattern.is_source(source))
    
    def get_patterns_by_sanitiser(self, sanitiser):
        return set(pattern for pattern in self.patterns if pattern.is_sanitiser(sanitiser))
    
    def get_vulns(self):
        return set(pattern.get_vuln_name() for pattern in self.patterns)
    
    def get_vulns_by_source(self, source):
        return set(pattern.get_vuln_name() for pattern in self.patterns if pattern.is_source(source))
    
    def get_vulns_by_sanitiser(self, sanitiser):
        return set(pattern.get_vuln_name() for pattern in self.patterns if pattern.is_sanitiser(sanitiser))
    
    def get_vulns_by_sink(self, node):
        return set(pattern.get_vuln_name() for pattern in self.patterns if pattern.is_sink(node))
    
    def get_non_sink_vulns(self, node):
        return set(pattern.get_vuln_name() for pattern in self.patterns if not pattern.is_sink(node))
    
    def get_non_implicit_vulns(self):
        return set(pattern.get_vuln_name() for pattern in self.patterns if not pattern.is_implicit())

    def get_implicit_vulns(self):
        return set(pattern.get_vuln_name() for pattern in self.patterns if pattern.is_implicit())
    
    def get_illegal_flows_multilabel(self, multilabel, node):
        new_multilabel = multilabel.get_copy()
        for vuln_name in new_multilabel.get_vulns().intersection(self.get_non_sink_vulns(node.get_name())):
            del new_multilabel.label_map[vuln_name]
        return new_multilabel
    
    def get_implicit_patterns_multilabel(self, multilabel):
        new_multilabel = multilabel.get_copy()
        for vuln_name in new_multilabel.get_vulns().intersection(self.get_non_implicit_vulns()):
            del new_multilabel.label_map[vuln_name]
        return new_multilabel

class MultiLabelling:
    
    """Maps variables to MultiLabel instances"""
    
    def __init__(self):
        self.variable_map = {}
        
    def add_multilabel(self, variable: str, multilabel: MultiLabel):
        if variable in self.variable_map:
            self.variable_map[variable] = MultiLabel.combine(self.variable_map[variable], multilabel)
        else:
            self.variable_map[variable] = multilabel.get_copy()
    
    def get_variable_map(self):
        return self.variable_map
    
    def is_variable_initialised(self, variable: str):
        return variable in self.variable_map
    
    def get_multilabel(self, variable):
        return deepcopy(self.variable_map[variable])
    
    def set_multilabel(self, variable, multilabel):
        self.variable_map[variable] = multilabel

    def get_copy(self):
        return deepcopy(self)
    
    def delete_multilabel(self, variable):
        del self.variable_map[variable]

    def conciliate_multilabelling(self, policy, other):

        other_variable_map = other.get_variable_map()
        
        for variable in self.variable_map:
            if variable in other_variable_map: # Variable in self and other
                self.variable_map[variable] = MultiLabel.combine(self.variable_map[variable], other.get_multilabel(variable))
            else: # Variable in self but not in other
                self.variable_map[variable] = MultiLabel.combine(self.variable_map[variable], MultiLabel.create_for_uninitialised_variable(policy, Node(variable, -1)))
        
        for variable in other_variable_map:
            # No need to repeat the case where variable is in self and other
            if variable not in self.variable_map: # Variable in other but not in self
                self.variable_map[variable] = MultiLabel.combine(MultiLabel.create_for_uninitialised_variable(policy, Node(variable, -1)), other.get_multilabel(variable))
        
    def __repr__(self):
        return self.variable_map.__repr__()

    def __eq__(self, other):
        if len(self.variable_map.keys()) != len(other.variable_map.keys()):
            return False

        for variable in self.variable_map.keys():
            if variable not in other.variable_map.keys() or self.variable_map[variable] != other.variable_map[variable]:
                return False
        return True
    
    @staticmethod
    def combine(multilabelling1, multilabelling2):
        new_multilabelling = multilabelling1.get_copy()
        for variable in multilabelling2.get_variable_map():
            if variable in new_multilabelling.get_variable_map():
                new_multilabelling.set_multilabel(variable, MultiLabel.combine(new_multilabelling.get_multilabel(variable), multilabelling2.get_multilabel(variable)))
            else:
                new_multilabelling.set_multilabel(variable, multilabelling2.get_multilabel(variable))
        return new_multilabelling
        
class Vulnerabilities:
    
    """Maps a vulnerability to a set of multilabels
    with that vulnerability."""
    
    def __init__(self):
        self.vulnerabilities = {}
        
    def add_vulnerability(self, policy, multilabel, node):
        new_multilabel = policy.get_illegal_flows_multilabel(multilabel, node)
        for vuln_name in new_multilabel.get_vulns():
            if vuln_name in self.vulnerabilities:
                node_data = (new_multilabel.get_label(vuln_name), node)
                if node_data not in self.vulnerabilities[vuln_name]:
                    self.vulnerabilities[vuln_name].append(node_data)
            else:
                self.vulnerabilities[vuln_name] = [(new_multilabel.get_label(vuln_name), node)]

    def get_vulnerabilities(self):
        return deepcopy(self.vulnerabilities)

    def conciliate_vulnerabilities(self, other):
        other_vulns = other.get_vulnerabilities()
        for vuln_name in other_vulns:
            other_vuln = other_vulns[vuln_name]
            if vuln_name in self.vulnerabilities:
                if other_vuln not in self.vulnerabilities[vuln_name]:
                    self.vulnerabilities[vuln_name] += other_vuln
            else:
                self.vulnerabilities[vuln_name] = other_vuln
                
    def __repr__(self):
        """
        <OUTPUT> ::= [ <VULNERABILITIES> ]
        <VULNERABILITIES> := "none" | <VULNERABILITY> | <VULNERABILITY>, <VULNERABILITIES>
        <VULNERABILITY> ::= { "vulnerability": "<STRING>",
                            "source": ["<STRING>", <INT>],
                            "sink": ["<STRING>", <INT>],
                            "unsanitized_flows": <YESNO>,
                            "sanitized_flows": [ <FLOWS> ] }
        <YESNO> ::= "yes" | "no"
        <FLOWS> ::= "none" | <FLOW> | <FLOW>, <FLOWS>
        <FLOW> ::= [ <SANITIZERS> ]
        <SANITIZERS> ::= [<STRING>, <INT>] | [<STRING>, <INT>], <SANITIZERS>
        """
        output = []
        for vuln_name in self.vulnerabilities:
            i = 1
            for vulnerability in self.vulnerabilities[vuln_name]:
                label = vulnerability[0]
                sink = vulnerability[1]
                for pair in label.get_pairs():
                    vuln = {}
                    vuln["vulnerability"] = vuln_name + "_" + str(i)
                    vuln["source"] = pair[0]
                    vuln["sink"] = sink
                    vuln["unsanitized_flows"] = "yes" if any([len(flow) == 0 for flow in pair[1]]) else "no"
                    vuln["sanitized_flows"] = [flow for flow in pair[1] if len(flow) > 0]
                    output.append(vuln)
                    i += 1

        return json.dumps(str(output))
