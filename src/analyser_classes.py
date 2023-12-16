from copy import deepcopy
import json

class Node:
    
    def __init__(self, name: str, line: int):
        self.name = name 
        self.line = line
    
    def get_name(self):
        return self.name
    
    def get_line(self):
        return self.line
    
    def __repr__(self):
        return [self.name, self.line].__repr__()
    
    def __eq__(self, other):
        return self.name == other.name and self.line == other.line
    
    def __iter__(self):
        return iter([self.name, self.line])
    
    def __hash__(self) -> int:
        return hash((self.name, self.line))

class Pattern:
    
    def __init__(self, vuln_name: str, sources: set[Node], sanitisers: set[Node], sinks: set[Node], implicit: bool):
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
        return self.implicit
    
    def __repr__(self):
        return [self.vuln_name, self.sources, self.sanitisers, self.sinks, self.implicit].__repr__()
    
    @staticmethod
    def from_json(pattern):
        return Pattern(pattern["vulnerability"], pattern["sources"], pattern["sanitizers"], pattern["sinks"], pattern["implicit"])
    
class Label:
    
    """A Label is, in isolation, a pattern-agnostic information flow.
       To associate it with a pattern and restrict its sources and sanitisers,
       it must belong to a MultiLabel instance."""
    
    def __init__(self, sources: set[Node], sanitisers: list[list[Node]]):
        self.sources = sources
        self.sanitisers = sanitisers
       
    def get_sources(self):
        return deepcopy(self.sources)
    
    def get_sanitisers(self):
        return deepcopy(self.sanitisers)
       
    def add_source(self, source: Node):
        self.sources.add(source)
        
    def __repr__(self):
        return [self.sources, self.sanitisers].__repr__()
       
    @staticmethod 
    def combine(label1, label2):
        sources = label1.get_sources().union(label2.get_sources())
        sanitisers = label1.get_sanitisers() + label2.get_sanitisers()
        return Label(sources, sanitisers)

class MultiLabel:
    
    """A MultiLabel matches a set of labels and patterns
    using a cartesian product.
       In each pair, the labels' sources and sanitisers
    are restricted to those also present in the pattern."""
    
    def __init__(self, patterns, label: Node):
        self.label_map = {}
        for pattern in patterns:
            label_to_pattern_sources = [source for source in label.get_sources() if pattern.is_source(source.get_name())]
            label_to_pattern_sanitisers = [[sanitiser for sanitiser in sanitiser_list if pattern.is_sanitiser(sanitiser.get_name())] for sanitiser_list in label.get_sanitisers()]
            if len(label_to_pattern_sources) > 0:
                vuln_name = pattern.get_vuln_name()
                self.label_map[vuln_name] = Label(label_to_pattern_sources, label_to_pattern_sanitisers)
                
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
    
    def __repr__(self):
        return self.label_map.__repr__()

    @staticmethod
    def combine(multilabel1, multilabel2):
        new_multilabel = multilabel1.get_copy()
        for vuln_name in multilabel2.get_vulns():
            if vuln_name in new_multilabel.get_vulns():
                new_multilabel.set_pattern_label(vuln_name, Label.combine(multilabel1.get_label(vuln_name), multilabel2.get_label(vuln_name)))
            else:
                new_multilabel.set_pattern_label(vuln_name, multilabel2.get_label(vuln_name))
        return new_multilabel
    
class Policy:
    
    def __init__(self, patterns: list[Pattern]):
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
    
    def get_vulns_by_sink(self, sink):
        return set(pattern.get_vuln_name() for pattern in self.patterns if pattern.is_sink(sink))
    
    def get_illegal_flows_multilabel(self, multilabel, sink):
        new_multilabel = multilabel.get_copy()
        for vuln_name in new_multilabel.get_vulns().difference(self.get_vulns_by_sink(sink.get_name())):
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
    
    def get_multilabel(self, variable):
        return deepcopy(self.variable_map[variable])
    
    def set_multilabel(self, variable, multilabel):
        self.variable_map[variable] = multilabel

    def get_copy(self):
        return deepcopy(self)
    
    def delete_multilabel(self, variable):
        del self.variable_map[variable]
        
    def __repr__(self):
        return self.variable_map.__repr__()
    
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
        
    def add_vulnerability(self, policy, multilabel, sink):
        new_multilabel = policy.get_illegal_flows_multilabel(multilabel, sink)
        for vuln_name in new_multilabel.get_vulns():
            if vuln_name in self.vulnerabilities:
                self.vulnerabilities[vuln_name] = (MultiLabel.combine(self.vulnerabilities[vuln_name][0], new_multilabel), sink)
            else:
                self.vulnerabilities[vuln_name] = (new_multilabel, sink)
                
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
            label = self.vulnerabilities[vuln_name][0].get_label(vuln_name)
            sink = self.vulnerabilities[vuln_name][1]
            sanitisers = label.get_sanitisers()
            for i, source in enumerate(label.get_sources()):
                vuln = {}
                vuln["vulnerability"] = vuln_name + "_" + str(i+1)
                vuln["source"] = source
                vuln["sink"] = sink
                vuln["unsanitized_flows"] = "yes" if any([len(flow) == 0 for flow in sanitisers]) else "no"
                vuln["sanitized_flows"] = [flow for flow in sanitisers if len(flow) > 0]
                output.append(vuln)

        return json.dumps(str(output))