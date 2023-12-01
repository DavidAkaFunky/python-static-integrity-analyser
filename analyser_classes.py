from utils import *

class Variable:
    
    def __init__(self, name: str, line: int):
        self.name = name 
        self.line = line
    
    def __repr__(self):
        return "({}, {})".format(self.name, self.line)
    
    def __eq__(self, other):
        return self.name == other.name and self.line == other.line
    
    def __hash__(self) -> int:
        return hash(self)

class Pattern:
    
    def __init__(self, vuln_name: str, sources: list[Variable], sanitisers: list[Variable], sinks: list[Variable], implicit: bool):
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
        return self.sources.copy()
    
    def get_sanitisers(self):
        return self.sanitisers.copy()
    
    def get_sinks(self):
        return self.sinks.copy()

    def is_implicit(self):
        return self.implicit
    
class Label:
    
    """A Label is, in isolation, a pattern-agnostic information flow.
       To associate it with a pattern and restrict its sources and sanitisers,
       it must belong to a MultiLabel instance."""
    
    def __init__(self, sources: list[Variable], sanitisers: list[Variable]):
        self.sources = sources
        self.sanitisers = sanitisers
       
    def get_sources(self):
        return self.sources.copy()
    
    def get_sanitisers(self):
        return self.sanitisers.copy()
       
    def add_source(self, source: Variable):
        self.sources.add(source)
       
    @staticmethod 
    def combine(label1, label2):
        sources = list_union(label1.get_sources(), label2.get_sources())
        sanitisers = list_union(label1.get_sanitisers(), label2.get_sanitisers())
        return Label(sources, sanitisers)

class MultiLabel:
    
    """A MultiLabel matches a list of labels and patterns
    using a cartesian product. In each pair, the labels'
    sources and sanitisers are restricted to those also
    present in the pattern, making each label"""
    
    def __init__(self, patterns: list[Pattern], labels: list[Label]):
        self.label_map = {}
        for pattern in patterns:
            for label in labels:
                label_to_pattern_sources = list_intersection(label.get_sources(), pattern.get_sources())
                label_to_pattern_sanitisers = list_intersection(label.get_sanitisers(), pattern.get_sanitisers())
                if len(label_to_pattern_sources) > 0 and len(label_to_pattern_sanitisers) > 0:
                    add_to_dict(self.label_map, pattern, Label(label_to_pattern_sources, label_to_pattern_sanitisers))
                
    def get_patterns(self):
        return list(self.label_map.keys()).copy()
        
    def get_labels(self):
        return list(self.label_map.values()).copy()
    
    def get_label_map(self):
        return self.label_map.copy()
    
    def get_vulns(self):
        return [pattern.get_vuln_name() for pattern in self.patterns]
    
    @staticmethod
    def create_multilabel(label_map):
        multilabel = MultiLabel([], [])
        multilabel.label_map = label_map
        return multilabel
        
    @staticmethod
    def combine(multilabel1, multilabel2):
        return MultiLabel.create_multilabel({**multilabel1.get_label_map(), **multilabel2.get_label_map()})
    
class Policy:
    
    def __init__(self, patterns: list[Pattern]):
        self.patterns = patterns
        
    def get_patterns(self):
        return self.patterns.copy()
        
    def get_vulns(self):
        return [pattern.get_vuln_name() for pattern in self.patterns]
    
    def get_vulns_by_source(self, source):
        return [pattern.get_vuln_name() for pattern in self.patterns if pattern.is_source(source)]
    
    def get_vulns_by_sanitiser(self, sanitiser):
        return [pattern.get_vuln_name() for pattern in self.patterns if pattern.is_sanitiser(sanitiser)]
    
    def get_vulns_by_sink(self, sink):
        return [pattern.get_vuln_name() for pattern in self.patterns if pattern.is_sink(sink)]
    
    @staticmethod
    def get_illegal_flows_multilabel(multilabel, sink):
        label_map = {label: pattern for label, pattern in multilabel.get_label_map() if pattern.is_sink(sink)}
        return MultiLabel.create_multilabel(label_map)
    

class MultiLabelling:
    
    """Maps variables to MultiLabel instances (cartesian product?)"""
    
    def __init__(self, variables: list[Variable], multilabels: list[MultiLabel]):
        self.variable_map = {variable: multilabel for variable in variables for multilabel in multilabels}
        
    def get_multilabel(self, variable):
        return self.variable_map[variable]
    
    def set_multilabel(self, variable, multilabel):
        self.variable_map[variable] = multilabel
        
        
class Vulnerabilities:
    
    def __init__(self):
        self.vulnerabilities = {}
        
    def add_vulnerability(self, multilabel, sink):
        new_multilabel = Policy.get_illegal_flows_multilabel(multilabel, sink)
        for vuln_name in new_multilabel.get_vulns():
            try:
                self.vulnerabilities[vuln_name] = MultiLabel.combine(self.vulnerabilities[vuln_name], new_multilabel)
            except KeyError:
                self.vulnerabilities[vuln_name] = new_multilabel