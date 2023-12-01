class Pattern:
    
    def __init__(self, vuln_name, sources, sanitisers, sinks):
        self.vuln_name = vuln_name
        self.sources = sources
        self.sanitisers = sanitisers
        self.sinks = sinks
        
    def is_source(self, name):
        return name in self.sources
    
    def is_sanitiser(self, name):
        return name in self.sanitisers
    
    def is_sink(self, name):
        return name in self.sinks
    
    def get_vuln_name(self):
        return self.vuln_name
    
    def get_sources(self):
        return self.sources.copy()
    
    def get_sanitisers(self):
        return self.sanitisers.copy()
    
    def get_sinks(self):
        return self.sinks.copy()
   
class Source:
    
    def __init__(self, name, line):
        self.name = name 
        self.line = line
    
    def __eq__(self, other):
        return self.name == other.name and self.line == other.line
    
class Label:
    
    def __init__(self, source, sanitisers):
        self.source = source
        self.sanitisers = sanitisers
       
    @staticmethod 
    def combine(label1, label2):
        assert label1.source == label2.source
        source = label1.source
        sanitisers = label1.sanitisers.union(label2.sanitisers)
        return Label(source, sanitisers)

class MultiLabel:
    
    """Maps patterns to labels"""
    
    def __init__(self, patterns, labels):
        self.label_map = {pattern: label for pattern, label in zip(patterns, labels)}    
        
    def get_patterns(self):
        return list(self.label_map.keys()).copy()
        
    def get_labels(self):
        return list(self.label_map.values()).copy()
    
    def get_label_map(self):
        return self.label_map.copy()
    
    def get_vulns(self):
        return [pattern.get_vuln_name() for pattern in self.get_patterns()]
    
    @staticmethod
    def create_multilabel(label_map):
        multilabel = MultiLabel([], [])
        multilabel.label_map = label_map
        return multilabel
        
    @staticmethod
    def combine(multilabel1, multilabel2):
        return MultiLabel.create_multilabel({**multilabel1.label_map, **multilabel2.label_map})
    
class Policy:
    
    def __init__(self, patterns):
        self.patterns = patterns
        
    def get_vulns(self):
        return [pattern.vuln_name for pattern in self.patterns]
    
    def get_vulns_by_source(self, source):
        return [pattern.vuln_name for pattern in self.patterns if pattern.is_source(source)]
    
    def get_vulns_by_sanitiser(self, sanitiser):
        return [pattern.vuln_name for pattern in self.patterns if pattern.is_sanitiser(sanitiser)]
    
    def get_vulns_by_sink(self, sink):
        return [pattern.vuln_name for pattern in self.patterns if pattern.is_sink(sink)]
    
    @staticmethod
    def get_illegal_flows_multilabel(multilabel, sink):
        label_map = {label: pattern for label, pattern in multilabel.get_label_map() if pattern.is_sink(sink)}
        return MultiLabel.create_multilabel(label_map)
    

class MultiLabelling:
    
    """Maps variables to multilabels"""
    
    def __init__(self, variables, multilabels):
        self.variable_map = {variable: multilabel for variable, multilabel in zip(variables, multilabels)}
        
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