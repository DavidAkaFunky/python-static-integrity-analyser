import sys
from ast import parse
from astexport.export import export_dict
from nodes import *

def parse_node(node):
    
    if node is None:
        return None
    
    if type(node) is list:
        return [parse_node(n) for n in node if n is not None]

    match node["ast_type"]:
        
        ########### EXPRESSIONS ###########
        
        case "Constant":
            try:
                kind = node["kind"]
            except KeyError:
                kind = None
            return Constant(node["value"], kind)
         
        case "Name":
            # Should we parse the ctx?
            return Name(node["id"], node["ctx"])
            
        case "BinOp":
            return BinOp(parse_node(node["left"]), node["op"], parse_node(node["right"]))
            
        case "UnaryOp":
            return UnaryOp(node["op"], parse_node(node["operand"]))
            
        case "BoolOp":
            return BoolOp(node["op"], parse_node(node["values"]))
            
        case "Compare":
            # Should we parse the ops?
            return Compare(parse_node(node["left"]), node["ops"], parse_node(node["comparators"]))
            
        case "Call":
            return Call(parse_node(node["func"]), parse_node(node["args"]), parse_node(node["keywords"]))
            
        case "Attribute":
            # Should we parse the ctx?
            return Attribute(parse_node(node["value"]), node["attr"], node["ctx"])
            
        ########### STATEMENTS ###########
        
        case "Expr":
            return Expr(parse_node(node["value"]))
        
        case "Assign":
            return Assign(parse_node(node["targets"]), parse_node(node["value"]), node["type_comment"])
            
        case "If":
            return If(parse_node(node["test"]), parse_node(node["body"]), parse_node(node["orelse"]))
            
        case "While":
            return While(parse_node(node["test"]), parse_node(node["body"]), parse_node(node["orelse"]))
            
        # Sugeria tentarmos o For, o Try e o Match como extras
            
        case _:
            raise NotImplementedError(node["ast_type"])
        

def parse_ast_dict(ast_dict):
    return parse_node(ast_dict["body"])

if __name__ == "__main__":
    
    if len(sys.argv) != 3 or not sys.argv[1].endswith(".py") or not sys.argv[2].endswith(".json"):
        print("Usage: python ./analyser.py <file> <patterns>")
        exit(1)
    
    slice_file = open(sys.argv[1], "r")
    patterns_file = open(sys.argv[2], "r")
    
    ast_py = parse(slice_file.read())
    ast_dict = export_dict(ast_py)
    
    print(ast_dict)

    nodes = parse_ast_dict(ast_dict)
    print(nodes)