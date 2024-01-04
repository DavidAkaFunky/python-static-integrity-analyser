import sys, json, ast, astexport.export
from ast_visitor import ASTVisitor

if __name__ == "__main__":
    
    if len(sys.argv) != 3 or not sys.argv[1].endswith(".py") or not sys.argv[2].endswith(".json"):
        print("Usage: python ./analyser.py <file> <patterns>")
        exit(1)
    
    slice_file = open(sys.argv[1], "r")
    
    with open(sys.argv[2], "r") as f:
        patterns_json = json.load(f)
    
    ast_py = ast.parse(slice_file.read())
    visitor = ASTVisitor(patterns_json)
    visitor.visit(ast_py)
    print(visitor.vulnerabilities)