import os, sys, json, ast, astexport.export
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

    output_folder = "./output/"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    output_file = open(output_folder + sys.argv[1].split("/")[1].split(".")[0] + ".output.json", "w+")
    output_file.write(json.dumps(visitor.vulnerabilities.__repr__(), default=lambda o: o.__dict__, indent=4))
    output_file.close()