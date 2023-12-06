from ast import NodeVisitor

class ASTVisitor(NodeVisitor):
    
    def visit_Name(self, node):
        pass
            
    def visit_BinOp(self, node):
        pass
            
    def visit_UnaryOp(self, node):
        pass
            
    def visit_BoolOp(self, node):
        pass
            
    def visit_Compare(self, node):
        pass
            
    def visit_Call(self, node):
        pass
            
    def visit_Attribute(self, node):
        pass
            
    ########### STATEMENTS ###########
        
    def visit_Expr(self, node):
        pass
        
    def visit_Assign(self, node):
        pass
            
    def visit_If(self, node):
        pass
            
    def visit_While(self, node):
        pass