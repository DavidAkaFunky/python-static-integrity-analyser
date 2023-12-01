class Constant:
    
    """Constant(constant value, string? kind)"""
    
    def __init__(self, value, kind):
        self.value = value
        self.kind = kind

    def __repr__(self):
        if self.kind is None:
            return "Constant({})".format(self.value)
        return "Constant({}, {})".format(self.value, self.kind)
    
    def analyse(self, policy):
        return policy.eval_constant(self)
            
class Name:
    
    """Name(identifier id, expr_context ctx)"""
    
    def __init__(self, id, ctx):
        self.id = id
        self.ctx = ctx

    def __repr__(self):
        return "Name({}, {})".format(self.id, self.ctx)
    
    def analyse(self, policy):
        return policy.eval_name(self)
    
class BinOp:
    
    """BinOp(expr left, operator op, expr right)"""
    
    def __init__(self, left, op, right):
        self.left = left
        self.op = op
        self.right = right

    def __repr__(self):
        return "BinOp({}, {}, {})".format(self.left, self.op, self.right)
    
    def analyse(self, policy):
        return policy.eval_binop(self)
    
class UnaryOp:
    
    """UnaryOp(unaryop op, expr operand)"""
    
    def __init__(self, op, operand):
        self.op = op
        self.operand = operand

    def __repr__(self):
        return "UnaryOp({}, {})".format(self.op, self.operand)
    
    def analyse(self, policy):
        return policy.eval_unaryop(self)
    
class BoolOp:
    
    """BoolOp(boolop op, expr* values)"""
    
    def __init__(self, op, values):
        self.op = op
        self.values = values

    def __repr__(self):
        return "BoolOp({}, {})".format(self.op, self.values)
    
    def analyse(self, policy):
        return policy.eval_boolop(self)
    
class Compare:
    
    """Compare(expr left, cmpop* ops, expr* comparators)"""
    
    def __init__(self, left, ops, comparators):
        self.left = left
        self.ops = ops
        self.comparators = comparators

    def __repr__(self):
        return "Compare({}, {}, {})".format(self.left, self.ops, self.comparators)
    
    def analyse(self, policy):
        return policy.eval_compare(self)
    
class Call:
    
    """Call(expr func, expr* args, keyword* keywords)"""
    
    def __init__(self, func, args, keywords):
        self.func = func
        self.args = args
        self.keywords = keywords

    def __repr__(self):
        return "Call({}, {}, {})".format(self.func, self.args, self.keywords)
    
    def analyse(self, policy):
        return policy.eval_call(self)
    
class Attribute:
    
    """Attribute(expr value, identifier attr, expr_context ctx)"""
    
    def __init__(self, value, attr, ctx):
        self.value = value
        self.attr = attr
        self.ctx = ctx

    def __repr__(self):
        return "Attribute({}, {}, {})".format(self.value, self.attr, self.ctx)
    
    def analyse(self, policy):
        return policy.eval_attribute(self)
    

########### STATEMENTS ###########

class Expr:
    
    """Expr(expr value)"""
    
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "Expression({})".format(self.value)

    def analyse(self, policy):
        return policy.eval_expr(self)
    
class Assign:
    
    """Assign(expr* targets, expr value, string? type_comment)"""
    
    def __init__(self, targets, value, type_comment):
        self.targets = targets
        self.value = value
        self.type_comment = type_comment

    def __repr__(self):
        return "Assign({}, {}, {})".format(self.targets, self.value, self.type_comment)
    
    def analyse(self, policy):
        return policy.eval_assign(self)
    
class If:

    """If(expr test, stmt* body, stmt* orelse)"""
    
    def __init__(self, test, body, orelse):
        self.test = test
        self.body = body
        self.orelse = orelse

    def __repr__(self):
        return "If({}, {}, {})".format(self.test, self.body, self.orelse)
    
    def analyse(self, policy):
        return policy.eval_if(self)

class While:
    
    """While(expr test, stmt* body, stmt* orelse)"""
    
    def __init__(self, test, body, orelse):
        self.test = test
        self.body = body
        self.orelse = orelse

    def __repr__(self):
        return "While({}, {}, {})".format(self.test, self.body, self.orelse)
    
    def analyse(self, policy):
        return policy.eval_while(self)