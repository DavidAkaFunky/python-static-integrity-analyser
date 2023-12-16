import ast
from analyser_classes import *
from functools import reduce

class ASTVisitor(ast.NodeVisitor):
   
	def __init__(self, patterns):
		self.policy = Policy([Pattern.from_json(pattern) for pattern in patterns])
		self.vulnerabilities = Vulnerabilities()
		self.multilabelling = MultiLabelling()
		self.stack = []
   
	########### EXPRESSIONS ###########
	
	def visit_Name(self, node):
		"""A named expression.
		   This AST node is produced by the assignment expressions operator
		(also known as the walrus operator).
		   As opposed to the Assign node in which the first argument can be multiple nodes,
		in this case both target and value must be single nodes."""
		pass
   			
	def visit_BinOp(self, node):
		"""A binary operation (like addition or division).
		   op is the operator, and left and right are any expression nodes."""
		self.visit(node.left)
		self.visit(node.right)
			
	def visit_UnaryOp(self, node):
		"""A unary operation. op is the operator, and operand any expression node."""
		self.visit(node.operand)
			
	def visit_BoolOp(self, node):
		"""A boolean operation, 'or' or 'and'. op is Or or And.
		   values are the values involved. 
		   Consecutive operations with the same operator, such as a or b or c,
		are collapsed into one node with several values.
		   This doesn't include not, which is a UnaryOp."""
		for value in node.values:
			self.visit(value)
			
	def visit_Compare(self, node):
		"""A comparison of two or more values.
		   left is the first value in the comparison, ops the list of operators,
		and comparators the list of values after the first element in the comparison."""
		self.visit(node.left)
		for comparator in node.comparators:
			self.visit(comparator)
			
	def visit_Call(self, node):
		"""A function call.
		   func is the function, which will often be a Name or Attribute object. Of the arguments:
		   - args holds a list of the arguments passed by position.
		   - keywords holds a list of keyword objects representing arguments passed by keyword.
		   When creating a Call node, args and keywords are required, but they can be empty lists."""

		self.visit(node.func)
		if isinstance(node.func, ast.Name):
			func = node.func.id
		elif isinstance(node.func, ast.Attribute):
			func = node.func.attr
		else:
			raise Exception("Function call not supported")

		args = node.args + node.keywords
		args_nodes = []
  
		for arg in args:
			self.visit(arg)
			if isinstance(arg, ast.Name):
				args_nodes.append(Node(arg.id, node.lineno))
			elif isinstance(arg, ast.Attribute):
				args_nodes.append(Node(arg.attr, node.lineno))
			else:
				raise Exception("Function call not supported")
		
		func_variable = Node(func, node.lineno)
		multilabel_source = MultiLabel(self.policy.get_patterns_by_source(func), Label({func_variable}, [[]]))
		multilabel_sanitiser = MultiLabel(self.policy.get_patterns_by_sanitiser(func), Label(set(), [[func_variable]]))
		multilabelling = MultiLabelling()

		for arg_node in args_nodes:
			# TODO Maybe check (somehow) if the argument is a value or a reference
			arg_name = arg_node.get_name()
			multilabelling.add_multilabel(arg_name, multilabel_source)
			multilabelling.add_multilabel(arg_name, multilabel_sanitiser)
			if arg_name in self.multilabelling.get_variable_map():	
				self.vulnerabilities.add_vulnerability(self.policy, self.multilabelling.get_multilabel(arg_name), func_variable)
   
		self.multilabelling = MultiLabelling.combine(self.multilabelling, multilabelling)
  
		for arg_node in args_nodes:
			if arg_node.get_name() in self.multilabelling.get_variable_map():
				self.stack.append(self.multilabelling.get_multilabel(arg_node.get_name()))
   
		self.stack.append(multilabel_source)
		self.stack.append(multilabel_sanitiser)
			
	def visit_Attribute(self, node):
		"""Attribute access, e.g. d.keys.
		   value is a node, typically a Name.
		   attr is a bare string giving the name of the attribute,
		and ctx is Load, Store or Del according to how the attribute is acted on."""
		# Might not be great, since the vulnerability is added to the attribute, not the value
		pass
			
	########### STATEMENTS ###########
		
	def visit_Expr(self, node):
		"""When an expression, such as a function call, 
		appears as a statement by itself with its return value not used or stored,
		it is wrapped in this container.
		   value holds one of the other nodes in this section, 
		a Constant, a Name, a Lambda, a Yield or YieldFrom node."""
		self.visit(node.value)
		
	def visit_Assign(self, node):
		"""An assignment. targets is a list of nodes, and value is a single node.
		   Multiple nodes in targets represents assigning the same value to each.
		   Unpacking is represented by putting a Tuple or List within targets."""
		for target in node.targets:
			self.visit(target)
		self.visit(node.value)
		while len(self.stack) > 0:
			multilabel = self.stack.pop()
			for target in node.targets:
				if isinstance(target, ast.Name):
					target_name = target.id
				elif isinstance(target, ast.Attribute):
					target_name = target.attr
				else:
					raise Exception("Function call not supported")
				self.multilabelling.add_multilabel(target_name, multilabel)
			
	def visit_If(self, node):
		"""An if statement.
		   test holds a single node, such as a Compare node.
		   body and orelse each hold a list of nodes.
		   elif clauses don't have a special representation in the AST,
		but rather appear as extra If nodes within the orelse section of the previous one."""
		pass
			
	def visit_While(self, node):
		"""A while loop.
		   test holds the condition, such as a Compare node."""
		pass