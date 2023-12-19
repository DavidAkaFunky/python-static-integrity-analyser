import ast
from analyser_classes import *
from functools import reduce

class ASTVisitor(ast.NodeVisitor):
   
	def __init__(self, patterns):
		self.policy = Policy([Pattern.from_json(pattern) for pattern in patterns])
		self.vulnerabilities = Vulnerabilities()
		self.multilabelling = MultiLabelling()
   
	########### EXPRESSIONS ###########
	
	def visit_Name(self, node):
		"""A named expression.
		   This AST node is produced by the assignment expressions operator
		(also known as the walrus operator).
		   As opposed to the Assign node in which the first argument can be multiple nodes,
		in this case both target and value must be single nodes."""
  
		multilabel = MultiLabel.create_empty()
		simple_node = Node(node.id, node.lineno)
  
		if self.multilabelling.is_variable_initialised(node.id):
			return simple_node, self.multilabelling.get_multilabel(node.id)

		else: # Uninitialised variable, counts as source
			# If our multilabel constructor is correct, we can send self.policy as the 1st argument instead
			multilabel = MultiLabel(self.policy.get_patterns_by_source(node.id), [Label(simple_node)])
			if not multilabel.is_empty() or len(self.policy.get_vulns_by_sanitiser(node.id)) != 0:
				return simple_node, multilabel
			else:
				return simple_node, MultiLabel.create_empty()
   			
	def visit_BinOp(self, node):
		"""A binary operation (like addition or division).
		   op is the operator, and left and right are any expression nodes."""
     
		_, left_multilabel = self.visit(node.left)
		_, right_multilabel = self.visit(node.right)
		return None, MultiLabel.combine(left_multilabel, right_multilabel)
			
	def visit_UnaryOp(self, node):
		"""A unary operation. op is the operator, and operand any expression node."""
  
		_, multiLabel = self.visit(node.operand)
		return None, multiLabel
			
	def visit_BoolOp(self, node):
		"""A boolean operation, 'or' or 'and'. op is Or or And.
		   values are the values involved. 
		   Consecutive operations with the same operator, such as a or b or c,
		are collapsed into one node with several values.
		   This doesn't include not, which is a UnaryOp."""
     
		multilabel = MultiLabel.create_empty()
		for value in node.values:
			_, value_multilabel = self.visit(value)
			multilabel = MultiLabel.combine(multilabel, value_multilabel)
		return None, multilabel
			
	def visit_Compare(self, node):
		"""A comparison of two or more values.
		   left is the first value in the comparison, ops the list of operators,
		and comparators the list of values after the first element in the comparison."""
  
		_, multilabel = self.visit(node.left)
		for comparator in node.comparators:
			_, cmp_multilabel = self.visit(comparator)
			multilabel = MultiLabel.combine(multilabel, cmp_multilabel)
		return None, multilabel
			
	def visit_Call(self, node):
		"""A function call.
		   func is the function, which will often be a Name or Attribute object. Of the arguments:
		   - args holds a list of the arguments passed by position.
		   - keywords holds a list of keyword objects representing arguments passed by keyword.
		   When creating a Call node, args and keywords are required, but they can be empty lists."""

		func_variable, return_multilabel = self.visit(node.func)

		for arg in node.args + node.keywords:
			_, arg_multilabel = self.visit(arg)
			return_multilabel = MultiLabel.combine(return_multilabel, arg_multilabel)
			self.vulnerabilities.add_vulnerability(self.policy, arg_multilabel, func_variable)

		return func_variable, return_multilabel
			
	def visit_Attribute(self, node):
		"""Attribute access, e.g. d.keys.
		   value is a node, typically a Name.
		   attr is a bare string giving the name of the attribute,
		and ctx is Load, Store or Del according to how the attribute is acted on."""
  
		multilabel_attr = self.visit(node.attr)
  
		## WORK IN PROGRESS (not sure yet)
		if type(node.value) == ast.Name:
			for label in multilabel_attr.get_labels():
				for pair in label.get_pairs():
					label.add_pair([node.value.id, pair[1]])
		_, multilabel = self.visit(node.value)
		new_multilabel = MultiLabel.combine(multilabel, multilabel_attr)
  
		return Node(node.value, node.lineno), new_multilabel
		
			
	########### STATEMENTS ###########
		
	def visit_Expr(self, node):
		"""When an expression, such as a function call, 
		appears as a statement by itself with its return value not used or stored,
		it is wrapped in this container.
		   value holds one of the other nodes in this section, 
		a Constant, a Name, a Lambda, a Yield or YieldFrom node."""
  
		_, multilabel = self.visit(node.value)
		return None, multilabel
		
	def visit_Assign(self, node):
		"""An assignment. targets is a list of nodes, and value is a single node.
		   Multiple nodes in targets represents assigning the same value to each.
		   Unpacking is represented by putting a Tuple or List within targets."""

		value = self.visit(node.value)
		print(value)
		if value is None:
			return None, None
		value_variable, value_multilabel = value
		targets = []
  
		for target in node.targets:
			# Converting to iterable to allow return unpacking
			# If it's a tuple, visit may return a list of (name, multilabel)
			# Otherwise, it returns just a (name, multilabel),
			# so making it a list allows concatenation of the results
			target_result = self.visit(target)
			if type(target_result) != list:
				target_result = [target_result]
			targets += target_result
		print(targets)
		for target_node, target_multilabel in targets:
			target_multilabel = MultiLabel.combine(value_multilabel, target_multilabel)
			target_multilabel.sanitise(self.policy, value_variable)
			self.vulnerabilities.add_vulnerability(self.policy, target_multilabel, value_variable)
			self.multilabelling.set_multilabel(target_node.get_name(), target_multilabel)
		print("_______________")
		return None, None
   
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