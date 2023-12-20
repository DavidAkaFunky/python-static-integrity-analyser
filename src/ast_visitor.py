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
  
		simple_node = Node(node.id, node.lineno)
		multilabel = MultiLabel(self.policy.get_patterns_by_source(node.id), [Label(simple_node)])
		
		if self.multilabelling.is_variable_initialised(node.id):
			return simple_node, MultiLabel.combine(self.multilabelling.get_multilabel(node.id), multilabel)

		# Uninitialised variable -> Check if source or sanitiser
		if not multilabel.is_empty() or len(self.policy.get_vulns_by_sanitiser(node.id)) != 0:
			return simple_node, multilabel

		# It's neither, return multilabel where it's a source in all patterns
		return simple_node, MultiLabel.create_for_uninitialised_variable(self.policy, simple_node)
   			
	def visit_BinOp(self, node):
		"""A binary operation (like addition or division).
		   op is the operator, and left and right are any expression nodes."""

		left = self.visit(node.left)
		if left is None:
			left_multilabel = MultiLabel.create_empty()
		else:
			left_multilabel = left[1]
   
		right = self.visit(node.right)
		if right is None:
			return None, left_multilabel
		return None, MultiLabel.combine(left_multilabel, right[1])
			
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
  
		func_variable, _ = self.visit(node.func)
		return_multilabel = MultiLabel(self.policy.get_patterns_by_source(func_variable.get_name()), [Label(func_variable)])

		for arg_node in node.args + node.keywords:
			arg = self.visit(arg_node)
			if arg is None:
				continue
			_, arg_multilabel = arg
			return_multilabel = MultiLabel.combine(return_multilabel, arg_multilabel)
		
		return_multilabel.sanitise(self.policy, func_variable)
		self.vulnerabilities.add_vulnerability(self.policy, return_multilabel, func_variable)

		return func_variable, return_multilabel
			
	def visit_Attribute(self, node):
		"""Attribute access, e.g. d.keys.
		   value is a node, typically a Name.
		   attr is a bare string giving the name of the attribute,
		and ctx is Load, Store or Del according to how the attribute is acted on."""
  
		# FIXME Maybe return a list containing:
		# [(value_node, value_multilabel), (value_and_attr_node, value_and_attr_multilabel)]

		value_node, value_multilabel = self.visit(node.value)
		attr_node = Node(node.attr, node.lineno)
  
		attr_multilabel = MultiLabel(self.policy.get_patterns_by_source(node.attr), [Label(attr_node)])
		if self.multilabelling.is_variable_initialised(node.attr):
			attr_multilabel = self.multilabelling.get_multilabel(node.attr)

		# Uninitialised variable -> Check if source or sanitiser
		if attr_multilabel.is_empty() and len(self.policy.get_vulns_by_sanitiser(node.attr)) == 0:
			attr_multilabel = MultiLabel.create_for_uninitialised_variable(self.policy, attr_node)
  
		value_node.add_attribute(node.attr)
		return value_node, MultiLabel.combine(value_multilabel, attr_multilabel)
		
			
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

		#print(type(node.value))
		value = self.visit(node.value)
		#print(value)
		if value is None:
			value_multilabel = MultiLabel.create_empty()
		else:
			_, value_multilabel = value
		targets = []

		for target in node.targets:
			# Converting to iterable to allow return unpacking
			# If it's a tuple, visit may return a list of (name, multilabel)
			# Otherwise, it returns just a (name, multilabel),
			# so making it a list allows concatenation of the results
			#print(type(target))
			target_result = self.visit(target)
			if type(target_result) != list:
				target_result = [target_result]
			targets += target_result
   
		for target_node, _ in targets:
			#print(target_node, target_multilabel)
			self.vulnerabilities.add_vulnerability(self.policy, value_multilabel, target_node)
			self.multilabelling.set_multilabel(target_node.get_name(), value_multilabel)
			#print(self.multilabelling)
		#print("_______________")
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