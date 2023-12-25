import ast
from analyser_classes import *
from functools import reduce

class ASTVisitor(ast.NodeVisitor):
   
	def __init__(self, patterns):
		self.policy = Policy([Pattern.from_json(pattern) for pattern in patterns])
		self.vulnerabilities = Vulnerabilities()
		self.multilabelling = MultiLabelling()
		self.conditions_stack = []
   
	########### EXPRESSIONS ###########
 
	def __get_variable_multilabel(self, name, lineno):
		simple_node = Node(name, lineno)
		multilabel = MultiLabel(self.policy.get_patterns_by_source(name), [Label(simple_node)])
		
		if self.multilabelling.is_variable_initialised(name):
			#print(name, "is initialised")
			return simple_node, MultiLabel.combine(self.multilabelling.get_multilabel(name), multilabel)

		# Uninitialised variable -> Check if source or sanitiser
		#if not multilabel.is_empty() or len(self.policy.get_vulns_by_sanitiser(name)) != 0:
		#	return simple_node, multilabel

		# It's neither, return multilabel where it's a source in all patterns
		return simple_node, MultiLabel.create_for_uninitialised_variable(self.policy, simple_node)
		
	
	def visit_Name(self, node):
		"""A named expression.
		   This AST node is produced by the assignment expressions operator
		(also known as the walrus operator).
		   As opposed to the Assign node in which the first argument can be multiple nodes,
		in this case both target and value must be single nodes."""
  
		return self.__get_variable_multilabel(node.id, node.lineno)
   			
	def visit_BinOp(self, node):
		"""A binary operation (like addition or division).
		   op is the operator, and left and right are any expression nodes."""

		#print("BINOP")

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

		#print("CALL")

		func_variables, _ = self.visit(node.func)
   
		if type(func_variables) != list:
			func_variables = [func_variables]
		
		return_multilabel = MultiLabel.create_empty()

		for arg_node in node.args + node.keywords:
			arg = self.visit(arg_node)
			if arg is None:
				continue
			_, arg_multilabel = arg
			return_multilabel = MultiLabel.combine(return_multilabel, arg_multilabel)
		
		for func_variable in func_variables:
			return_multilabel.sanitise(self.policy, func_variable)
			self.vulnerabilities.add_vulnerability(self.policy, return_multilabel, func_variable)

		# FIXME Only the final argument counts as caller
		# This works fine for calls like x() and x.y()
		# But treats y as a variable in x.y().z()
		for func_variable in func_variables[:-1]:
			return_multilabel = MultiLabel.combine(return_multilabel, self.__get_variable_multilabel(func_variable.get_name(), func_variable.get_line())[1])

		# Workaround for the problem above so that the name of the function always counts as initialised
  		# and doesn't generate non-initialised multilabels (e.g. y in the last example)
		self.multilabelling.set_multilabel(func_variables[-1].get_name(), MultiLabel.create_empty())
	
		return func_variables, MultiLabel.combine(return_multilabel, MultiLabel(self.policy.get_patterns_by_source(func_variables[-1].get_name()), [Label(func_variables[-1])]))
			
	def visit_Attribute(self, node):
		"""Attribute access, e.g. d.keys.
		   value is a node, typically a Name.
		   attr is a bare string giving the name of the attribute,
		and ctx is Load, Store or Del according to how the attribute is acted on."""

		#print("ATTRIBUTE")
		all_nodes, value_multilabel = self.visit(node.value)
		if type(all_nodes) != list:
			all_nodes = [all_nodes]

		# Only the attribute is initialised
		for node_ in all_nodes:
			node_.do_not_initialise()
  
		attr_node, attr_multilabel = self.__get_variable_multilabel(node.attr, node.lineno)

		all_nodes.append(attr_node)
		#print("VALUE MULTILABEL", value_multilabel)
		#print("ATTR MULTILABEL", attr_multilabel)
		return all_nodes, MultiLabel.combine(value_multilabel, attr_multilabel)
		
			
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

		#print("ASSIGN")

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
			target_node, _ = self.visit(target)
	
			if type(target_node) != list:
				target_node = [target_node]
			targets += target_node
  
		#print(value_multilabel)
  
		for target_node in targets:
			self.vulnerabilities.add_vulnerability(self.policy, value_multilabel, target_node)
			if target_node.should_initialise():
				self.multilabelling.set_multilabel(target_node.get_name(), value_multilabel)
		
		#print("MULTILABELLING", self.multilabelling)
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