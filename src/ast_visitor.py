import ast
from analyser_classes import *
from functools import reduce

class ASTVisitor(ast.NodeVisitor):
   
	def __init__(self, patterns):
		self.policy = Policy([Pattern.from_json(pattern) for pattern in patterns])
		self.vulnerabilities = Vulnerabilities()
		self.multilabelling = MultiLabelling()
		self.conditions_stack = []

	def __update_test(self, test_node, pos = None):
		test = self.visit(test_node)
  
		if test is None:
			return None

		test = test[1]

		imp = self.policy.get_implicit_patterns_multilabel(test)

		for k in test.get_vulns():
			if k not in imp.get_vulns():
				del test.label_map[k]

		if pos is None:
			pos = len(self.conditions_stack) - 1
			self.conditions_stack.append(test)
		else:
			self.conditions_stack[pos] = test

		return pos
 
	def __get_variable_multilabel(self, name, lineno):
		simple_node = Node(name, lineno)
		multilabel = MultiLabel(self.policy.get_patterns_by_source(name), [Label(simple_node)])
		
		if self.multilabelling.is_variable_initialised(name):
			multilabel = MultiLabel.combine(self.multilabelling.get_multilabel(name), multilabel)

			# Variables not present in *all* if/else branches 
   			# contain a false "non-initialised" source with lineno = -1.
			# This is fixed by replacing that value with the node's lineno
			# before returning the multilabel
			multilabel.fix_lineno(lineno)
			return simple_node, multilabel

		# Uninitialised variable -> Return multilabel where it's a source in all patterns
		return simple_node, MultiLabel.create_for_uninitialised_variable(self.policy, simple_node)
		
	
	########### EXPRESSIONS ###########
	
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
			cmp_multilabel = self.visit(comparator)
			if cmp_multilabel is None:
				cmp_multilabel = MultiLabel.create_empty()
			else:
				_, cmp_multilabel = cmp_multilabel
			multilabel = MultiLabel.combine(multilabel, cmp_multilabel)

		return None, multilabel
			
	def visit_Call(self, node):
		"""A function call.
		   func is the function, which will often be a Name or Attribute object. Of the arguments:
		   - args holds a list of the arguments passed by position.
		   - keywords holds a list of keyword objects representing arguments passed by keyword.
		   When creating a Call node, args and keywords are required, but they can be empty lists."""

		func_variables, _ = self.visit(node.func)
   
		if type(func_variables) != list:
			func_variables = [func_variables]
		
		return_multilabel = MultiLabel.create_empty()

		for arg_node in node.args + node.keywords:
			arg = self.visit(arg_node)
			if arg is None:
				arg_multilabel = MultiLabel.create_empty()
			else:
				_, arg_multilabel = arg
			return_multilabel = MultiLabel.combine(return_multilabel, arg_multilabel)
   
		for cond in self.conditions_stack:
			return_multilabel = MultiLabel.combine(return_multilabel, cond)
 
		for func_variable in func_variables:
			return_multilabel.sanitise(self.policy, func_variable)
			self.vulnerabilities.add_vulnerability(self.policy, return_multilabel, func_variable)

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

		all_nodes, value_multilabel = self.visit(node.value)
		if type(all_nodes) != list:
			all_nodes = [all_nodes]

		# Only the attribute is initialised
		for node_ in all_nodes:
			node_.do_not_initialise()
  
		attr_node, attr_multilabel = self.__get_variable_multilabel(node.attr, node.lineno)

		all_nodes.append(attr_node)

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

		value = self.visit(node.value)

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

			target_node, _ = self.visit(target)
	
			if type(target_node) != list:
				target_node = [target_node]
			targets += target_node
  
		for target_node in targets:
			
			for iws in self.conditions_stack:
				value_multilabel = MultiLabel.combine(value_multilabel, iws)
      
			self.vulnerabilities.add_vulnerability(self.policy, value_multilabel, target_node)

			if target_node.should_initialise():
				self.multilabelling.set_multilabel(target_node.get_name(), value_multilabel)

		return None, None
   
	def visit_If(self, node):
		"""An if statement.
		   test holds a single node, such as a Compare node.
		   body and orelse each hold a list of nodes.
		   elif clauses don't have a special representation in the AST,
		but rather appear as extra If nodes within the orelse section of the previous one."""

		test = self.visit(node.test)

		if test is not None:
			multilabel = self.policy.get_implicit_patterns_multilabel(test[1])
			self.conditions_stack.append(multilabel)

		ml1 = deepcopy(self)
		for body_node in node.body:
			ml1.visit(body_node)
		
		ml2 = deepcopy(self)
		for or_else_node in node.orelse:
			ml2.visit(or_else_node)

		ml1.multilabelling.conciliate_multilabelling(self.policy, ml2.multilabelling)
		ml1.vulnerabilities.conciliate_vulnerabilities(ml2.vulnerabilities)

		self.multilabelling = ml1.multilabelling
		self.vulnerabilities = ml1.vulnerabilities

		if test is not None:
			self.conditions_stack.pop()

		return None, None

	def visit_While(self, node):
		"""A while loop.
		   test holds the condition, such as a Compare node."""

		iws_pos = self.__update_test(node.test)

		ml1 = deepcopy(self)
		found_break = False

		ml_states = [deepcopy(ml1.multilabelling)]
  
		for _ in range(10000):
   
			for body_node in node.body:

				if type(body_node) == ast.Break:
					found_break = True
					break

				if type(body_node) == ast.Continue:
					break
 
				ml1.visit(body_node)
    
			if found_break or ml1.multilabelling in ml_states:
				break

			ml_states.append(deepcopy(ml1.multilabelling))
   
			ml1.__update_test(node.test, iws_pos)

		if not found_break: # No longer an implicit flow

			self.multilabelling = ml1.multilabelling
			self.vulnerabilities = ml1.vulnerabilities
   
			if iws_pos is not None:
				self.conditions_stack.pop()
   
			for or_else_node in node.orelse:
				self.visit(or_else_node)

		else:
      
			ml2 = deepcopy(self)
			for or_else_node in node.orelse:
				ml2.visit(or_else_node)

			ml1.multilabelling.conciliate_multilabelling(self.policy, ml2.multilabelling)
			ml1.vulnerabilities.conciliate_vulnerabilities(ml2.vulnerabilities)

			del ml2

			self.multilabelling = ml1.multilabelling
			self.vulnerabilities = ml1.vulnerabilities

			if iws_pos is not None:
				self.conditions_stack.pop()
		
		del ml1

		return None, None

	def visit_Match(self, node):
		"""A match statement. 
  		   subject holds the subject of the match (the object that is being matched against the cases)
        and cases contains an iterable of match_case nodes with the different cases."""
        
		subject = self.visit(node.subject)
  
		if subject is not None:
			multilabel = self.policy.get_implicit_patterns_multilabel(subject[1])
			self.conditions_stack.append(multilabel)

		conditions_stack = deepcopy(self.conditions_stack)

		for i, case in enumerate(node.cases):
			state = deepcopy(self)
			# We need to keep track of all tested conditions from one case to the following
			state.conditions_stack = conditions_stack
			state.visit(case)
			conditions_stack = state.conditions_stack
			if i == 0:
				cases = [state.multilabelling, state.vulnerabilities]
			else:
				cases[0].conciliate_multilabelling(self.policy, state.multilabelling)
				cases[1].conciliate_vulnerabilities(state.vulnerabilities)

		self.multilabelling.conciliate_multilabelling(self.policy, cases[0])
		self.vulnerabilities.conciliate_vulnerabilities(cases[1])

		if subject is not None:
			self.conditions_stack.pop()
   
		return None, None

	def visit_match_case(self, node):
		"""A single case pattern in a match statement. 
  		   pattern contains the match pattern that the subject will be matched against.
           Note that the AST nodes produced for patterns differ from those produced for expressions, even when they share the same syntax.
		   The guard attribute contains an expression that will be evaluated if the pattern matches the subject.
		   body contains a list of nodes to execute if the pattern matches and the result of evaluating the guard expression is true."""
		
		pattern = self.visit(node.pattern)
  
		if pattern is not None:
			multilabel = self.policy.get_implicit_patterns_multilabel(pattern[1])
			self.conditions_stack.append(multilabel)

		if node.guard is not None:
			guard = self.visit(node.guard)

			if guard is not None:
				multilabel = self.policy.get_implicit_patterns_multilabel(guard[1])
				self.conditions_stack.append(multilabel)

		for body_node in node.body:
			self.visit(body_node)
   
		return None, None
   
	def visit_MatchValue(self, node):
		"""A match literal or value pattern that compares by equality.
  		   value is an expression node.
           Permitted value nodes are restricted as described in the match statement documentation.
           This pattern succeeds if the match subject is equal to the evaluated value."""

		return self.visit(node.value)

	def MatchSingleton(self, node):
		"""A match literal pattern that compares by identity.
		   value is the singleton to be compared against: None, True, or False.
		   This pattern succeeds if the match subject is the given constant."""

		return self.visit(node.value)

	def visit_For(self, node):

		iws_pos = self.__update_test(node.iter)
  
		ml1 = deepcopy(self)
		found_break = False

		ml_states = [deepcopy(ml1.multilabelling)]

		for _ in range(10000):
   
			targets = [node.target] if (type(node.target) != tuple and type(node.target) != list) else node.target
			assignment = ast.Assign(targets, node.iter)
			ml1.visit(assignment)

			for body_node in node.body:

				if type(body_node) == ast.Break:
					found_break = True
					break

				if type(body_node) == ast.Continue:
					break

				ml1.visit(body_node)

			if found_break or ml1.multilabelling in ml_states:
				break

			ml_states.append(deepcopy(ml1.multilabelling))

			ml1.__update_test(node.iter, iws_pos)
		
		if not found_break: # No longer an implicit flow

			self.multilabelling = ml1.multilabelling
			self.vulnerabilities = ml1.vulnerabilities
   
			if iws_pos is not None:
				self.conditions_stack.pop()
   
			for or_else_node in node.orelse:
				self.visit(or_else_node)

		else:
      
			ml2 = deepcopy(self)
			for or_else_node in node.orelse:
				ml2.visit(or_else_node)

			ml1.multilabelling.conciliate_multilabelling(self.policy, ml2.multilabelling)
			ml1.vulnerabilities.conciliate_vulnerabilities(ml2.vulnerabilities)

			del ml2

			self.multilabelling = ml1.multilabelling
			self.vulnerabilities = ml1.vulnerabilities

			if iws_pos is not None:
				self.conditions_stack.pop()
		
		del ml1

		return None, None
        
	def visit_AugAssign(self, node):
		targets = [node.target] if (type(node.target) != tuple and type(node.target) != list) else node.target
		self.visit(ast.Assign(targets, ast.BinOp(node.target, node.op, node.value)))