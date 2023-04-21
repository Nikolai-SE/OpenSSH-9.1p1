import clang.cindex
import os
import subprocess
import tempfile


# Варианты использования clang с помощью Python и CPP.
# Для работы нужен libclang (он же предоставляет биндинги для python)
# pip install libclang

def traverseAST(c_file='sshd.c'):
    """
    :param c_file:   the path to the C file
    :return:
    """

    # Create an index
    index = clang.cindex.Index.create()

    # Parse the C file
    tu = index.parse(c_file)

    # Traverse the AST to extract information
    def visit_node(node):
        if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            print('Found function definition:', node.spelling)
        for child_node in node.get_children():
            visit_node(child_node)

    visit_node(tu.cursor)


def generate_call_graph(c_file='sshd.c'):
    """
    Следующим сниппетом можно сгенерировать call graph для файла:
    :param c_file: the path to the C file
    :return:
    """

    # Create an index
    index = clang.cindex.Index.create()

    # Parse the C file
    tu = index.parse(c_file)

    # Traverse the AST to extract information

    current_function = None

    def visit_node(node):
        global current_function
        if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            # print('Found function definition:', node.spelling)
            current_function = node.spelling
        if node.kind == clang.cindex.CursorKind.CALL_EXPR:
            print(current_function, '->', node.spelling)
        for child_node in node.get_children():
            visit_node(child_node)

    visit_node(tu.cursor)


def generation_call_graph_by_clang(c_file='sshd.c'):
    # Create an index
    index = clang.cindex.Index.create()

    # Parse the C file
    tu = index.parse(c_file)

    # Create a dictionary to store the call graph
    call_graph = {}

    # Traverse the AST to extract information
    def visit_node(node, parent):
        if node.kind == clang.cindex.CursorKind.CALL_EXPR:
            caller = parent.spelling
            callee = node.spelling
            if caller not in call_graph:
                call_graph[caller] = []
            call_graph[caller].append(callee)
        elif node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            parent = node
        for child_node in node.get_children():
            visit_node(child_node, parent)

    visit_node(tu.cursor, None)

    # Write the call graph to a DOT file
    dot_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    dot_file.write('digraph call_graph {\n')
    for caller, callees in call_graph.items():
        for callee in callees:
            dot_file.write('  "{}" -> "{}";\n'.format(caller, callee))
    dot_file.write('}\n')
    dot_file.close()

    # Use DOT to create a PNG file from the DOT file
    png_file = os.path.splitext(c_file)[0] + '.png'
    subprocess.call(['dot', '-Tpng', '-o', png_file, dot_file.name])

    # Delete the DOT file
    os.unlink(dot_file.name)


def make_CFG_graph_to_free(c_file='sshd.c'):
    # Create an index
    index = clang.cindex.Index.create()

    # Parse the C file
    tu = index.parse(c_file)

    # Create a dictionary to store the call graph
    call_graph = {}
    # Reverse call graph
    call_graph_r = {}

    # Traverse the AST to extract information
    def visit_node(node, parent):
        if node.kind == clang.cindex.CursorKind.CALL_EXPR:
            caller = parent.spelling
            callee = node.spelling
            if caller not in call_graph:
                call_graph[caller] = []
            if callee not in call_graph_r:
                call_graph_r[callee] = []
            call_graph[caller].append(callee)
            call_graph_r[callee].append(caller)

        elif node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            parent = node
        for child_node in node.get_children():
            visit_node(child_node, parent)

    visit_node(tu.cursor, None)

    func_uses_free = set()

    def mark_free_funcs(func):
        global func_uses_free
        func_uses_free.add(func)
        if call_graph_r.get(func) is None: return
        for next_func in call_graph_r[func]:
            if next_func not in func_uses_free:
                func_uses_free.add(next_func)
                mark_free_funcs(next_func)

    mark_free_funcs('free')

    # Write the call graph to a DOT file
    dot_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    dot_file.write('digraph call_graph {\n')
    for caller, callees in call_graph.items():
        for callee in callees:
            if callee in func_uses_free:
                dot_file.write('  "{}" -> "{}";\n'.format(caller, callee))
    dot_file.write('}\n')
    dot_file.close()

    # Use DOT to create a PNG file from the DOT file
    png_file = os.path.splitext(c_file)[0] + '.png'
    subprocess.call(['dot', '-Tpng', '-o', png_file, dot_file.name])

    # Delete the DOT file
    os.unlink(dot_file.name)
