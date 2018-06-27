import androguard.misc
import androguard.decompiler.dad.decompile
import re

import analysis
import astparse
import utils


def resolve_identifier(context, identifier):
    """
    Recursively resolves identifiers defined in 'context'
    """
    start = identifier
    while str(start) in context:
        start = context.get(str(start))
    if type(start) is astparse.Literal:
        start = start.value
    return start


def analyze_method(dx, method):
    """
    Analyze Androguard MethodAnalysis object in 'method' for Xposed hooks
    """
    hooks = []
    invocations = []
    dfs_methods = [(method, {})]

    def dfs_callback(context, node):
        if node[0] == "MethodInvocation":
            inv = astparse.MethodInvocation(node)
            invocations.append((inv, context.copy()))

            print("found invocation:", inv.triple, node)
            m = dx.get_method_analysis_by_name(utils.to_dv_notation(inv.triple[0]), inv.triple[1], inv.triple[2])
            if m and not m.is_external():
                print("to analyze:", m.get_method())
                dfs_methods.append((dx.get_method(m.get_method()), context.copy()))

            return False
        if node[0] == "LocalDeclarationStatement":
            decl = astparse.LocalDeclarationStatement(node)
            context[str(decl.name)] = decl.value
            return False
        elif node[0] == "Assignment":
            assignment = astparse.Assignment(node)
            context[str(assignment.lhs)] = assignment.rhs
            return False

        return True

    while dfs_methods:
        (m, context) = dfs_methods.pop()
        print("analyzing", m, context)

        decompiler = androguard.decompiler.dad.decompile.DvMethod(m)
        decompiler.process(doAST=True)
        ast = decompiler.ast

        for p in ast["params"]:
            param = astparse.Parameter(p)
            if str(param.name) not in context:
                context[str(param.name)] = param

        astparse.dfs(ast['body'], lambda n: dfs_callback(context, n))

    for inv, ctx in invocations:
        if not type(inv.base) is astparse.TypeName:
            continue
        if (inv.base.name == "de/robv/android/xposed/XposedHelpers" and \
            (inv.name == "findAndHookMethod" or \
             inv.name == "findAndHookConstructor")) or \
            (inv.base.name == "de/robv/android/xposed/XposedBridge" and \
             (inv.name == "hookAllConstructors")):

            if type(inv.params[-1]) is not astparse.ClassInstanceCreation:
                # hook objects are passed as an Object array of N elements.
                # where N-1 elements are the classes of the target function's parameters
                # and the last/N-th element contains the XC_MethodHook instance, which
                # we are trying to extract.
                hook_array = inv.params[-1]
                hook_array_size = ctx[str(hook_array)].param.value
                hook_obj_identifier = "{0}[{1}]".format(hook_array, int(hook_array_size) - 1)
                hook_obj = resolve_identifier(ctx, hook_obj_identifier)
            else:
                # hookAllConstructors receives a direct XC_MethodHook instance
                hook_obj = inv.params[-1]

            # get hook class if referenced directly in a class instance creation
            if isinstance(hook_obj, astparse.ClassInstanceCreation):
                hook_obj = hook_obj.type

            # extract class names from calls to XposedHelpers.findClass(className, classLoader)
            # a pattern common in Xposed module hooks
            cls = resolve_identifier(ctx, inv.params[0])
            if isinstance(cls, astparse.MethodInvocation) and isinstance(cls.base, astparse.TypeName):
                if cls.base.name == "de/robv/android/xposed/XposedHelpers" and cls.name == "findClass":
                    # resolve parameter once more in case a local/variable was passed
                    cls = resolve_identifier(ctx, cls.params[0])
            # class literals
            elif isinstance(cls, astparse.TypeName):
                cls = cls.name.replace("/", ".")

            targetmethod = resolve_identifier(ctx, inv.params[-2]) if inv.name == "findAndHookMethod" else None

            # we can't deal with dynamic class names in static analysis
            if type(cls) is not str:
                print("Target class ({0}) is dynamic, skipping hook {0}#{1}".format(cls, targetmethod))
                continue

            # also skip dynamic method names
            if not type(targetmethod) in [str, type(None)]:
                print("Target method ({0}) is dynamic, skipping hook {0}#{1}".format(cls, targetmethod))
                continue

            # and dynamic hook objects
            if type(hook_obj) is not astparse.TypeName:
                print("Callback object ({0}) is dynamic, skipping hook {1}#{2}".format(hook_obj, cls, targetmethod))
                continue

            callback = hook_obj.name

            hook = analysis.Hook(cls, targetmethod, callback)

            hooks.append(hook)

    print(hooks)
    return hooks


def analyze(a, d, dx):
    if not (a and d and dx):
        print("Could not analyze..")
        return None

    ep_name = utils.get_xposed_entrypoint(a)
    if ep_name is None:
        print("No Xposed entrypoint found")
        return

    print("Xposed entrypoint:", ep_name)
    ep_method = dx.get_method_analysis_by_name(utils.to_dv_notation(ep_name),
                                               "handleLoadPackage",
                                               "(Lde/robv/android/xposed/callbacks/XC_LoadPackage$LoadPackageParam;)V")

    return hooks

def analyze_callback(a, d, dx, callback):
    result = []
    decompiler = androguard.decompiler.dad.decompile.DvMethod(dx.get_method(callback.get_method()))
    decompiler.process(doAST=True)
    ast = decompiler.ast
    context = {}

    for p in ast["params"]:
        param = astparse.Parameter(p)
        context[str(param.name)] = param

    invocations = []
    def dfs_callback(node):
        parsed = astparse.parse_expression(node)
        if type(parsed) is not list:
            print("callback:", parsed)
        if node[0] == "MethodInvocation":
            invocations.append((parsed, context.copy()))
        if node[0] == "LocalDeclarationStatement":
            context[str(parsed.name)] = parsed.value
        elif node[0] == "Assignment":
            context[str(parsed.lhs)] = parsed.rhs
        return True

    astparse.dfs(ast['body'], dfs_callback)

    for inv, ctx in invocations:
        if inv.name == "setResult" and inv.triple[0] == "de/robv/android/xposed/XC_MethodHook$MethodHookParam":
            result.append("Setting return value to " + str(inv.params[0]))
        elif inv.triple[0] == "de/robv/android/xposed/XposedHelpers":
            rex = re.match(r"set(.*)Field", inv.name)
            if rex:
                result.append("Setting {0} of {1} to".format(rex[1],
                                                             resolve_identifier(inv.params[1]),
                                                             resolve_identifier(inv.params[2])))
            rex = re.match(r"get(.*)Field", inv.name)
            if rex:
                result.append("Getting {0} field \"{1}\" of {2}".format(rex[1],
                                                                        resolve_identifier(ctx, inv.params[1]),
                                                                        resolve_identifier(ctx, inv.params[0])))

    return result

def analyze_hooks(a, d, dx, hook):
    result = {}
    cbname = hook.callbackobj.replace("$", "\$")  # $ needs to be escaped as callgraph generator expects regexps

    for cb in dx.find_methods(utils.to_dv_notation(cbname),
                              "^(after|before)HookedMethod$",
                              "\(Lde/robv/android/xposed/XC_MethodHook\$MethodHookParam;\)V"):
        name = cb.get_method().get_name()
        analysis = analyze_callback(a, d, dx, cb)
        if analysis:
            result[name] = analysis

    return result
