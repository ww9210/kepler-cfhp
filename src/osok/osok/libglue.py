# THIS FILE IS OBSOLETE
# http://www.qtrac.eu/pyclassmulti.html
def add_methods_from(*modules):
    def decorator(Class):
        for module in modules:
            for method in getattr(module, "__methods__"):
                setattr(Class, method.__name__, method)
        return Class
    return decorator

def register_method(methods):
    def register_method(method):
        methods.append(method)
        return method # Unchanged
    return register_method