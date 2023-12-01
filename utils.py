def list_union(l1: list, l2: list):
    return list(set(l1).union(set(l2)))

def list_intersection(l1: list, l2: list):
    return list(set(l1).intersection(set(l2)))

def add_to_dict(dictionary: dict, key: any, value: any):
    try:
        dictionary[key].append(value)
    except KeyError:
        dictionary[key] = [value]