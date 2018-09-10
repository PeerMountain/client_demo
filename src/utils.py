

def merge_dicts(*dicts):
    result = {}
    for d in dicts:
        result.update(d)
    return result



def read_file_contents(filename):
    with open(filename, "rb") as fin:
        return fin.read()
    
