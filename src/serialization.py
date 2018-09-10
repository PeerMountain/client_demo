import msgpack
import datetime
from enum import Enum
import binascii


class MsgpackSerialize():
    """ Deterministric serialization to msgpack (sorts dictionnary and object fields)"""
    
    @staticmethod
    def to_struct(obj):
        if hasattr(obj, "to_struct"):
            result =  obj.to_struct()
            return result
        elif hasattr(obj, "__dataclass_fields__"):
            result = []
            for k in sorted(obj.__dataclass_fields__.keys()):
                v = getattr(obj, k)
                result.append((k, MsgpackSerialize.to_struct(v)))
            return result
        elif isinstance(obj, Enum):
            return obj.name
        elif type(obj) in (list, tuple):
            return [MsgpackSerialize.to_struct(v) for v in obj]
        elif type(obj) is dict:
            keys = sorted(obj.keys())
            return [(MsgpackSerialize.to_struct(k), MsgpackSerialize.to_struct(obj[k])) for k in keys]
        elif type(obj) is datetime.date:
            return obj.isoformat()
        else:
            return obj

    @staticmethod
    def pack(obj):
        res = MsgpackSerialize.to_struct(obj)
        result = msgpack.packb(res, use_bin_type=True)
        return result
    
    @staticmethod
    def from_struct(objtype, data):
        if data is None:
            return None
        if hasattr(objtype, "from_struct"):
            return objtype.from_struct(data)
        elif hasattr(objtype, "__dataclass_fields__"):
            initilizers = {}
            for (k, value) in data: 
                field = objtype.__dataclass_fields__[k]
                #for k, field in objtype.__dataclass_fields__.items():
                initilizers[k] = MsgpackSerialize.from_struct(field.type, value)
            return objtype(**initilizers)
        elif isinstance(objtype, type) and issubclass(objtype, Enum):
            return objtype[data]
        elif hasattr(objtype, "__origin__") and objtype.__origin__ in (list, tuple):
            listype= objtype.__args__[0]
            return [MsgpackSerialize.from_struct(listype, v) for v in data]
        elif hasattr(objtype, "__origin__") and objtype.__origin__ is dict:
            dict_src, dict_dest = objtype.__args__[0], objtype.__args__[1]
            return dict((MsgpackSerialize.from_struct(dict_src, k), MsgpackSerialize.from_struct(dict_dest, v)) for k, v in data)
        elif objtype is datetime.date:
            return datetime.date.fromisoformat(data)
        else:
            return data

    @staticmethod
    def unpack(objtype, data):
        struct = msgpack.unpackb(data, raw=False)
        return MsgpackSerialize.from_struct(objtype, struct)
