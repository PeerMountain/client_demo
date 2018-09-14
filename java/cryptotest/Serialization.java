
public class Serialization {
	
	public static Object ToStruct(Object obj) {
	    Class cls = obj.getClass();
	    if (cls.isEnum()) {
	    	return ("uhu");
	    }
	    return ("");
	}
	/* @staticmethod
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
            		*/

	
	
}
