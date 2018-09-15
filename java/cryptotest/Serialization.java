package cryptotest;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import cryptotest.model.BodyType;

public class Serialization {
	
	public static Object ToStructFromObject(Object obj) {
		Class cls = obj.getClass();
		Method m;
		try {
    		m = cls.getMethod("ToStruct", null);
    	} catch (NoSuchMethodException e) {
    		return (null);
    	}
		try {
	    	return (m.invoke(obj));
		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			return null;
		}
	}
	public static Object ToStruct(Object obj) {
	    Class cls = obj.getClass();
		
		Object res = ToStructFromObject(obj);
		System.out.println("res");
	    System.out.println(res);
	    if (res != null)
			return res;
	    if (cls.isEnum()) {
	    	return ((Enum)obj).name();
	    }
	    else if (cls == byte[].class) {
	    	return (obj);
	    }
	    else if (cls.isPrimitive()) {
	    	return (obj);
	    } else { // Class
	    	List<Object> result = new ArrayList<Object>(); 
	    	Field[] allFields = cls.getDeclaredFields();
	    	Arrays.sort(allFields, (a,b) -> a.getName().compareTo(b.getName()));

	    	for (Field field : allFields) {
	    		List<Object> l = new ArrayList<Object>();
	    		Object value;
	    		try {
	    			value = field.get(obj);
	    		} catch (IllegalAccessException e) {
	    			continue;
	    		}
	    		l.add(field.getName());
	    		System.out.println(value);
	    	    l.add(Serialization.ToStruct(value));
	    		result.add(l);
	    	}
	    	// List fields and append to result list result.append((k, MsgpackSerialize.to_struct(v)))
	    	return result;
	    }
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
