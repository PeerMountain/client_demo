package cryptotest;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.value.Value;

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
		if (obj == null)
			return obj;
	    Class cls = obj.getClass();
		
		Object res = ToStructFromObject(obj);
		/*System.out.println("res");
	    System.out.println(obj);
	    System.out.println(cls.isPrimitive());
	    System.out.println(cls.toString());*/
	    if (res != null)
			return res;
	    if (cls.isEnum()) {
	    	return ((Enum)obj).name();
	    }
	    if (obj instanceof LocalDate) {
	    	return ((LocalDate)obj).format(DateTimeFormatter.ISO_DATE);
	    }
	    else if (cls == byte[].class) {
	    	return (obj);
	    }
	    else if (cls.isArray()) {
	    	List<Object> result = new ArrayList<Object>(); 
	    	for (Object o : (Object[])obj) {
	    		result.add(Serialization.ToStruct(o));
	    	}
	    	return result;
	    }
	    else if (Utils.isPrimitiveOrWrapped(cls)) {
	    	return (obj);
	    } else { // Class
	    	List<Object> result = new ArrayList<Object>(); 
	    	Field[] allFields = cls.getFields();
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
	    		//System.out.println(field.getName());
	    		//System.out.println(value);
	    	    l.add(Serialization.ToStruct(value));
	    		result.add(l);
	    	}
	    	// List fields and append to result list result.append((k, MsgpackSerialize.to_struct(v)))
	    	return result;
	    }
	}
	public static void PackToBuffer(MessageBufferPacker packer, Object obj) throws Exception {
	    if(obj == null ) {
	    	packer.packNil();
	    }
	    else if(obj instanceof String) {
	        packer.packString((String)obj);
	    }
	    else if(obj instanceof Integer) {
	        packer.packInt((Integer) obj);
	    }
	    else if(obj instanceof Boolean) {
	        packer.packBoolean((boolean)obj);
	    }
	    else if(obj instanceof Double) {
	        packer.packDouble((double)obj);
	    }
	    else if(obj instanceof Long) {
	        packer.packLong((long)obj);
	    }
	    else if(obj instanceof byte[]) {
	    	byte[] bytes = (byte[])obj;

	        packer.packBinaryHeader(bytes.length);
	        packer.writePayload(bytes);
	    }
	    else if(obj instanceof List) {
	    	
	    	List<Object> list = (List<Object>)(obj);
	    	packer.packArrayHeader(list.size());
	    	for (Object o: list) {
	    		PackToBuffer(packer, o);
	    	}
	    }
	
	}
	public static byte[] Pack(Object obj) throws Exception {
		MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();

		Object res = ToStruct(obj);
		PackToBuffer(packer, res);
		return packer.toByteArray();
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
