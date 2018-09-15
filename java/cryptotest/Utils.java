package cryptotest;

import java.lang.reflect.Method;

public class Utils {
	
	public static boolean HasMethod(Class cls, String name) 
	{
		Method[] methods = cls.getMethods();
		for (Method m : methods) {
		  if (m.getName().equals(name)) {
		    return true;
		  }
		}
		return false;
	}
	public static boolean isPrimitiveOrWrapped(Class<?> cls) {
		if (cls.isPrimitive())
			return true;
	    return cls.equals(Boolean.class) || 
		       cls.equals(String.class) || 
	    	   cls.equals(Integer.class) ||
	    	   cls.equals(Character.class) ||
	    	   cls.equals(Byte.class) ||
	    	   cls.equals(Short.class) ||
	    	   cls.equals(Double.class) ||
	    	   cls.equals(Long.class) ||
	    	   cls.equals(Float.class);
	}
	
}
