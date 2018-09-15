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
}
