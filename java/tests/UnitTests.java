package tests;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import cryptotest.Hex;
import cryptotest.Serialization;
import cryptotest.model.Address;
import cryptotest.model.Attachement;
import cryptotest.model.BodyType;
import cryptotest.model.messages.InviteRegistration;

public class UnitTests {
    @Test
    public void testRSA_PKCS1_Sign() {
    	InviteRegistration r = new InviteRegistration(
    			"http://api.bitstamp.com/teleferic",
                new Address("2nPfgysH5URwM6mcknqwNEgbCi9C36oQsdZ"),
                new Address("2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK"),
                Hex.ToByteArray("0f2e63df2c59f0b4108d4ae187be24718d9bcaa64903f883d38b9a81d1cca664"),
                1,
                Hex.ToByteArray("29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e"));
    	System.out.println("test 1");
    }

    @Test
    public void testSerialization_Enum() {
    	String r = (String)Serialization.ToStruct(BodyType.InviteRegistration);
    	
    	assertEquals(r, "InviteRegistration");
    }

    @Test
    public void testSerialization_Attachement() {
    	Attachement a = new Attachement(Hex.ToByteArray("00"), Hex.ToByteArray("01"), Hex.ToByteArray("02"), Hex.ToByteArray("03"), new ArrayList<byte[]>());
   
    	Object obj = Serialization.ToStruct(a);
    	
    	System.out.println(obj);
    }


    @Test
    public void testSerialization_InviteRegistration_Pack() throws Exception{
    	InviteRegistration a = new InviteRegistration("http://api.bitstamp.com/teleferic",
                new Address("2nPfgysH5URwM6mcknqwNEgbCi9C36oQsdZ"),
                new Address("2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK"),
                Hex.ToByteArray("0f2e63df2c59f0b4108d4ae187be24718d9bcaa64903f883d38b9a81d1cca664"),
                1,
                Hex.ToByteArray("29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e"));
   
    	byte[] bytes = Serialization.Pack(a);
    	
    	assertEquals(Hex.FromByteArray(bytes), "9692ac626f6f737472617041646472d923326e506667797348355552774d366d636b6e71774e4567624369394333366f5173645a92ac626f6f73747261704e6f6465d921687474703a2f2f6170692e6269747374616d702e636f6d2f74656c65666572696392aa696e766974654e616d65c42d29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e92ac6f66666572696e6741646472d923326e39684c4c7a68706e3475655248596f4a42746352374a6b6d746356346f6d7a4c4b92ba73657276696365416e6e6f756e63656d656e744d657373616765c4200f2e63df2c59f0b4108d4ae187be24718d9bcaa64903f883d38b9a81d1cca66492b1736572766963654f66666572696e67494401");
    }

    
    
    
    
    
}
