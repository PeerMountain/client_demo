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
    public void testSerialization_InviteRegistration() {
    	InviteRegistration a = new InviteRegistration("http://api.bitstamp.com/teleferic",
                new Address("2nPfgysH5URwM6mcknqwNEgbCi9C36oQsdZ"),
                new Address("2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK"),
                Hex.ToByteArray("0f2e63df2c59f0b4108d4ae187be24718d9bcaa64903f883d38b9a81d1cca664"),
                1,
                Hex.ToByteArray("29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e"));
   
    	Object obj = Serialization.ToStruct(a);
    	
    	System.out.println(obj);
    }


}
