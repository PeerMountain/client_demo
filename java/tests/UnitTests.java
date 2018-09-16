package tests;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import cryptotest.Hex;
import cryptotest.Serialization;
import cryptotest.model.Address;
import cryptotest.model.Attachement;
import cryptotest.model.BodyType;
import cryptotest.model.DestinationType;
import cryptotest.model.ServiceAttestation;
import cryptotest.model.ServiceDocument;
import cryptotest.model.XForm;
import cryptotest.model.messages.Invitation;
import cryptotest.model.messages.InviteRegistration;
import cryptotest.model.messages.ServiceRegistration;

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
    public void testSerialization_InviteRegistration() throws Exception{
    	InviteRegistration a = new InviteRegistration("http://api.bitstamp.com/teleferic",
                new Address("2nPfgysH5URwM6mcknqwNEgbCi9C36oQsdZ"),
                new Address("2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK"),
                Hex.ToByteArray("0f2e63df2c59f0b4108d4ae187be24718d9bcaa64903f883d38b9a81d1cca664"),
                1,
                Hex.ToByteArray("29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e"));
   
    	byte[] bytes = Serialization.Pack(a);
    	
    	assertEquals(Hex.FromByteArray(bytes), "9692ac626f6f737472617041646472d923326e506667797348355552774d366d636b6e71774e4567624369394333366f5173645a92ac626f6f73747261704e6f6465d921687474703a2f2f6170692e6269747374616d702e636f6d2f74656c65666572696392aa696e766974654e616d65c42d29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e92ac6f66666572696e6741646472d923326e39684c4c7a68706e3475655248596f4a42746352374a6b6d746356346f6d7a4c4b92ba73657276696365416e6e6f756e63656d656e744d657373616765c4200f2e63df2c59f0b4108d4ae187be24718d9bcaa64903f883d38b9a81d1cca66492b1736572766963654f66666572696e67494401");
    }

    @Test
    public void testSerialization_ServiceRegistration() throws Exception{
    	ServiceRegistration a = new ServiceRegistration(
    	         "exchange",
    	         new Address("2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK"),
    	         LocalDate.of(2018, 1, 1),
    	         null,
    	         "Bitstamp",
    	         "Cryptocurrency Exchange",
    	         new byte[0], 
    	         new ServiceDocument[] {
    	        		 new ServiceDocument(new XForm(new String[] {"IdentityDocument"}),
	    	        		 		new ServiceAttestation[] {new ServiceAttestation(new Address("2n6HW4uS6Wqq8e4vgkQHnniCu3yrhvjHHHF"),
	    	        		 								  new String[] {"MRZ", "Fraud", "PEP", "Sanction", "SanctionCountry", "CountryRisk", "BlackList"},
	    	                        		 				  DestinationType.SendServiceProvider,
	    	                        		 				  0)}),
    	        		 new ServiceDocument(new XForm(new String[] {"Name", "Surname", "AddressLine1", "AddressLine2", "PostalCode", "City", "Country", "Email", "PhoneNumber"}),
	    	        		 		new ServiceAttestation[] {new ServiceAttestation(new Address("2n6HW4uS6Wqq8e4vgkQHnniCu3yrhvjHHHF"),
	    	        		 								  new String[] {"AddressValidity", "KnownCustomer", "ResidenceClassifier"},
	    	                        		 				  DestinationType.SendServiceProvider,
	    	                        		 				  null)}),
    	        		 new ServiceDocument(new XForm(new String[] {"TermsAndConditions"}),
	    	        		 		new ServiceAttestation[] {})});
    	Object s = Serialization.ToStruct(a);
    	
    	byte[] bytes = Serialization.Pack(a);

    	assertEquals(Hex.FromByteArray(bytes), "9892a9646f63756d656e7473939292b472657175697265644174746573746174696f6e73919492ab6165504d41646472657373d923326e3648573475533657717138653476676b51486e6e69437533797268766a4848484692b06174746573746174696f6e5f6c69737497a34d525aa54672617564a3504550a853616e6374696f6eaf53616e6374696f6e436f756e747279ab436f756e7472795269736ba9426c61636b4c69737492b464657374696e6174696f6e504d41646472657373b353656e645365727669636550726f766964657292b57570646174654672657175656e6379496e446179730092a578666f726d9192ab6669656c64735f696e697491b04964656e74697479446f63756d656e749292b472657175697265644174746573746174696f6e73919492ab6165504d41646472657373d923326e3648573475533657717138653476676b51486e6e69437533797268766a4848484692b06174746573746174696f6e5f6c69737493af4164647265737356616c6964697479ad4b6e6f776e437573746f6d6572b35265736964656e6365436c617373696669657292b464657374696e6174696f6e504d41646472657373b353656e645365727669636550726f766964657292b57570646174654672657175656e6379496e44617973c092a578666f726d9192ab6669656c64735f696e697499a44e616d65a75375726e616d65ac416464726573734c696e6531ac416464726573734c696e6532aa506f7374616c436f6465a443697479a7436f756e747279a5456d61696cab50686f6e654e756d6265729292b472657175697265644174746573746174696f6e739092a578666f726d9192ab6669656c64735f696e697491b25465726d73416e64436f6e646974696f6e7392ae73657276696365456e6444617465c092a9736572766963654964a865786368616e676592bc736572766963654d61726b6574696e675f6465736372697074696f6eb743727970746f63757272656e63792045786368616e676592b6736572766963654d61726b6574696e675f696d616765c40092b5736572766963654d61726b6574696e675f6e616d65a84269747374616d7092b073657276696365504d41646472657373d923326e39684c4c7a68706e3475655248596f4a42746352374a6b6d746356346f6d7a4c4b92b073657276696365537461727444617465aa323031382d30312d3031");
    }

    @Test
    public void testSerialization_Invitation() throws Exception{
    	Invitation a = new Invitation(
    			"http://api.bitstamp.com/teleferic",
                new Address("2nPfgysH5URwM6mcknqwNEgbCi9C36oQsdZ"),
                new Address("2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK"),
                Hex.ToByteArray("657f7b33bcee0048e7310ed203bdf44e83ad4332d10392602dbf6afce83ee8be"),
                1,
                Hex.ToByteArray("29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e"),
                Hex.ToByteArray("7ed4909d67fda33ff6e4a16ebfd73a0cd1974a3825275f87dc18bf09b63f1b3c"),
                Hex.ToByteArray("717a48e52e29a3fa379a953faa6893e32ec5a27b945e605f1085f3232d424c13"));
    	Object s = Serialization.ToStruct(a);
    	
    	byte[] bytes = Serialization.Pack(a);

    	assertEquals(Hex.FromByteArray(bytes), "9892ac626f6f737472617041646472d923326e506667797348355552774d366d636b6e71774e4567624369394333366f5173645a92ac626f6f73747261704e6f6465d921687474703a2f2f6170692e6269747374616d702e636f6d2f74656c65666572696392a9696e766974654b6579c420717a48e52e29a3fa379a953faa6893e32ec5a27b945e605f1085f3232d424c1392ab696e766974654d73674944c4207ed4909d67fda33ff6e4a16ebfd73a0cd1974a3825275f87dc18bf09b63f1b3c92aa696e766974654e616d65c42d29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e92ac6f66666572696e6741646472d923326e39684c4c7a68706e3475655248596f4a42746352374a6b6d746356346f6d7a4c4b92ba73657276696365416e6e6f756e63656d656e744d657373616765c420657f7b33bcee0048e7310ed203bdf44e83ad4332d10392602dbf6afce83ee8be92b1736572766963654f66666572696e67494401");
    }
    
       
}
