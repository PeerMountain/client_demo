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

    @Test
    public void testSerialization_ServiceRegistration_Pack() throws Exception{
    	ServiceRegistration a = new ServiceRegistration(
    	         "exchange",
    	         new Address("2n9hLLzhpn4ueRHYoJBtcR7JkmtcV4omzLK"),
    	         LocalDate.of(2018, 1, 1),
    	         null,
    	         "Bitstamp",
    	         "Cryptocurrency Exchange",
    	         new byte[0], 
    	         new ServiceDocument[] {
    	        		 new ServiceDocument(new XForm(Arrays.asList("IdentityDocument")),
	    	        		 		new ServiceAttestation[] {new ServiceAttestation(new Address("2n6HW4uS6Wqq8e4vgkQHnniCu3yrhvjHHHF"),
	    	                        		 				  Arrays.asList("MRZ", "Fraud", "PEP", "Sanction", "SanctionCountry", "CountryRisk", "BlackList"),
	    	                        		 				  DestinationType.SendServiceProvider,
	    	                        		 				  0)}),
    	        		 new ServiceDocument(new XForm(Arrays.asList("Name", "Surname", "AddressLine1", "AddressLine2", "PostalCode", "City", "Country", "Email", "PhoneNumber")),
	    	        		 		new ServiceAttestation[] {new ServiceAttestation(new Address("2n6HW4uS6Wqq8e4vgkQHnniCu3yrhvjHHHF"),
	    	                        		 				  Arrays.asList("AddressValidity", "KnownCustomer", "ResidenceClassifier"),
	    	                        		 				  DestinationType.SendServiceProvider,
	    	                        		 				  null)}),
    	        		 new ServiceDocument(new XForm(Arrays.asList("TermsAndConditions")),
	    	        		 		new ServiceAttestation[] {new ServiceAttestation(new Address("2n6HW4uS6Wqq8e4vgkQHnniCu3yrhvjHHHF"),
	    	                        		 				  Arrays.asList("MRZ", "Fraud", "PEP", "Sanction", "SanctionCountry", "CountryRisk", "BlackList"),
	    	                        		 				  DestinationType.SendServiceProvider,
	    	                        		 				  0)}),
    	        		 	   new ServiceDocument(new XForm(Arrays.asList("Name", "Surname", "AddressLine1", "AddressLine2", "PostalCode",
 	                                                "City", "Country", "Email", "PhoneNumber")),
    	        		 			  new ServiceAttestation[] {})});
    	Object s = Serialization.ToStruct(a);
    	
    	System.out.println(s);
    	//byte[] bytes = Serialization.Pack(a);
    	/*String serviceId, Address servicePMAddress, LocalDate serviceStartDate, 
		LocalDate serviceEndDate, String serviceMarketing_name, String serviceMarketing_description, 
		byte[] serviceMarketing_image, List<ServiceDocument> documents
		*/
    	//assertEquals(Hex.FromByteArray(bytes), "9692ac626f6f737472617041646472d923326e506667797348355552774d366d636b6e71774e4567624369394333366f5173645a92ac626f6f73747261704e6f6465d921687474703a2f2f6170692e6269747374616d702e636f6d2f74656c65666572696392aa696e766974654e616d65c42d29c88d786ed68ce6fcb62aa63bf9ab61081d72dc7603a3d323a23268ffaa8b66746cf6168fe66480cd433f478e92ac6f66666572696e6741646472d923326e39684c4c7a68706e3475655248596f4a42746352374a6b6d746356346f6d7a4c4b92ba73657276696365416e6e6f756e63656d656e744d657373616765c4200f2e63df2c59f0b4108d4ae187be24718d9bcaa64903f883d38b9a81d1cca66492b1736572766963654f66666572696e67494401");
    }
   
    
    
	public String serviceId;
	public String servicePMAddress;
	public LocalDate serviceStartDate;
	public LocalDate serviceEndDate;
	public String serviceMarketing_name;
	public String serviceMarketing_description;
	public byte[] serviceMarketing_image;
	public List<ServiceDocument> documents;

    
}
