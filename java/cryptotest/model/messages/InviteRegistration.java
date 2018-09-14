package cryptotest.model.messages;

import cryptotest.model.Address;
import cryptotest.model.MessageBody;

public class InviteRegistration extends MessageBody {
	public String boostrapNode;
	public Address boostrapAddr;
	public Address offeringAddr;
	public byte[] serviceAnnouncementMessage;
	public int serviceOfferingID;
	public byte[] inviteName;
	
	public InviteRegistration(String boostrapNode, Address boostrapAddr, Address offeringAddr, byte[] serviceAnnouncementMessage, 
								int serviceOfferingID, byte[] inviteName) 
	{
		this.boostrapNode = boostrapNode;
		this.boostrapAddr = boostrapAddr;
		this.offeringAddr = offeringAddr;
		this.serviceAnnouncementMessage = serviceAnnouncementMessage;
		this.serviceOfferingID = serviceOfferingID;
		this.inviteName = inviteName;		
	}

}
