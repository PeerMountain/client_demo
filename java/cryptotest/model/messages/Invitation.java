package cryptotest.model.messages;

import cryptotest.model.Address;

public class Invitation extends InviteRegistration {
	public byte[] inviteMsgID;
	public byte[] inviteKey;
	public Invitation(String boostrapNode, Address boostrapAddr, Address offeringAddr,
					  byte[] serviceAnnouncementMessage, int serviceOfferingID, byte[] inviteName) {
		super(boostrapNode, boostrapAddr, offeringAddr, serviceAnnouncementMessage, serviceOfferingID, inviteName);
		// TODO Auto-generated constructor stub
	}

}
