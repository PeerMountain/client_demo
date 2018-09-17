package cryptotest.model.messages;

import java.time.LocalDate;
import java.util.List;

import cryptotest.model.ServiceDocument;

public class RegistrationRequest {
	public byte[] inviteMsgID;
	public byte[] keyProof;
	public String inviteName;
	public String publicKey;
	public String publicNickname;

	public RegistrationRequest(byte[] inviteMsgID, byte[] keyProof, String inviteName, 
			String publicKey, String publicNickname) {
		this.inviteMsgID = inviteMsgID;
		this.keyProof = keyProof;
		this.inviteName = inviteName;
		this.publicKey = publicKey;
		this.publicNickname = publicNickname;
	}

}
