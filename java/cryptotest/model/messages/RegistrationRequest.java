package cryptotest.model.messages;

import java.time.LocalDate;
import java.util.List;

import cryptotest.model.ServiceDocument;

public class RegistrationRequest {
	public byte[] inviteMsgID;
	public byte[] keyProof;
	public byte[] inviteName;
	public byte[] publicKey;
	public byte[] publicNickname;

	public RegistrationRequest(byte[] inviteMsgID, byte[] keyProof, byte[] inviteName, 
			byte[] publicKey, byte[] publicNickname) {
		this.inviteMsgID = inviteMsgID;
		this.keyProof = keyProof;
		this.inviteName = inviteName;
		this.publicKey = publicKey;
		this.publicNickname = publicNickname;
	}

}
