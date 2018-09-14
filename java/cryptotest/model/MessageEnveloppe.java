package cryptotest.model;

import java.util.List;
import java.util.Map;

public class MessageEnveloppe {
	public byte[] messageHash;
	public byte[] dossierHash;
	public Address senderAddr;
	public byte[] messageSig;
	public byte[] message;
	public Map<Address, byte[]> ACL;
	public List<Attachement> attachements;
	public byte[] replacesMsgHash;

}
