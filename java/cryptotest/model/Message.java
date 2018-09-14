package cryptotest.model;

public class Message {
	public int serviceID;
	public int consumerID;
    public byte[] dossierSalt;
    public BodyType bodyType;
    public MessageBody body;
}
