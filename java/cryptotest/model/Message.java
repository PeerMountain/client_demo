package cryptotest.model;

public class Message {
	public int serviceID;
	public int consumerID;
    public byte[] dossierSalt;
    public BodyType bodyType;
    public MessageBody body;
    
    public Message(int serviceID, int consumerID, byte[] dossierSalt, BodyType bodyType, MessageBody body) {
    	this.serviceID = serviceID;
    	this.consumerID = consumerID;
    	this.dossierSalt = dossierSalt;
    	this.bodyType = bodyType;
    	this.body = body;
    }
}
