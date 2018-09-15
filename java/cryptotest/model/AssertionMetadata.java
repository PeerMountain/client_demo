package cryptotest.model;

public class AssertionMetadata {
	public byte[] MetaSalt;
	public String MetaValue;
	
	public AssertionMetadata(byte[] MetaSalt, String MetaValue) 
	{
		this.MetaSalt = MetaSalt;
		this.MetaValue = MetaValue;
	}

}
