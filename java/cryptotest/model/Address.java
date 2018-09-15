package cryptotest.model;

public class Address {
	public String address;
	public Address(String address) {
		this.address = address;
	}
	public Object ToStruct() {
		return address;
	}
}
