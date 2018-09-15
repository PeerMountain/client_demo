package cryptotest.model;

import java.util.List;

public class AttestationEntry {

	public String attestType;
	public AttestationDetail detail;
	
	public AttestationEntry(String attestType, AttestationDetail detail) {
		this.attestType = attestType;
		this.detail = detail;
	}

}
