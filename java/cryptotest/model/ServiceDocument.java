package cryptotest.model;

import java.util.List;

public class ServiceDocument {

	public String xform;
	public List<ServiceAttestation> requiredAttestations;
	
	public ServiceDocument(String xform, List<ServiceAttestation> requiredAttestations) {
		this.xform = xform;
		this.requiredAttestations = requiredAttestations;
	}

}
