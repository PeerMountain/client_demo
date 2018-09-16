package cryptotest.model;

import java.util.List;

public class ServiceDocument {

	public XForm xform;
	public ServiceAttestation[] requiredAttestations;
	
	public ServiceDocument(XForm xform, ServiceAttestation[] requiredAttestations) {
		this.xform = xform;
		this.requiredAttestations = requiredAttestations;
	}

}
