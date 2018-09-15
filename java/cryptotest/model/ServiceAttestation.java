package cryptotest.model;

import java.util.List;

public class ServiceAttestation {

	public Address aePMAddress;
	public List<String> attestation_list;
	public DestinationType destinationPMAddress;
	public int updateFrequencyInDays;
	
	public ServiceAttestation(Address aePMAddress, List<String> attestation_list, DestinationType destinationPMAddress, int updateFrequencyInDays) {
		this.aePMAddress = aePMAddress;
		this.attestation_list = attestation_list;
		this.destinationPMAddress = destinationPMAddress;
		this.updateFrequencyInDays = updateFrequencyInDays;
	}

}
