package cryptotest.model;

import java.util.List;

public class ServiceAttestation {

	public Address aePMAddress;
	public List<String> attestation_list;
	public DestinationType destinationPMAddress;
	public Integer updateFrequencyInDays;
	
	public ServiceAttestation(Address aePMAddress, List<String> attestation_list, DestinationType destinationPMAddress, Integer updateFrequencyInDays) {
		this.aePMAddress = aePMAddress;
		this.attestation_list = attestation_list;
		this.destinationPMAddress = destinationPMAddress;
		this.updateFrequencyInDays = updateFrequencyInDays;
	}

}
