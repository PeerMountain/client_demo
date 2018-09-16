package cryptotest.model.messages;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

import cryptotest.model.Address;
import cryptotest.model.DestinationType;
import cryptotest.model.ServiceDocument;

public class ServiceRegistration {
	public String serviceId;
	public Address servicePMAddress;
	public LocalDate serviceStartDate;
	public LocalDate serviceEndDate;
	public String serviceMarketing_name;
	public String serviceMarketing_description;
	public byte[] serviceMarketing_image;
	public List<ServiceDocument> documents;

	public ServiceRegistration(String serviceId, Address servicePMAddress, LocalDate serviceStartDate, 
			LocalDate serviceEndDate, String serviceMarketing_name, String serviceMarketing_description, 
			byte[] serviceMarketing_image, List<ServiceDocument> documents) {
		this.serviceId = serviceId;
		this.servicePMAddress = servicePMAddress;
		this.serviceStartDate = serviceStartDate;
		this.serviceEndDate = serviceEndDate;
		this.serviceMarketing_name = serviceMarketing_name;
		this.serviceMarketing_description = serviceMarketing_description;
		this.serviceMarketing_image = serviceMarketing_image;
		this.documents = documents;
	}
}


