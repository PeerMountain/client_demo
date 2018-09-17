package cryptotest.model.messages;

import java.time.LocalDate;
import java.util.Map;

import cryptotest.model.Address;
import cryptotest.model.AssertionMetadata;
import cryptotest.model.MessageBody;

public class Assertion extends MessageBody {
	public Address subjectAddr;
	public LocalDate validUntil;
	public LocalDate retainUntil;
	public byte[] containerKey;
	public Map<String, AssertionMetadata> Meta;
	public Assertion(Address subjectAddr, LocalDate validUntil, LocalDate retainUntil, 
			byte[] containerKey, Map<String, AssertionMetadata> Meta) {
		this.subjectAddr = subjectAddr;
		this.validUntil = validUntil;
		this.retainUntil = retainUntil;
		this.containerKey = containerKey;
		this.Meta = Meta;
	}

}
