package cryptotest.model;

import java.util.ArrayList;
import java.util.List;


public class Attachement {
    public byte[] containerHash;
    public byte[] containerSig;
    public byte[] objectContainer;
    public byte[] objectHash;
    public List<byte[]> Metahashes;
    
    public Attachement(byte[] containerHash, byte[] containerSig, byte[] objectContainer, byte[] objectHash, List<byte[]> Metahashes) {
    	this.containerHash = containerHash;
    	this.containerSig = containerSig;
    	this.objectContainer = objectContainer;
    	this.objectHash = objectHash;
    	this.Metahashes = Metahashes;
    }

}
