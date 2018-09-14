package cryptotest.model;

import java.util.List;

public class Attachement {
    public byte[]	containerHash;
    public byte[]	containerSig;
    public byte[]	objectContainer;
    public byte[]	objectHash;
    public List<byte[]> Metahashes;
}
