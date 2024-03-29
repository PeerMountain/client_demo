package tests;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.FileReader;
import java.nio.file.Paths;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.Test;

import cryptotest.Hex;

import org.bouncycastle.openssl.PEMKeyPair;
import java.security.PrivateKey;

public class RSATests {

	static String readFile(String path, Charset encoding) throws IOException 
	{
	  byte[] encoded = Files.readAllBytes(Paths.get(path));
	  return new String(encoded, encoding);
	}

    @Test
    public void test_SignRSA_PKCS1_v1_5() throws Exception {
        // Load file in PKCS1 format (but not PKCS8 which might look similar)
    	File privateKeyFile = new File("./tests/client.pem"); // private key file in PEM format
		PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile));
		Object obj = pemParser.readObject();

        if (!(obj instanceof PEMKeyPair)) {
			throw new Exception("Error in private key file");
		}
        PEMKeyPair pemkeypair = (PEMKeyPair)obj;
        
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        
        KeyPair key = converter.getKeyPair(pemkeypair);

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(key.getPrivate());
        privateSignature.update("hello".getBytes(StandardCharsets.UTF_8));

        byte[] signature = privateSignature.sign();

        String sig = Base64.getEncoder().encodeToString(signature);
        
    	// The we sign using PKCS1 v1.5 which is deterministic so there is no need to mock random
        assertEquals(sig, "oEH+z0bebQLMAtGiRlqdBUD0Q7RriHVM0JDLOMQhQzrs3CJstIzyMDKJlqXIhHkoiUfZEC6cd3fvGmd2heubPkpWtNsZqvc1sMd63Ia238NVzubFelM9BtZpc/aGzH0lQMyaUexum8a4eN3sdNNaltVTFelawgJcnfIeFIMoNEI=");
   	}
	
}
