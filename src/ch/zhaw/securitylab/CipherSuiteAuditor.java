package ch.zhaw.securitylab;

import java.util.HashMap;
import java.util.Map.Entry;

public class CipherSuiteAuditor {

	private HashMap<String, Integer> cipherKeyMap;

	public CipherSuiteAuditor() {
		initKeyMap();
	}

	private void initKeyMap() {
		// thx to http://stackoverflow.com/questions/12348563/java-cipher-suite
		// for the mapping
		cipherKeyMap = new HashMap<String, Integer>();

		cipherKeyMap.put("_WITH_IDEA_CBC_", 128);
		cipherKeyMap.put("_WITH_RC2_CBC_40_", 40);
		cipherKeyMap.put("_WITH_RC4_40_", 40);
		cipherKeyMap.put("_WITH_RC4_128_", 128);
		cipherKeyMap.put("_WITH_DES40_CBC_", 40);
		cipherKeyMap.put("_WITH_DES_CBC_", 56);
		cipherKeyMap.put("_WITH_3DES_EDE_CBC_", 168);
		cipherKeyMap.put("_WITH_AES_128_CBC_", 128);
		cipherKeyMap.put("_WITH_AES_256_CBC_", 256);
		cipherKeyMap.put("_WITH_AES_128_GCM_", 128);
		cipherKeyMap.put("_WITH_AES_256_GCM_", 256);

	}

	/**
	 * • Length of the symmetric key is at least 128 bits (3DES is OK as well).
	 * • The server must authenticate itself. • RC4 should be considered as an
	 * insecure cipher. • MD5 should be considered as an insecure hash function.
	 * 
	 * @param suite
	 * @return
	 */
	public boolean isSecure(String suite) {
		if (isAnon(suite)) 
			return false;
		if (hasInsecureKeyLength(suite))
			return false;
		if (isRC4(suite))
			return false;
		if (isMd5(suite))
			return false;

		return true;

	}

	private boolean isAnon(String suite) {
		return suite.toLowerCase().contains("anon");
	}

	private boolean hasInsecureKeyLength(String suite) {

		int length = getKeyLength(suite);

		return length < 128;
	}

	private int getKeyLength(String suite) {
		for (Entry<String, Integer> entry : cipherKeyMap.entrySet()) {
			if (suite.toLowerCase().contains(entry.getKey().toLowerCase())) {
				return entry.getValue();
			}
		}
		return 0; // we dont know, so insecure
	}

	private boolean isMd5(String suite) {
		return suite.toLowerCase().contains("md5");
	}

	private boolean isRC4(String suite) {
		return suite.toLowerCase().contains("rc4");
	}

}
