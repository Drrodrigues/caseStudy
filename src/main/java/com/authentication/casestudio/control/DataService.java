package com.authentication.casestudio.control;

import com.authentication.casestudio.SpringConfiguration;
import com.authentication.casestudio.boundary.AuthenticationOptionsResponse;
import com.authentication.casestudio.boundary.RegisterOptionsResponse;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

@Service
public class DataService {

	private KeyFactory keyFactory = KeyFactory.getInstance(SpringConfiguration.ALGORITHM);

	public DataService() throws NoSuchAlgorithmException {
		Security.addProvider(new BouncyCastleProvider());
	}

	private String createRandomId() {
		return UUID.randomUUID().toString();
	}

	@CachePut(value="challenges", key = "#result.deviceId")
	public DeviceChallenge createDeviceChallenge() {
		String challengeCode = createRandomId();
		String deviceId = createRandomId();
		return new DeviceChallenge(deviceId, challengeCode);
	}


	@Cacheable(value="challenges")
	@CacheEvict(value = "challenges", key = "#deviceId")
	public DeviceChallenge getChallengeData(String deviceId) {
		return null;
	}

	public PublicKey getPublicKey(String base64PublickKey) throws IOException, InvalidKeySpecException {
		PemReader pemReader = new PemReader(new StringReader(new String(Base64.decode(base64PublickKey))));
		PemObject pemObject = pemReader.readPemObject();
		byte[] content = pemObject.getContent();
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
		return keyFactory.generatePublic(pubKeySpec);
	}

	@CachePut(value="challenges", key = "#deviceId")
	public DeviceChallenge createDeviceChallenge(String deviceId) {
		String challengeCode = createRandomId();
		return new DeviceChallenge(deviceId, challengeCode);

	}
}
