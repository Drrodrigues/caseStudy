package com.authentication.casestudio.boundary;

import com.authentication.casestudio.control.AppToken;
import com.authentication.casestudio.control.DataService;
import com.authentication.casestudio.control.DeviceChallenge;
import com.authentication.casestudio.control.DeviceInfo;
import com.authentication.casestudio.control.DeviceManager;
import com.authentication.casestudio.control.DeviceValidatorService;
import com.authentication.casestudio.control.TokenService;
import com.authentication.casestudio.entities.Device;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


@RestController
public class AuthenticationController {

	@Autowired
	private DeviceValidatorService deviceValidatorService;

	@Autowired
	private DataService dataService;

	@Autowired
	private DeviceManager deviceManager;

	@Autowired
	private TokenService tokenService;

	@PostMapping("authentication/init")
	public ResponseEntity<AuthenticationOptionsResponse> authentication1Step(@RequestBody DeviceInfo deviceInfo) {
		if (!deviceValidatorService.validate(deviceInfo)){
			return ResponseEntity.badRequest().build();
		}
		DeviceChallenge deviceChallenge = dataService.createDeviceChallenge(deviceInfo.getDeviceId());
		return ResponseEntity.ok(new AuthenticationOptionsResponse(deviceChallenge.getChallenge()));
	}

	@PostMapping("authentication/complete")
	public ResponseEntity<String> authentication2Step(@RequestBody AuthenticationRequest authenticationRequest)
			throws InvalidKeyException, NoSuchAlgorithmException,
			IOException, InvalidKeySpecException, SignatureException {
		DeviceChallenge deviceChallenge = dataService.getChallengeData(authenticationRequest.getDeviceId());
		if (deviceChallenge != null && deviceChallenge.getChallenge().equals(authenticationRequest.getChallenge())){
			Optional<Device> device = deviceManager.findById(authenticationRequest.getDeviceId());
			if (device.isPresent()){
				PublicKey publicKey = dataService.getPublicKey(device.get().getPublicKey());
				Signature signature = Signature.getInstance("SHA256withRSA");
				signature.initVerify(publicKey);
				signature.update(deviceChallenge.getDeviceId().concat(deviceChallenge.getChallenge()).getBytes(StandardCharsets.UTF_8));
				boolean isVerified = signature.verify(Base64.getDecoder().decode(authenticationRequest.getSignature().getBytes(StandardCharsets.UTF_8)));
				System.out.println("Signature Verified: " + isVerified);
				if (isVerified){
					String token = tokenService.encrypt(new AppToken(authenticationRequest.getDeviceId(), Instant.now()
							.plus(10, ChronoUnit.MINUTES), dataService.createDeviceChallenge(authenticationRequest.getDeviceId()).getChallenge()));
				return ResponseEntity.ok(token);
				}
			}
		}
		return ResponseEntity.status(HttpStatusCode.valueOf(403)).build();
	}

}
