package com.authentication.casestudio.boundary;

import com.authentication.casestudio.SpringConfiguration;
import com.authentication.casestudio.control.AppToken;
import com.authentication.casestudio.control.DataService;
import com.authentication.casestudio.control.DeviceChallenge;
import com.authentication.casestudio.control.DeviceManager;
import com.authentication.casestudio.control.DeviceValidatorService;
import com.authentication.casestudio.control.TokenService;
import com.authentication.casestudio.entities.Device;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@RestController
public class RegistrationController {

	@Autowired
	private DataService dataService;

	@Autowired
	private DeviceManager deviceManager;

	@Autowired
	private TokenService tokenService;

	@PostMapping("registration/init")
	public ResponseEntity<RegisterOptionsResponse> register1Step() {
		DeviceChallenge deviceChallenge = dataService.createDeviceChallenge();
		return ResponseEntity.ok(new RegisterOptionsResponse(deviceChallenge.getDeviceId(), deviceChallenge.getChallenge()));
	}

	@PostMapping("registration/complete")
	public ResponseEntity<String> register2Step(@RequestBody RegistrationRequest registrationRequest)
			throws IOException, InvalidKeySpecException {
		DeviceChallenge deviceChallenge = dataService.getChallengeData(registrationRequest.getDeviceId());
		if (deviceChallenge != null && deviceChallenge.getChallenge().equals(registrationRequest.getChallenge())){
			//validate key
			dataService.getPublicKey(registrationRequest.getBase64PublicKey());
			deviceManager.save(new Device(registrationRequest.getDeviceId(), registrationRequest.getBase64PublicKey(), SpringConfiguration.HASHING, SpringConfiguration.ALGORITHM));
			String newChallenge = dataService.createDeviceChallenge(registrationRequest.getDeviceId()).getChallenge();
			String token = tokenService.encrypt(new AppToken(registrationRequest.getDeviceId(), Instant.now()
					.plus(10, ChronoUnit.MINUTES), newChallenge));
			return ResponseEntity.ok(token);
		}
		return ResponseEntity.badRequest().build();
	}
}
