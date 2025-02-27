package com.authentication.casestudio.boundary;

import com.authentication.casestudio.control.AppToken;
import com.authentication.casestudio.control.DataService;
import com.authentication.casestudio.control.DeviceChallenge;
import com.authentication.casestudio.control.TokenService;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
public class ProtectedResourceController {

	@Autowired
	private TokenService tokenService;

	@Autowired
	private DataService dataService;

	@PostMapping("protected")
	public ResponseEntity<String> protectedOp(@RequestHeader(name = HttpHeaders.AUTHORIZATION) String authHeader, @RequestParam String deviceId) {

		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			return ResponseEntity.badRequest().build();
		}

		final String tokenString = authHeader.substring(7);
		AppToken token = tokenService.decrypt(tokenString);

		if (token != null){
			DeviceChallenge deviceChallenge = dataService.getChallengeData(deviceId);
			if (deviceChallenge!= null && token.getExpiry().isAfter(Instant.now()) && token.getDeviceId().equals(deviceId)
					&& token.getChallenge().equals(deviceChallenge.getChallenge())) {
				return ResponseEntity.ok("Protected access OK");
			}

		}
		return ResponseEntity.status(HttpStatusCode.valueOf(403)).body("Token is invalid");
	}
}
