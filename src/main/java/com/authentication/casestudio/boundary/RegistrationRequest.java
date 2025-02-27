package com.authentication.casestudio.boundary;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class RegistrationRequest {

	private String deviceId;
	private String challenge;
	private String base64PublicKey;
}
