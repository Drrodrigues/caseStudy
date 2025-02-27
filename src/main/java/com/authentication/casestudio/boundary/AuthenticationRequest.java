package com.authentication.casestudio.boundary;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class AuthenticationRequest {

	@NotBlank
	private String deviceId;
	@NotBlank
	private String challenge;
	@NotBlank
	private String signature;

}
