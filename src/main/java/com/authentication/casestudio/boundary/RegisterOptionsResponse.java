package com.authentication.casestudio.boundary;

import com.authentication.casestudio.SpringConfiguration;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class RegisterOptionsResponse {

	private String deviceId;
	private String challenge;
	private final String hashType = SpringConfiguration.HASHING;
	private final String digitalSignatureMethod = SpringConfiguration.ALGORITHM;


}
