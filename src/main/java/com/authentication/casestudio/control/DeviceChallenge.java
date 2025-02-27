package com.authentication.casestudio.control;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class DeviceChallenge {
	private String deviceId;
	private String challenge;
}
