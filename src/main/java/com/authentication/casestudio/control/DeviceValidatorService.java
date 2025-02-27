package com.authentication.casestudio.control;

import org.springframework.stereotype.Service;

@Service
public class DeviceValidatorService {

	public boolean validate(DeviceInfo deviceInfo) {
		return deviceInfo.getDeviceId()!= null && !deviceInfo.getDeviceId().isEmpty();
	}
}
