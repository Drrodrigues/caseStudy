package com.authentication.casestudio.control;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AppToken {

	private String deviceId;
	private Instant expiry;
	private String challenge;

}
