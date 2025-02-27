package com.authentication.casestudio.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.security.PublicKey;

@AllArgsConstructor
@Getter
@Entity
@NoArgsConstructor
public class Device {

	@Id
	private String deviceId;
	@Lob
	private String publicKey;
	private String hashType;
	private String digitalSignatureMethod;

}
