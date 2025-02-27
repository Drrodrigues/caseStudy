package com.authentication.casestudio.control;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.PostConstruct;
import lombok.extern.log4j.Log4j2;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.Version;
import org.paseto4j.version4.Paseto;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

@Log4j2
@Service
public class TokenService {

	@Value("${app.token.secret}")
	private String secret;

	@Value("${app.token.footer}")
	private String footer;

	private JsonMapper mapper = new JsonMapper();

	@PostConstruct
	private void init() {
		mapper.registerModule(new JavaTimeModule());
	}

	/**
	 * PASETO Version 4: Prioritizing Cutting-edge Security and Efficiency
	 * Designed For modern systems that demand the forefront of security technology and operational efficiency.
	 *
	 * Encryption (Local Mode): Similar to Version 2, PASETO Version 4 utilizes XChaCha20-Poly1305 for encryption,
	 * ensuring exceptional security and performance levels.
	 * This encryption choice is ideal for systems that prioritize both security and high-speed operation.
	 * **/
	public String encrypt(AppToken token) {
		String payload;
		try {
			payload = mapper.writeValueAsString(token);
			return Paseto.encrypt(key(), payload, footer);
		} catch (PasetoException | JsonProcessingException e) {
			log.error("Failed to encode token: {}", e.getMessage());
			return null;
		}
	}

	public AppToken decrypt(String token) {
		try {
			String payload = Paseto.decrypt(key(), token, footer);
			return mapper.readValue(payload, AppToken.class);
		} catch (PasetoException | JsonProcessingException e) {
			log.error("Failed to decode token: {}", e.getMessage());
			return null;
		}
	}

	private SecretKey key() {
		return new SecretKey(this.secret.getBytes(StandardCharsets.UTF_8), Version.V4);
	}

}
