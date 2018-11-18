package winet.kw.tl.security;

import winet.kw.tl.dto.User;

/*Facade Class*/
public class Crypto {

	public static User decrypt(User user) {

		return AES.getDecryptor(RSA.getDecryptor().decrypt(user.getAccessKey())).decrypt(user);
	}

	public static User encrypt(User user) {
		String key = AES.generateSecretKey();
		
		user = AES.getEncryptor(key).encrypt(user);
		user.setAccessKey(RSA.getEncryptor().encrypt(key));
		
		return user;
	
	}

}
