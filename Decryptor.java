package winet.kw.tl.security;

/**
 * Created by COMSO on 2018-03-27.
 */

import java.security.Key;

import winet.kw.tl.dto.User;

abstract public class Decryptor {
	
	private Key key = null;

	protected Key getKey() {
		return key;
	}
	protected void setKey(Key key) {
		this.key = key;
	}

    abstract public String decrypt(String encrypted);

    public User decrypt(User user) {
    	User decrypted = new User();
    	
    	decrypted.setEMail(decrypt(user.getEMail()));
    	decrypted.setName(decrypt(user.getName()));
    	decrypted.setPassword(decrypt(user.getPassword()));
    	decrypted.setPNum(decrypt(user.getPNum()));
        System.out.println(decrypted.toString());

        return decrypted;
    }

}
