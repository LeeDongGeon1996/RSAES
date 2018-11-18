package winet.kw.tl.security;

import java.security.Key;

import winet.kw.tl.dto.User;

abstract public class Encryptor{

	private Key key = null;

	protected Key getKey() {
		return key;
	}
	protected void setKey(Key key) {
		this.key = key; 
	}

	abstract public String encrypt(String rawValue);
	
    public User encrypt(User rawUser) {
        User encrypted = new User();

        encrypted.setEMail(encrypt(rawUser.getEMail()));
        encrypted.setPassword(encrypt(rawUser.getPassword()));
        encrypted.setPNum(encrypt(rawUser.getPNum()));
        encrypted.setName(encrypt(rawUser.getName()));

        return encrypted;
    }
}