package winet.kw.tl.security;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AES {

	private static final int KEY_SIZE = 256;
	private static final String ENCRYPT_ALGO = "AES";
	private static final String TRANSFORMATION = ENCRYPT_ALGO + "/ECB/PKCS5Padding";
	// private static byte[] secretKey = null;

	private AES() {
		// do nothing.
	}

	public static String generateSecretKey() {

		// 상대방에게 secretKey를 전달해주는 메소드.
		byte[] secretKey = null;

		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(ENCRYPT_ALGO);
			keyGenerator.init(KEY_SIZE);

			secretKey = keyGenerator.generateKey().getEncoded();

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// For Spring Server.
		String SecretKeyStr = Base64.getEncoder().encodeToString(secretKey);
		// For Android.
		// String SecretKeyStr = Base64.encodeToString(aes.secretKey, Base64.NO_WRAP);

		System.out.println();

		return SecretKeyStr;
	}

	private static String getSecretKey() {

		// 상대방에게 secretKey를 받아오는 메소드.
		//어떻게 받아올지 모르겟음...
		//그래서 일단 그냥 인자로 받기..
		return generateSecretKey();
	}

	public static Encryptor getEncryptor(String secretKey) {

		return new AES.AESEncryptor(secretKey);
	}

	public static Decryptor getDecryptor(String secretKey) {
		return new AES.AESDecryptor(secretKey);
	}

	private static class AESEncryptor extends Encryptor {
		
		private AESEncryptor(String secretKeyStr) {
			
			// 전달 받은 string을 공개키로 변환.
			// ***************** For Spring Server. *****************
			SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(secretKeyStr), ENCRYPT_ALGO);
			// ***************** For Android. *****************
			// SecretKeySpec keySpec = new SecretKeySpec(Base64.decode(secretKeyStr,
			// Base64.NO_WRAP), ENCRYPT_ALGO);

			setKey(keySpec);
		}
		
		@Override
		public String encrypt(String rawValue) {
			String encrypted = null;

			try {
				Cipher cipher = Cipher.getInstance(TRANSFORMATION);
				cipher.init(Cipher.ENCRYPT_MODE, (SecretKey) getKey());

				// 인코딩 주의!! - charset설정주의 / base64플래그 중요!
				// ***************** For Spring Server. *****************
				encrypted = Base64.getEncoder()
						.encodeToString(cipher.doFinal(rawValue.getBytes(StandardCharsets.UTF_8)));
				// ***************** For Android. *****************
				// encrypted =
				// Base64.encodeToString(cipher.doFinal(rawValue.getBytes(StandardCharsets.UTF_8)),
				// Base64.NO_WRAP);

			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			}

			return encrypted;
		}
	}

	private static class AESDecryptor extends Decryptor {

		private AESDecryptor(String secretKeyStr) {

			// 전달 받은 string을 공개키로 변환.
			// ***************** For Spring Server. *****************
			SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(secretKeyStr), ENCRYPT_ALGO);
			// ***************** For Android. *****************
			// SecretKeySpec keySpec = new SecretKeySpec(Base64.decode(secretKeyStr,
			// Base64.NO_WRAP), ENCRYPT_ALGO);

			setKey(keySpec);
		}

		@Override
		public String decrypt(String encrypted) {
			String decoded = null;

			try {
				Cipher cipher = Cipher.getInstance(TRANSFORMATION);
				cipher.init(Cipher.DECRYPT_MODE, (SecretKey) getKey());

				// 문자열 생성시 반드시 charset지정 할 것.
				// ***************** For Spring Server. *****************
				decoded = new String(
						cipher.doFinal(Base64.getDecoder().decode(encrypted.getBytes(StandardCharsets.UTF_8))),
						StandardCharsets.UTF_8);
				// ***************** For Android. *****************
				// decoded = new
				// String(cipher.doFinal(Base64.decode(encrypted.getBytes(StandardCharsets.UTF_8),
				// Base64.NO_WRAP)), StandardCharsets.UTF_8);

			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}

			System.out.println(decoded);
			return decoded;
		}

	}

}
